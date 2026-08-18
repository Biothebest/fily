use std::{io, sync::Arc, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use reqwest::Url;
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{timeout, timeout_at, Instant},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    domain::mail::{AccountId, ConnectedAccount, CredentialId},
    providers::{
        gmail::{GmailOAuthCompletionInput, GmailProvider},
        ProviderError, ProviderResult,
    },
};

const CALLBACK_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const CALLBACK_READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CALLBACK_CONNECTIONS: usize = 16;
const MAX_CALLBACK_REQUEST_BYTES: usize = 16 * 1024;
const MAX_CLIENT_CONFIG_BYTES: u64 = 64 * 1024;
const CALLBACK_PATH_PREFIX: &str = "/oauth/gmail/";
const INSTALLED_APP_CREDENTIAL_ID: &str = "gmail-installed-app-client-v1";

/// Runs Gmail's installed-app authorization flow entirely inside the trusted Rust core.
///
/// The native file chooser, selected path, downloaded client credential, callback authorization
/// code, PKCE verifier, and OAuth tokens never cross this API boundary. Account IDs are generated
/// by the trusted core, and the verified Gmail profile supplies the public account identity.
pub struct GmailOAuthOnboarding {
    provider: Arc<GmailProvider>,
}

impl GmailOAuthOnboarding {
    pub fn new(provider: Arc<GmailProvider>) -> Self {
        Self { provider }
    }

    /// Opens the native client-config picker if the application client has not yet been
    /// configured, launches the system browser, receives Google's loopback callback, and stores
    /// the resulting refresh token in the OS credential vault through `GmailProvider`.
    pub async fn connect(&self) -> ProviderResult<ConnectedAccount> {
        let account_id = AccountId::new(format!("gmail-{}", random_urlsafe(24)))
            .map_err(|_| ProviderError::ProviderFailure)?;
        let credential_id = CredentialId::new(INSTALLED_APP_CREDENTIAL_ID)
            .map_err(|_| ProviderError::ProviderFailure)?;
        if !self.provider.oauth_client_configured(&credential_id)? {
            let client = pick_google_client_config().await?;
            self.provider.store_oauth_client(
                &credential_id,
                &client.client_id,
                client.client_secret.as_deref(),
            )?;
        }

        // Binding before constructing the authorization URL removes the port-selection race.
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|_| ProviderError::Network)?;
        let port = listener
            .local_addr()
            .map_err(|_| ProviderError::Network)?
            .port();
        let callback_path = format!("{CALLBACK_PATH_PREFIX}{}", random_urlsafe(24));
        let redirect_uri = format!("http://127.0.0.1:{port}{callback_path}");

        let start = self
            .provider
            .begin_oauth_for_onboarding(&account_id, &credential_id, redirect_uri.clone())
            .await?;

        if open::that(&start.authorization_url).is_err() {
            self.provider.discard_pending_oauth(&account_id).ok();
            return Err(ProviderError::ProviderFailure);
        }

        let authorization_code = match receive_callback(
            listener,
            &callback_path,
            &start.state,
            CALLBACK_TIMEOUT,
        )
        .await
        {
            Ok(code) => code,
            Err(error) => {
                self.provider.discard_pending_oauth(&account_id).ok();
                return Err(error);
            }
        };

        let result = self
            .provider
            .complete_oauth(GmailOAuthCompletionInput {
                account_id: account_id.clone(),
                credential_id,
                redirect_uri,
                state: start.state,
                authorization_code,
            })
            .await;
        if result.is_err() {
            self.provider.discard_pending_oauth(&account_id).ok();
        }
        result
    }
}

#[derive(Deserialize)]
struct GoogleClientConfigFile {
    installed: GoogleInstalledClient,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct GoogleInstalledClient {
    client_id: String,
    #[serde(default)]
    client_secret: Option<String>,
}

async fn pick_google_client_config() -> ProviderResult<GoogleInstalledClient> {
    let selected = rfd::AsyncFileDialog::new()
        .set_title("Select Google OAuth client configuration")
        .add_filter("Google OAuth client configuration", &["json"])
        .pick_file()
        .await
        .ok_or(ProviderError::NotConfigured)?;

    // The path is used only within the trusted core. Checking metadata on the opened handle and
    // taking one extra byte keeps a changed or special file from causing an unbounded allocation.
    let file = tokio::fs::File::open(selected.path())
        .await
        .map_err(|_| ProviderError::NotConfigured)?;
    let metadata = file
        .metadata()
        .await
        .map_err(|_| ProviderError::NotConfigured)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_CLIENT_CONFIG_BYTES {
        return Err(ProviderError::NotConfigured);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(MAX_CLIENT_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| ProviderError::NotConfigured)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_CLIENT_CONFIG_BYTES {
        return Err(ProviderError::NotConfigured);
    }

    let config: GoogleClientConfigFile =
        serde_json::from_slice(bytes.as_ref()).map_err(|_| ProviderError::NotConfigured)?;
    validate_client_config(&config.installed)?;
    Ok(config.installed)
}

fn validate_client_config(client: &GoogleInstalledClient) -> ProviderResult<()> {
    let valid_client_id = !client.client_id.is_empty()
        && client.client_id.len() <= 4_096
        && client.client_id.is_ascii()
        && client.client_id.ends_with(".apps.googleusercontent.com")
        && !client.client_id.bytes().any(|byte| byte.is_ascii_control());
    let valid_secret = client.client_secret.as_deref().map_or(true, |secret| {
        !secret.is_empty()
            && secret.len() <= 4_096
            && !secret.bytes().any(|byte| byte.is_ascii_control())
    });
    if !valid_client_id || !valid_secret {
        return Err(ProviderError::NotConfigured);
    }
    Ok(())
}

async fn receive_callback(
    listener: TcpListener,
    callback_path: &str,
    expected_state: &str,
    callback_timeout: Duration,
) -> ProviderResult<String> {
    let deadline = Instant::now() + callback_timeout;
    for _ in 0..MAX_CALLBACK_CONNECTIONS {
        let (mut stream, _) = timeout_at(deadline, listener.accept())
            .await
            .map_err(|_| ProviderError::Network)?
            .map_err(|_| ProviderError::Network)?;

        let request = match timeout(CALLBACK_READ_TIMEOUT, read_http_request(&mut stream)).await {
            Ok(Ok(request)) => request,
            _ => {
                write_response(&mut stream, ResponseKind::BadRequest).await;
                continue;
            }
        };
        let callback = match parse_callback(&request, callback_path, expected_state) {
            CallbackParse::Unrelated => {
                write_response(&mut stream, ResponseKind::NotFound).await;
                continue;
            }
            CallbackParse::Rejected => {
                write_response(&mut stream, ResponseKind::Rejected).await;
                return Err(ProviderError::Authentication);
            }
            CallbackParse::Authorized(code) => code,
        };
        write_response(&mut stream, ResponseKind::Authorized).await;
        return Ok(callback);
    }
    Err(ProviderError::Network)
}

async fn read_http_request(stream: &mut TcpStream) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut request = Zeroizing::new(Vec::with_capacity(1_024));
    let mut buffer = Zeroizing::new([0_u8; 1_024]);
    while request.len() < MAX_CALLBACK_REQUEST_BYTES {
        let remaining = MAX_CALLBACK_REQUEST_BYTES - request.len();
        let chunk_len = remaining.min(buffer.len());
        let read = stream.read(&mut buffer[..chunk_len]).await?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(request);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid OAuth callback request",
    ))
}

enum CallbackParse {
    Authorized(String),
    Rejected,
    Unrelated,
}

fn parse_callback(request: &[u8], callback_path: &str, expected_state: &str) -> CallbackParse {
    let request = match std::str::from_utf8(request) {
        Ok(request) => request,
        Err(_) => return CallbackParse::Unrelated,
    };
    let request_line = match request.split("\r\n").next() {
        Some(line) => line,
        None => return CallbackParse::Unrelated,
    };
    let mut parts = request_line.split_ascii_whitespace();
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return CallbackParse::Unrelated;
    };
    if method != "GET" || !matches!(version, "HTTP/1.0" | "HTTP/1.1") || !target.starts_with('/') {
        return CallbackParse::Unrelated;
    }

    let url = match Url::parse(&format!("http://127.0.0.1{target}")) {
        Ok(url) => url,
        Err(_) => return CallbackParse::Unrelated,
    };
    if url.path() != callback_path {
        return CallbackParse::Unrelated;
    }
    if url.fragment().is_some() {
        return CallbackParse::Rejected;
    }

    let mut code = None;
    let mut state = None;
    let mut oauth_error = false;
    for (name, value) in url.query_pairs() {
        match name.as_ref() {
            "code" if code.is_none() => code = Some(value.into_owned()),
            "state" if state.is_none() => state = Some(value.into_owned()),
            "error" => oauth_error = true,
            "code" | "state" => return CallbackParse::Rejected,
            _ => {}
        }
    }
    let Some(state) = state else {
        return CallbackParse::Rejected;
    };
    if oauth_error || !constant_time_eq(state.as_bytes(), expected_state.as_bytes()) {
        return CallbackParse::Rejected;
    }
    match code {
        Some(code) if !code.is_empty() && code.len() <= 4_096 => CallbackParse::Authorized(code),
        _ => CallbackParse::Rejected,
    }
}

enum ResponseKind {
    Authorized,
    Rejected,
    BadRequest,
    NotFound,
}

async fn write_response(stream: &mut TcpStream, kind: ResponseKind) {
    let (status, body) = match kind {
        ResponseKind::Authorized => (
            "200 OK",
            "Authorization complete. You can close this window and return to Fily.",
        ),
        ResponseKind::Rejected => (
            "400 Bad Request",
            "Authorization was not completed. Return to Fily and try again.",
        ),
        ResponseKind::BadRequest => ("400 Bad Request", "Invalid request."),
        ResponseKind::NotFound => ("404 Not Found", "Not found."),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await.ok();
    stream.shutdown().await.ok();
}

fn random_urlsafe(bytes: usize) -> String {
    let mut random = Zeroizing::new(vec![0_u8; bytes]);
    OsRng.fill_bytes(random.as_mut());
    URL_SAFE_NO_PAD.encode(random.as_slice())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}
