use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use rand::{rngs::OsRng, RngCore};
use reqwest::{Method, StatusCode, Url};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    domain::mail::{
        AccountId, Attachment, AttachmentId, ConnectRequest, ConnectedAccount, CredentialId,
        DeleteDraftRequest, DisconnectRequest, DraftId, DraftRequest, DraftResult, EmailAddress,
        Folder, FolderId, FolderRole, ListFoldersRequest, Message, MessageId, MessageSummary,
        MoveRequest, MutationRequest, MutationResult, ProviderKind, RetrieveRequest, SearchRequest,
        SearchResults, SendRequest, SendResult, SyncBatch, SyncChange, SyncRequest, Validate,
        MAX_BODY_BYTES,
    },
    providers::{MailProvider, ProviderError, ProviderResult},
    vault::CredentialVault,
};

const API_ROOT: &str = "https://gmail.googleapis.com/gmail/v1/users/me";
const AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const REVOKE_ENDPOINT: &str = "https://oauth2.googleapis.com/revoke";
const GMAIL_SCOPE: &str = "https://www.googleapis.com/auth/gmail.modify";
const CLIENT_SECRET_KIND: &str = "gmail-oauth-client-v1";
const PENDING_SECRET_KIND: &str = "gmail-oauth-pending-v1";
const TOKEN_SECRET_KIND: &str = "gmail-oauth-token-v1";
const OAUTH_PENDING_LIFETIME_SECS: u64 = 10 * 60;
const ACCESS_TOKEN_SKEW_SECS: u64 = 60;
const MAX_OAUTH_FIELD_BYTES: usize = 4096;

/// Internal PKCE initiation result. The verifier remains in the OS credential vault.
pub(super) struct GmailOAuthStart {
    pub(super) authorization_url: String,
    pub(super) state: String,
}

/// Internal authorization response. It intentionally cannot be serialized into a command DTO.
pub(super) struct GmailOAuthCompletionInput {
    pub(super) account_id: AccountId,
    pub(super) credential_id: CredentialId,
    pub(super) redirect_uri: String,
    pub(super) state: String,
    pub(super) authorization_code: String,
}

impl Drop for GmailOAuthCompletionInput {
    fn drop(&mut self) {
        self.authorization_code.zeroize();
        self.state.zeroize();
    }
}

/// Gmail performs no write unless the trusted caller's authorization gate approves the exact
/// request. Implementations should consume one-use operation authorizations rather than merely
/// checking that their opaque IDs are non-empty.
pub trait GmailAuthorizationGate: Send + Sync {
    fn authorize_draft(&self, _request: &DraftRequest) -> bool {
        false
    }
    fn authorize_delete_draft(&self, _request: &DeleteDraftRequest) -> bool {
        false
    }
    fn authorize_send(&self, _request: &SendRequest) -> bool {
        false
    }
    fn authorize_move(&self, _request: &MoveRequest) -> bool {
        false
    }
    fn authorize_archive(&self, _request: &MutationRequest) -> bool {
        false
    }
    fn authorize_trash(&self, _request: &MutationRequest) -> bool {
        false
    }
    fn authorize_disconnect(&self, _request: &DisconnectRequest) -> bool {
        false
    }
}

#[derive(Debug, Default)]
pub struct DenyAllGmailMutations;
impl GmailAuthorizationGate for DenyAllGmailMutations {}

pub struct GmailProvider {
    http: reqwest::Client,
    vault: Arc<CredentialVault>,
    authorizer: Arc<dyn GmailAuthorizationGate>,
    access_tokens: Mutex<HashMap<String, CachedAccessToken>>,
}

impl GmailProvider {
    pub fn new(
        vault: Arc<CredentialVault>,
        authorizer: Arc<dyn GmailAuthorizationGate>,
    ) -> ProviderResult<Self> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(45))
            .user_agent("Fily-Desktop/0.1")
            .build()
            .map_err(|_| ProviderError::NotConfigured)?;
        Ok(Self {
            http,
            vault,
            authorizer,
            access_tokens: Mutex::new(HashMap::new()),
        })
    }

    /// Installs a Google OAuth client credential directly into the OS vault. This is a trusted-core
    /// bootstrap API: command DTOs and React must never carry `client_secret`.
    pub(super) fn store_oauth_client(
        &self,
        credential_id: &CredentialId,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> ProviderResult<()> {
        credential_id.validate()?;
        validate_oauth_field("clientId", client_id)?;
        if let Some(secret) = client_secret {
            validate_oauth_field("clientSecret", secret)?;
        }
        let stored = OAuthClientCredential {
            client_id: client_id.to_owned(),
            client_secret: client_secret.map(str::to_owned),
        };
        let serialized = Zeroizing::new(
            serde_json::to_vec(&stored).map_err(|_| ProviderError::ProviderFailure)?,
        );
        self.vault
            .set_secret(
                &credential_vault_key(credential_id.as_str()),
                CLIENT_SECRET_KIND,
                serialized.as_ref(),
            )
            .map_err(|_| ProviderError::NotConfigured)
    }
    pub(super) fn oauth_client_configured(
        &self,
        credential_id: &CredentialId,
    ) -> ProviderResult<bool> {
        credential_id.validate()?;
        self.vault
            .get_secret(
                &credential_vault_key(credential_id.as_str()),
                CLIENT_SECRET_KIND,
            )
            .map(|credential| credential.is_some())
            .map_err(|_| ProviderError::NotConfigured)
    }

    /// Begins the installed-app flow without trusting presentation code to supply an identity.
    /// The verified Gmail profile becomes the connected account identity after token exchange.
    pub(super) async fn begin_oauth_for_onboarding(
        &self,
        account_id: &AccountId,
        credential_id: &CredentialId,
        redirect_uri: String,
    ) -> ProviderResult<GmailOAuthStart> {
        account_id.validate()?;
        credential_id.validate()?;
        validate_redirect_uri(&redirect_uri)?;
        let client = self.load_oauth_client(credential_id)?;
        let verifier = random_urlsafe(64);
        let state = random_urlsafe(32);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let pending = PendingOAuth {
            credential_id: credential_id.as_str().to_owned(),
            redirect_uri: redirect_uri.clone(),
            state: state.clone(),
            verifier,
            expires_at: unix_seconds().saturating_add(OAUTH_PENDING_LIFETIME_SECS),
        };
        let serialized = Zeroizing::new(
            serde_json::to_vec(&pending).map_err(|_| ProviderError::ProviderFailure)?,
        );
        self.vault
            .set_secret(
                &account_vault_key(account_id.as_str()),
                PENDING_SECRET_KIND,
                serialized.as_ref(),
            )
            .map_err(|_| ProviderError::NotConfigured)?;

        let mut url = Url::parse(AUTH_ENDPOINT).map_err(|_| ProviderError::NotConfigured)?;
        url.query_pairs_mut()
            .append_pair("client_id", &client.client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", GMAIL_SCOPE)
            .append_pair("access_type", "offline")
            .append_pair("prompt", "consent")
            .append_pair("include_granted_scopes", "true")
            .append_pair("state", &state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(GmailOAuthStart {
            authorization_url: url.to_string(),
            state,
        })
    }

    pub(super) async fn complete_oauth(
        &self,
        input: GmailOAuthCompletionInput,
    ) -> ProviderResult<ConnectedAccount> {
        input.account_id.validate()?;
        input.credential_id.validate()?;
        validate_redirect_uri(&input.redirect_uri)?;
        validate_oauth_field("state", &input.state)?;
        validate_oauth_field("authorizationCode", &input.authorization_code)?;

        let key = account_vault_key(input.account_id.as_str());
        let pending_bytes = self
            .vault
            .get_secret(&key, PENDING_SECRET_KIND)
            .map_err(|_| ProviderError::NotConfigured)?
            .ok_or(ProviderError::Authentication)?;
        let pending: PendingOAuth = serde_json::from_slice(pending_bytes.as_ref())
            .map_err(|_| ProviderError::Authentication)?;
        if pending.expires_at < unix_seconds()
            || !oauth_value_valid(&pending.state)
            || !oauth_value_valid(&pending.verifier)
            || !oauth_value_valid(&pending.redirect_uri)
            || !oauth_value_valid(&pending.credential_id)
            || !constant_time_eq(pending.state.as_bytes(), input.state.as_bytes())
            || pending.redirect_uri != input.redirect_uri
            || pending.credential_id != input.credential_id.as_str()
        {
            return Err(ProviderError::Authentication);
        }
        let client = self.load_oauth_client(&input.credential_id)?;
        let token: OAuthTokenResponse = self
            .http
            .post(TOKEN_ENDPOINT)
            .form(&TokenExchangeForm {
                code: &input.authorization_code,
                client_id: &client.client_id,
                client_secret: client.client_secret.as_deref(),
                redirect_uri: &input.redirect_uri,
                code_verifier: &pending.verifier,
                grant_type: "authorization_code",
            })
            .send()
            .await
            .map_err(|_| ProviderError::Network)
            .and_then(classify_token_response)?
            .json()
            .await
            .map_err(|_| ProviderError::Authentication)?;
        let refresh_token = token
            .refresh_token
            .as_ref()
            .filter(|value| !value.is_empty())
            .cloned()
            .ok_or(ProviderError::Authentication)?;
        if token.access_token.is_empty() {
            return Err(ProviderError::Authentication);
        }
        let session = OAuthSession {
            credential_id: input.credential_id.as_str().to_owned(),
            client_id: client.client_id.clone(),
            client_secret: client.client_secret.clone(),
            refresh_token,
        };
        let profile = match self.profile_with_access_token(&token.access_token).await {
            Ok(profile) => profile,
            Err(error) => {
                self.revoke_token(&session.refresh_token).await.ok();
                self.vault.delete_secret(&key, PENDING_SECRET_KIND).ok();
                return Err(error);
            }
        };
        let serialized = Zeroizing::new(
            serde_json::to_vec(&session).map_err(|_| ProviderError::ProviderFailure)?,
        );
        self.vault
            .set_secret(&key, TOKEN_SECRET_KIND, serialized.as_ref())
            .map_err(|_| ProviderError::NotConfigured)?;
        self.vault
            .delete_secret(&key, PENDING_SECRET_KIND)
            .map_err(|_| ProviderError::NotConfigured)?;
        self.cache_access_token(
            input.account_id.as_str(),
            token.access_token.clone(),
            token.expires_in,
        );
        let normalized_email = normalize_email(&profile.email_address)?;
        Ok(ConnectedAccount {
            account_id: input.account_id.clone(),
            provider: ProviderKind::Gmail,
            identity: EmailAddress {
                address: normalized_email,
                display_name: None,
            },
        })
    }
    /// Removes an incomplete PKCE transaction without touching any connected-account token.
    /// This is restricted to the trusted provider layer for cancellation and timeout cleanup.
    pub(super) fn discard_pending_oauth(&self, account_id: &AccountId) -> ProviderResult<()> {
        account_id.validate()?;
        self.vault
            .delete_secret(&account_vault_key(account_id.as_str()), PENDING_SECRET_KIND)
            .map_err(|_| ProviderError::NotConfigured)
    }

    fn load_oauth_client(
        &self,
        credential_id: &CredentialId,
    ) -> ProviderResult<OAuthClientCredential> {
        let bytes = self
            .vault
            .get_secret(
                &credential_vault_key(credential_id.as_str()),
                CLIENT_SECRET_KIND,
            )
            .map_err(|_| ProviderError::NotConfigured)?
            .ok_or(ProviderError::NotConfigured)?;
        let client: OAuthClientCredential =
            serde_json::from_slice(bytes.as_ref()).map_err(|_| ProviderError::NotConfigured)?;
        if !oauth_value_valid(&client.client_id)
            || client
                .client_secret
                .as_deref()
                .is_some_and(|value| !oauth_value_valid(value))
        {
            return Err(ProviderError::NotConfigured);
        }
        Ok(client)
    }

    fn load_session(&self, account_id: &AccountId) -> ProviderResult<OAuthSession> {
        let bytes = self
            .vault
            .get_secret(&account_vault_key(account_id.as_str()), TOKEN_SECRET_KIND)
            .map_err(|_| ProviderError::NotConfigured)?
            .ok_or(ProviderError::Authentication)?;
        let session: OAuthSession =
            serde_json::from_slice(bytes.as_ref()).map_err(|_| ProviderError::Authentication)?;
        if !oauth_value_valid(&session.credential_id)
            || !oauth_value_valid(&session.client_id)
            || !oauth_value_valid(&session.refresh_token)
            || session
                .client_secret
                .as_deref()
                .is_some_and(|value| !oauth_value_valid(value))
        {
            return Err(ProviderError::Authentication);
        }
        Ok(session)
    }

    async fn access_token(&self, account_id: &AccountId) -> ProviderResult<Zeroizing<String>> {
        let now = unix_seconds();
        if let Some(token) = self
            .access_tokens
            .lock()
            .map_err(|_| ProviderError::ProviderFailure)?
            .get(account_id.as_str())
            .filter(|token| token.expires_at > now.saturating_add(ACCESS_TOKEN_SKEW_SECS))
        {
            return Ok(Zeroizing::new(token.value.clone()));
        }
        let session = self.load_session(account_id)?;
        let response = self
            .http
            .post(TOKEN_ENDPOINT)
            .form(&RefreshTokenForm {
                refresh_token: &session.refresh_token,
                client_id: &session.client_id,
                client_secret: session.client_secret.as_deref(),
                grant_type: "refresh_token",
            })
            .send()
            .await
            .map_err(|_| ProviderError::Network)?;
        let response = classify_token_response(response)?;
        let refreshed: OAuthTokenResponse = response
            .json()
            .await
            .map_err(|_| ProviderError::Authentication)?;
        if refreshed.access_token.is_empty() {
            return Err(ProviderError::Authentication);
        }
        self.cache_access_token(
            account_id.as_str(),
            refreshed.access_token.clone(),
            refreshed.expires_in,
        );
        Ok(Zeroizing::new(refreshed.access_token.clone()))
    }

    fn cache_access_token(&self, account_id: &str, token: String, expires_in: Option<u64>) {
        if let Ok(mut cache) = self.access_tokens.lock() {
            cache.insert(
                account_id.to_owned(),
                CachedAccessToken {
                    value: token,
                    expires_at: unix_seconds()
                        .saturating_add(expires_in.unwrap_or(3600).min(24 * 3600)),
                },
            );
        }
    }

    fn clear_access_token(&self, account_id: &str) {
        if let Ok(mut cache) = self.access_tokens.lock() {
            cache.remove(account_id);
        }
    }

    async fn profile_with_access_token(&self, access_token: &str) -> ProviderResult<GmailProfile> {
        let url =
            Url::parse(&format!("{API_ROOT}/profile")).map_err(|_| ProviderError::NotConfigured)?;
        let response = self
            .http
            .get(url)
            .bearer_auth(access_token)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| ProviderError::Network)?;
        if !response.status().is_success() {
            return Err(classify_gmail_response(response).await);
        }
        response
            .json()
            .await
            .map_err(|_| ProviderError::ProviderFailure)
    }

    async fn revoke_token(&self, refresh_token: &str) -> ProviderResult<()> {
        let response = self
            .http
            .post(REVOKE_ENDPOINT)
            .form(&RevokeTokenForm {
                token: refresh_token,
            })
            .send()
            .await
            .map_err(|_| ProviderError::Network)?;
        if response.status().is_success() || response.status() == StatusCode::BAD_REQUEST {
            Ok(())
        } else {
            Err(classify_gmail_status(response.status()))
        }
    }

    async fn api_response(
        &self,
        account_id: &AccountId,
        method: Method,
        path: &[&str],
        query: &[(String, String)],
        body: Option<Value>,
    ) -> ProviderResult<reqwest::Response> {
        let mut url = Url::parse(API_ROOT).map_err(|_| ProviderError::NotConfigured)?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| ProviderError::NotConfigured)?;
            for segment in path {
                segments.push(segment);
            }
        }
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                pairs.append_pair(key, value);
            }
        }
        for attempt in 0..2 {
            let token = self.access_token(account_id).await?;
            let mut request = self
                .http
                .request(method.clone(), url.clone())
                .bearer_auth(token.as_str())
                .header(reqwest::header::ACCEPT, "application/json");
            if let Some(body) = &body {
                request = request.json(body);
            }
            let response = request.send().await.map_err(|_| ProviderError::Network)?;
            if response.status() == StatusCode::UNAUTHORIZED && attempt == 0 {
                self.clear_access_token(account_id.as_str());
                continue;
            }
            if !response.status().is_success() {
                return Err(classify_gmail_response(response).await);
            }
            return Ok(response);
        }
        Err(ProviderError::Authentication)
    }

    async fn api_json<T: DeserializeOwned>(
        &self,
        account_id: &AccountId,
        method: Method,
        path: &[&str],
        query: &[(String, String)],
        body: Option<Value>,
    ) -> ProviderResult<T> {
        self.api_response(account_id, method, path, query, body)
            .await?
            .json()
            .await
            .map_err(|_| ProviderError::ProviderFailure)
    }

    async fn get_gmail_message(
        &self,
        account_id: &AccountId,
        id: &str,
        full: bool,
    ) -> ProviderResult<GmailMessage> {
        self.api_json(
            account_id,
            Method::GET,
            &["messages", id],
            &[(
                "format".into(),
                if full { "full" } else { "metadata" }.into(),
            )],
            None,
        )
        .await
    }

    async fn list_message_page(
        &self,
        account_id: &AccountId,
        label_ids: &[FolderId],
        query: Option<&str>,
        page_token: Option<&str>,
        limit: u16,
    ) -> ProviderResult<GmailMessageList> {
        let mut params = vec![
            ("maxResults".into(), limit.min(500).to_string()),
            ("includeSpamTrash".into(), "true".into()),
        ];
        if let Some(query) = query {
            params.push(("q".into(), query.to_owned()));
        }
        if let Some(token) = page_token {
            params.push(("pageToken".into(), token.to_owned()));
        }
        for label in label_ids {
            params.push(("labelIds".into(), label.as_str().to_owned()));
        }
        self.api_json(account_id, Method::GET, &["messages"], &params, None)
            .await
    }

    async fn initial_sync(
        &self,
        request: SyncRequest,
        cursor: Option<InitialCursor>,
    ) -> ProviderResult<SyncBatch> {
        let (history_id, page_token) = match cursor {
            Some(cursor) => (cursor.history_id, cursor.page_token),
            None => {
                let profile: GmailProfile = self
                    .api_json(&request.account_id, Method::GET, &["profile"], &[], None)
                    .await?;
                (profile.history_id, None)
            }
        };
        let page = self
            .list_message_page(
                &request.account_id,
                &request.folder_ids,
                None,
                page_token.as_deref(),
                request.limit,
            )
            .await?;
        let mut changes = Vec::with_capacity(page.messages.len());
        for message_ref in page.messages.into_iter().take(request.limit as usize) {
            let message = self
                .get_gmail_message(&request.account_id, &message_ref.id, false)
                .await?;
            changes.push(SyncChange::Upsert(summarize(&message)?));
        }
        let has_more = page.next_page_token.is_some();
        let next_cursor = if let Some(page_token) = page.next_page_token {
            Some(encode_cursor(&GmailCursor::Initial(InitialCursor {
                history_id,
                page_token: Some(page_token),
            }))?)
        } else {
            Some(encode_cursor(&GmailCursor::History(HistoryCursor {
                start_history_id: history_id,
                page_token: None,
                offset: 0,
            }))?)
        };
        Ok(SyncBatch {
            changes,
            next_cursor,
            has_more,
        })
    }

    async fn history_sync(
        &self,
        request: SyncRequest,
        cursor: HistoryCursor,
    ) -> ProviderResult<SyncBatch> {
        let mut params = vec![
            ("startHistoryId".into(), cursor.start_history_id.clone()),
            ("maxResults".into(), request.limit.min(500).to_string()),
        ];
        if let Some(token) = &cursor.page_token {
            params.push(("pageToken".into(), token.clone()));
        }
        let page: GmailHistoryList = match self
            .api_json(
                &request.account_id,
                Method::GET,
                &["history"],
                &params,
                None,
            )
            .await
        {
            Err(ProviderError::NotFound) => return Err(ProviderError::Conflict),
            result => result?,
        };
        let mut affected = ordered_history_changes(&page.history);
        if !request.folder_ids.is_empty() {
            let allowed: BTreeSet<&str> = request.folder_ids.iter().map(|id| id.as_str()).collect();
            affected.retain(|(_, change)| {
                change.deleted
                    || change
                        .labels
                        .iter()
                        .any(|label| allowed.contains(label.as_str()))
            });
        }
        let entries = affected;
        let start = cursor.offset.min(entries.len());
        let end = (start + request.limit as usize).min(entries.len());
        let mut changes = Vec::with_capacity(end.saturating_sub(start));
        for (id, change) in &entries[start..end] {
            changes.push(if change.deleted {
                SyncChange::Delete(MessageId::new(id.clone())?)
            } else {
                SyncChange::Upsert(summarize(
                    &self
                        .get_gmail_message(&request.account_id, id, false)
                        .await?,
                )?)
            });
        }
        let more_in_page = end < entries.len();
        let has_more = more_in_page || page.next_page_token.is_some();
        let next_cursor = if more_in_page {
            Some(encode_cursor(&GmailCursor::History(HistoryCursor {
                start_history_id: cursor.start_history_id,
                page_token: cursor.page_token,
                offset: end,
            }))?)
        } else if let Some(page_token) = page.next_page_token {
            Some(encode_cursor(&GmailCursor::History(HistoryCursor {
                start_history_id: cursor.start_history_id,
                page_token: Some(page_token),
                offset: 0,
            }))?)
        } else {
            Some(encode_cursor(&GmailCursor::History(HistoryCursor {
                start_history_id: page.history_id.unwrap_or(cursor.start_history_id),
                page_token: None,
                offset: 0,
            }))?)
        };
        Ok(SyncBatch {
            changes,
            next_cursor,
            has_more,
        })
    }

    async fn batch_modify(
        &self,
        account_id: &AccountId,
        ids: &[MessageId],
        add: Vec<String>,
        remove: Vec<String>,
    ) -> ProviderResult<()> {
        self.api_response(
            account_id,
            Method::POST,
            &["messages", "batchModify"],
            &[],
            Some(json!({
                "ids": ids.iter().map(MessageId::as_str).collect::<Vec<_>>(),
                "addLabelIds": add,
                "removeLabelIds": remove,
            })),
        )
        .await?;
        Ok(())
    }
}

#[async_trait]
impl MailProvider for GmailProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Gmail
    }

    async fn connect(&self, request: ConnectRequest) -> ProviderResult<ConnectedAccount> {
        request.validate()?;
        if request.provider != ProviderKind::Gmail {
            return Err(ProviderError::NotConfigured);
        }
        let session = self.load_session(&request.account_id)?;
        if session.credential_id != request.credential_id.as_str() {
            return Err(ProviderError::Authentication);
        }
        let profile: GmailProfile = self
            .api_json(&request.account_id, Method::GET, &["profile"], &[], None)
            .await?;
        if !profile
            .email_address
            .eq_ignore_ascii_case(&request.identity.address)
        {
            return Err(ProviderError::Authentication);
        }
        let normalized_email = normalize_email(&profile.email_address)?;
        Ok(ConnectedAccount {
            account_id: request.account_id,
            provider: ProviderKind::Gmail,
            identity: EmailAddress {
                address: normalized_email,
                display_name: request.identity.display_name,
            },
        })
    }

    async fn list_folders(&self, request: ListFoldersRequest) -> ProviderResult<Vec<Folder>> {
        request.validate()?;
        let response: GmailLabelList = self
            .api_json(&request.account_id, Method::GET, &["labels"], &[], None)
            .await?;
        let mut folders = Vec::with_capacity(response.labels.len());
        for label in response.labels {
            let detail: GmailLabel = self
                .api_json(
                    &request.account_id,
                    Method::GET,
                    &["labels", &label.id],
                    &[],
                    None,
                )
                .await?;
            let role = label_role(&detail.id);
            folders.push(Folder {
                id: FolderId::new(detail.id)?,
                name: detail.name,
                role,
                unread_count: detail.messages_unread,
                total_count: detail.messages_total,
            });
        }
        Ok(folders)
    }

    async fn incremental_sync(&self, request: SyncRequest) -> ProviderResult<SyncBatch> {
        request.validate()?;
        let cursor = request.cursor.as_deref().map(decode_cursor).transpose()?;
        match cursor {
            None => self.initial_sync(request, None).await,
            Some(GmailCursor::Initial(cursor)) => self.initial_sync(request, Some(cursor)).await,
            Some(GmailCursor::History(cursor)) => self.history_sync(request, cursor).await,
        }
    }

    async fn retrieve(&self, request: RetrieveRequest) -> ProviderResult<Message> {
        request.validate()?;
        let gmail = self
            .get_gmail_message(&request.account_id, request.message_id.as_str(), true)
            .await?;
        normalize_message(&gmail, request.include_body, request.max_attachment_bytes)
    }

    async fn search(&self, request: SearchRequest) -> ProviderResult<SearchResults> {
        request.validate()?;
        let page = self
            .list_message_page(
                &request.account_id,
                &request.folder_ids,
                Some(&request.query),
                request.cursor.as_deref(),
                request.limit,
            )
            .await?;
        let mut messages = Vec::with_capacity(page.messages.len());
        for reference in page.messages.into_iter().take(request.limit as usize) {
            messages.push(summarize(
                &self
                    .get_gmail_message(&request.account_id, &reference.id, false)
                    .await?,
            )?);
        }
        Ok(SearchResults {
            messages,
            next_cursor: page.next_page_token,
        })
    }

    async fn draft(&self, request: DraftRequest) -> ProviderResult<DraftResult> {
        request.validate()?;
        if !self.authorizer.authorize_draft(&request) {
            return Err(ProviderError::Unauthorized);
        }
        if !request.attachment_ids.is_empty() {
            return Err(ProviderError::Unsupported);
        }
        let reply = if let Some(message_id) = &request.in_reply_to {
            let message = self
                .get_gmail_message(&request.account_id, message_id.as_str(), false)
                .await?;
            let headers = header_map(message.payload.as_ref());
            let rfc_message_id = header(&headers, "message-id").and_then(safe_rfc_message_id);
            Some((message.thread_id, rfc_message_id))
        } else {
            None
        };
        let raw = build_mime(
            &request,
            reply
                .as_ref()
                .and_then(|(_, message_id)| message_id.as_deref()),
        )?;
        let mut message_body = json!({ "raw": URL_SAFE_NO_PAD.encode(raw.as_bytes()) });
        if let Some(thread_id) = reply
            .as_ref()
            .and_then(|(thread_id, _)| thread_id.as_deref())
        {
            message_body["threadId"] = Value::String(thread_id.to_owned());
        }
        let body = Some(json!({ "message": message_body }));
        let response: GmailDraft = if let Some(draft_id) = &request.draft_id {
            self.api_json(
                &request.account_id,
                Method::PUT,
                &["drafts", draft_id.as_str()],
                &[],
                body,
            )
            .await?
        } else {
            self.api_json(&request.account_id, Method::POST, &["drafts"], &[], body)
                .await?
        };
        Ok(DraftResult {
            draft_id: DraftId::new(response.id)?,
            updated_at_ms: unix_millis(),
        })
    }

    async fn delete_draft(&self, request: DeleteDraftRequest) -> ProviderResult<()> {
        request.validate()?;
        if !self.authorizer.authorize_delete_draft(&request) {
            return Err(ProviderError::Unauthorized);
        }
        self.api_response(
            &request.account_id,
            Method::DELETE,
            &["drafts", request.draft_id.as_str()],
            &[],
            None,
        )
        .await?;
        Ok(())
    }

    async fn send(&self, request: SendRequest) -> ProviderResult<SendResult> {
        request.validate()?;
        if !self.authorizer.authorize_send(&request) {
            return Err(ProviderError::Unauthorized);
        }
        let response: GmailMessage = self
            .api_json(
                &request.account_id,
                Method::POST,
                &["drafts", "send"],
                &[],
                Some(json!({ "id": request.draft_id.as_str() })),
            )
            .await?;
        Ok(SendResult {
            message_id: MessageId::new(response.id)?,
            sent_at_ms: parse_internal_date(response.internal_date.as_deref())
                .unwrap_or_else(unix_millis),
        })
    }

    async fn move_messages(&self, request: MoveRequest) -> ProviderResult<MutationResult> {
        request.validate()?;
        if !self.authorizer.authorize_move(&request) {
            return Err(ProviderError::Unauthorized);
        }
        let labels: GmailLabelList = self
            .api_json(&request.account_id, Method::GET, &["labels"], &[], None)
            .await?;
        let destination = request.destination_folder_id.as_str();
        let destination_is_user = labels
            .labels
            .iter()
            .find(|label| label.id == destination)
            .ok_or(ProviderError::NotFound)?
            .kind
            .as_deref()
            == Some("user");
        if destination == "TRASH" {
            return Err(ProviderError::Unauthorized);
        }
        if !destination_is_user && destination != "INBOX" {
            return Err(ProviderError::Unsupported);
        }
        let remove = labels
            .labels
            .into_iter()
            .filter(|label| {
                label.id != destination
                    && (label.kind.as_deref() == Some("user")
                        || matches!(label.id.as_str(), "INBOX" | "SPAM" | "TRASH"))
            })
            .map(|label| label.id)
            .collect();
        self.batch_modify(
            &request.account_id,
            &request.message_ids,
            vec![destination.to_owned()],
            remove,
        )
        .await?;
        Ok(MutationResult {
            operation_id: request.authorization_id,
            affected: request.message_ids.len() as u16,
        })
    }

    async fn archive(&self, request: MutationRequest) -> ProviderResult<MutationResult> {
        request.validate()?;
        if !self.authorizer.authorize_archive(&request) {
            return Err(ProviderError::Unauthorized);
        }
        self.batch_modify(
            &request.account_id,
            &request.message_ids,
            vec![],
            vec!["INBOX".into()],
        )
        .await?;
        Ok(MutationResult {
            operation_id: request.authorization_id,
            affected: request.message_ids.len() as u16,
        })
    }

    async fn trash(&self, request: MutationRequest) -> ProviderResult<MutationResult> {
        request.validate()?;
        if !self.authorizer.authorize_trash(&request) {
            return Err(ProviderError::Unauthorized);
        }
        for id in &request.message_ids {
            let _: GmailMessage = self
                .api_json(
                    &request.account_id,
                    Method::POST,
                    &["messages", id.as_str(), "trash"],
                    &[],
                    Some(json!({})),
                )
                .await?;
        }
        Ok(MutationResult {
            operation_id: request.authorization_id,
            affected: request.message_ids.len() as u16,
        })
    }

    async fn disconnect(&self, request: DisconnectRequest) -> ProviderResult<()> {
        request.validate()?;
        if !self.authorizer.authorize_disconnect(&request) {
            return Err(ProviderError::Unauthorized);
        }
        let key = account_vault_key(request.account_id.as_str());
        let session = self.load_session(&request.account_id)?;
        self.revoke_token(&session.refresh_token).await?;
        self.vault
            .delete_secret(&key, TOKEN_SECRET_KIND)
            .map_err(|_| ProviderError::NotConfigured)?;
        self.vault
            .delete_secret(&key, PENDING_SECRET_KIND)
            .map_err(|_| ProviderError::NotConfigured)?;
        self.clear_access_token(request.account_id.as_str());
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct OAuthClientCredential {
    client_id: String,
    client_secret: Option<String>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct PendingOAuth {
    credential_id: String,
    redirect_uri: String,
    state: String,
    verifier: String,
    expires_at: u64,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct OAuthSession {
    credential_id: String,
    client_id: String,
    client_secret: Option<String>,
    refresh_token: String,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct CachedAccessToken {
    value: String,
    expires_at: u64,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
struct OAuthTokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
}

#[derive(Serialize)]
struct TokenExchangeForm<'a> {
    code: &'a str,
    client_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<&'a str>,
    redirect_uri: &'a str,
    code_verifier: &'a str,
    grant_type: &'static str,
}

#[derive(Serialize)]
struct RefreshTokenForm<'a> {
    refresh_token: &'a str,
    client_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<&'a str>,
    grant_type: &'static str,
}

#[derive(Serialize)]
struct RevokeTokenForm<'a> {
    token: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailProfile {
    email_address: String,
    history_id: String,
}

#[derive(Debug, Deserialize)]
struct GmailLabelList {
    #[serde(default)]
    labels: Vec<GmailLabel>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailLabel {
    id: String,
    name: String,
    #[serde(rename = "type")]
    kind: Option<String>,
    messages_total: Option<u64>,
    messages_unread: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailMessageList {
    #[serde(default)]
    messages: Vec<GmailMessageRef>,
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GmailMessageRef {
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailMessage {
    id: String,
    thread_id: Option<String>,
    #[serde(default)]
    label_ids: Vec<String>,
    #[serde(default)]
    snippet: String,
    internal_date: Option<String>,
    payload: Option<GmailPart>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailPart {
    #[serde(default)]
    part_id: String,
    #[serde(default)]
    mime_type: String,
    #[serde(default)]
    filename: String,
    #[serde(default)]
    headers: Vec<GmailHeader>,
    #[serde(default)]
    body: GmailBody,
    #[serde(default)]
    parts: Vec<GmailPart>,
}

#[derive(Debug, Deserialize)]
struct GmailHeader {
    name: String,
    value: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailBody {
    attachment_id: Option<String>,
    size: Option<u64>,
    data: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailHistoryList {
    #[serde(default)]
    history: Vec<GmailHistory>,
    next_page_token: Option<String>,
    history_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailHistory {
    #[serde(default)]
    messages_added: Vec<GmailHistoryMessage>,
    #[serde(default)]
    messages_deleted: Vec<GmailHistoryMessage>,
    #[serde(default)]
    labels_added: Vec<GmailHistoryLabels>,
    #[serde(default)]
    labels_removed: Vec<GmailHistoryLabels>,
}

#[derive(Debug, Deserialize)]
struct GmailHistoryMessage {
    message: GmailHistoryMessageValue,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailHistoryLabels {
    message: GmailHistoryMessageValue,
    #[serde(default)]
    label_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailHistoryMessageValue {
    id: String,
    #[serde(default)]
    label_ids: Vec<String>,
}

#[derive(Debug, Default)]
struct HistoryChange {
    deleted: bool,
    labels: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "mode", rename_all = "snake_case")]
enum GmailCursor {
    Initial(InitialCursor),
    History(HistoryCursor),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialCursor {
    history_id: String,
    page_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryCursor {
    start_history_id: String,
    page_token: Option<String>,
    offset: usize,
}

#[derive(Debug, Deserialize)]
struct GmailDraft {
    id: String,
}

fn classify_token_response(response: reqwest::Response) -> ProviderResult<reqwest::Response> {
    match response.status() {
        status if status.is_success() => Ok(response),
        StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            Err(ProviderError::Authentication)
        }
        StatusCode::TOO_MANY_REQUESTS => Err(ProviderError::RateLimited),
        status if status.is_server_error() => Err(ProviderError::Network),
        _ => Err(ProviderError::ProviderFailure),
    }
}

fn classify_gmail_status(status: StatusCode) -> ProviderError {
    match status {
        StatusCode::UNAUTHORIZED => ProviderError::Authentication,
        StatusCode::FORBIDDEN => ProviderError::Unauthorized,
        StatusCode::NOT_FOUND => ProviderError::NotFound,
        StatusCode::CONFLICT | StatusCode::PRECONDITION_FAILED => ProviderError::Conflict,
        StatusCode::TOO_MANY_REQUESTS => ProviderError::RateLimited,
        status if status.is_server_error() => ProviderError::Network,
        _ => ProviderError::ProviderFailure,
    }
}

async fn classify_gmail_response(response: reqwest::Response) -> ProviderError {
    let status = response.status();
    if status == StatusCode::FORBIDDEN && response.content_length().unwrap_or(u64::MAX) <= 64 * 1024
    {
        if let Ok(body) = response.bytes().await {
            if let Ok(payload) = serde_json::from_slice::<Value>(&body) {
                let reasons = payload.pointer("/error/errors").and_then(Value::as_array);
                let rate_limited = reasons.into_iter().flatten().any(|detail| {
                    matches!(
                        detail.get("reason").and_then(Value::as_str),
                        Some("rateLimitExceeded" | "userRateLimitExceeded" | "quotaExceeded")
                    )
                });
                if rate_limited {
                    return ProviderError::RateLimited;
                }
            }
        }
    }
    classify_gmail_status(status)
}

fn oauth_value_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_OAUTH_FIELD_BYTES
        && !value.chars().any(char::is_control)
}

fn validate_oauth_field(_field: &str, value: &str) -> ProviderResult<()> {
    if !oauth_value_valid(value) {
        return Err(ProviderError::InvalidInput);
    }
    Ok(())
}

fn validate_redirect_uri(value: &str) -> ProviderResult<()> {
    validate_oauth_field("redirectUri", value)?;
    let url = Url::parse(value).map_err(|_| ProviderError::InvalidInput)?;
    let local_http =
        url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if url.fragment().is_some() || (!local_http && url.scheme() != "https") {
        return Err(ProviderError::InvalidInput);
    }
    Ok(())
}

fn credential_vault_key(id: &str) -> String {
    format!("gmail-credential-{:x}", Sha256::digest(id.as_bytes()))
}
fn account_vault_key(id: &str) -> String {
    format!("gmail-account-{:x}", Sha256::digest(id.as_bytes()))
}

fn random_urlsafe(bytes: usize) -> String {
    let mut random = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut random);
    URL_SAFE_NO_PAD.encode(random)
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

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn encode_cursor(cursor: &GmailCursor) -> ProviderResult<String> {
    let bytes = serde_json::to_vec(cursor).map_err(|_| ProviderError::ProviderFailure)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_cursor(encoded: &str) -> ProviderResult<GmailCursor> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ProviderError::InvalidInput)?;
    serde_json::from_slice(&bytes).map_err(|_| ProviderError::InvalidInput)
}

fn ordered_history_changes(history: &[GmailHistory]) -> Vec<(String, HistoryChange)> {
    let mut positions = HashMap::<String, usize>::new();
    let mut changes = Vec::new();
    for record in history {
        for added in &record.messages_added {
            record_history_change(
                &mut changes,
                &mut positions,
                added.message.id.clone(),
                HistoryChange {
                    deleted: false,
                    labels: added.message.label_ids.clone(),
                },
            );
        }
        for labeled in record.labels_added.iter().chain(&record.labels_removed) {
            record_history_change(
                &mut changes,
                &mut positions,
                labeled.message.id.clone(),
                HistoryChange {
                    deleted: false,
                    labels: if labeled.message.label_ids.is_empty() {
                        labeled.label_ids.clone()
                    } else {
                        labeled.message.label_ids.clone()
                    },
                },
            );
        }
        for deleted in &record.messages_deleted {
            record_history_change(
                &mut changes,
                &mut positions,
                deleted.message.id.clone(),
                HistoryChange {
                    deleted: true,
                    labels: deleted.message.label_ids.clone(),
                },
            );
        }
    }
    changes
}

fn record_history_change(
    changes: &mut Vec<(String, HistoryChange)>,
    positions: &mut HashMap<String, usize>,
    id: String,
    change: HistoryChange,
) {
    if let Some(index) = positions.get(&id).copied() {
        changes[index].1 = change;
    } else {
        positions.insert(id.clone(), changes.len());
        changes.push((id, change));
    }
}

fn label_role(id: &str) -> FolderRole {
    match id {
        "INBOX" => FolderRole::Inbox,
        "SENT" => FolderRole::Sent,
        "DRAFT" => FolderRole::Drafts,
        "TRASH" => FolderRole::Trash,
        "SPAM" => FolderRole::Spam,
        "ALL" | "ALL_MAIL" => FolderRole::Archive,
        _ => FolderRole::Other,
    }
}

fn summarize(message: &GmailMessage) -> ProviderResult<MessageSummary> {
    let headers = header_map(message.payload.as_ref());
    Ok(MessageSummary {
        id: MessageId::new(message.id.clone())?,
        folder_ids: message
            .label_ids
            .iter()
            .map(|id| FolderId::new(id.clone()))
            .collect::<Result<_, _>>()?,
        thread_id: message.thread_id.clone(),
        subject: header(&headers, "subject").unwrap_or_default().to_owned(),
        from: header(&headers, "from").and_then(parse_one_address),
        to: header(&headers, "to")
            .map(parse_addresses)
            .unwrap_or_default(),
        received_at_ms: parse_internal_date(message.internal_date.as_deref()).unwrap_or(0),
        unread: message.label_ids.iter().any(|label| label == "UNREAD"),
        has_attachments: message
            .payload
            .as_ref()
            .map(part_has_attachment)
            .unwrap_or(false),
        preview: message.snippet.clone(),
    })
}

fn normalize_message(
    message: &GmailMessage,
    include_body: bool,
    max_attachment_bytes: u64,
) -> ProviderResult<Message> {
    let headers = header_map(message.payload.as_ref());
    let mut text = None;
    let mut html = None;
    let mut attachments = Vec::new();
    if let Some(payload) = &message.payload {
        collect_parts(
            payload,
            &message.id,
            include_body,
            max_attachment_bytes,
            &mut text,
            &mut html,
            &mut attachments,
        )?;
    }
    Ok(Message {
        summary: summarize(message)?,
        cc: header(&headers, "cc")
            .map(parse_addresses)
            .unwrap_or_default(),
        bcc: header(&headers, "bcc")
            .map(parse_addresses)
            .unwrap_or_default(),
        reply_to: header(&headers, "reply-to").and_then(parse_one_address),
        text_body: text,
        html_body: html.map(|body| sanitize_html(&body)),
        attachments,
    })
}

fn collect_parts(
    part: &GmailPart,
    message_id: &str,
    include_body: bool,
    max_attachment_bytes: u64,
    text: &mut Option<String>,
    html: &mut Option<String>,
    attachments: &mut Vec<Attachment>,
) -> ProviderResult<()> {
    let size = part.body.size.unwrap_or(0);
    let attachment = !part.filename.is_empty() || part.body.attachment_id.is_some();
    if attachment {
        if size <= max_attachment_bytes {
            let remote_id = part.body.attachment_id.as_deref().unwrap_or(&part.part_id);
            attachments.push(Attachment {
                id: AttachmentId::new(format!("gmail:{message_id}:{remote_id}"))?,
                filename: safe_filename(&part.filename),
                media_type: if part.mime_type.is_empty() {
                    "application/octet-stream".into()
                } else {
                    part.mime_type.clone()
                },
                size_bytes: size,
            });
        }
    } else if include_body {
        if let Some(data) = &part.body.data {
            if data.len() > MAX_BODY_BYTES.saturating_mul(4) / 3 + 8 {
                return Err(ProviderError::ProviderFailure);
            }
            let decoded = decode_gmail_base64(data).ok_or(ProviderError::ProviderFailure)?;
            if decoded.len() > MAX_BODY_BYTES {
                return Err(ProviderError::ProviderFailure);
            }
            let body = String::from_utf8_lossy(&decoded).into_owned();
            match part.mime_type.as_str() {
                "text/plain" if text.is_none() => *text = Some(body),
                "text/html" if html.is_none() => *html = Some(body),
                _ => {}
            }
        }
    }
    for child in &part.parts {
        collect_parts(
            child,
            message_id,
            include_body,
            max_attachment_bytes,
            text,
            html,
            attachments,
        )?;
    }
    Ok(())
}

fn decode_gmail_base64(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .ok()
}

fn header_map(payload: Option<&GmailPart>) -> BTreeMap<String, String> {
    payload
        .map(|payload| {
            payload
                .headers
                .iter()
                .map(|header| (header.name.to_ascii_lowercase(), header.value.clone()))
                .collect()
        })
        .unwrap_or_default()
}
fn header<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    headers.get(name).map(String::as_str)
}

fn parse_addresses(value: &str) -> Vec<EmailAddress> {
    value.split(',').filter_map(parse_one_address).collect()
}

fn parse_one_address(value: &str) -> Option<EmailAddress> {
    let value = value.trim();
    let (display_name, address) =
        if let (Some(open), Some(close)) = (value.rfind('<'), value.rfind('>')) {
            if close <= open {
                return None;
            }
            let name = value[..open].trim().trim_matches('"');
            (
                if name.is_empty() {
                    None
                } else {
                    Some(name.to_owned())
                },
                value[open + 1..close].trim(),
            )
        } else {
            (None, value)
        };
    let address = normalize_email(address).ok()?;
    let parsed = EmailAddress {
        address,
        display_name,
    };
    parsed.validate().ok()?;
    Some(parsed)
}

fn normalize_email(value: &str) -> ProviderResult<String> {
    let (local, domain) = value
        .rsplit_once('@')
        .ok_or(ProviderError::ProviderFailure)?;
    let normalized = format!("{local}@{}", domain.to_ascii_lowercase());
    let address = EmailAddress {
        address: normalized.clone(),
        display_name: None,
    };
    address
        .validate()
        .map_err(|_| ProviderError::ProviderFailure)?;
    Ok(normalized)
}

fn parse_internal_date(value: Option<&str>) -> Option<i64> {
    value?.parse::<i64>().ok().filter(|value| *value >= 0)
}
fn part_has_attachment(part: &GmailPart) -> bool {
    !part.filename.is_empty()
        || part.body.attachment_id.is_some()
        || part.parts.iter().any(part_has_attachment)
}
fn safe_filename(value: &str) -> String {
    let leaf = value.rsplit(['/', '\\']).next().unwrap_or("").trim();
    if leaf.is_empty() || leaf == "." || leaf == ".." {
        "attachment".into()
    } else {
        leaf.chars().filter(|c| !c.is_control()).take(255).collect()
    }
}
fn sanitize_html(value: &str) -> String {
    let mut builder = ammonia::Builder::default();
    builder.rm_tags(&[
        "img", "form", "iframe", "object", "embed", "svg", "math", "style",
    ]);
    builder.clean(value).to_string()
}

fn build_mime(request: &DraftRequest, reply_message_id: Option<&str>) -> ProviderResult<String> {
    let mut headers = vec![
        format!("To: {}", format_addresses(&request.to)),
        format!("Subject: {}", request.subject),
        "MIME-Version: 1.0".to_owned(),
    ];
    if !request.cc.is_empty() {
        headers.push(format!("Cc: {}", format_addresses(&request.cc)));
    }
    if !request.bcc.is_empty() {
        headers.push(format!("Bcc: {}", format_addresses(&request.bcc)));
    }
    if let Some(id) = reply_message_id {
        headers.push(format!("In-Reply-To: <{id}>"));
        headers.push(format!("References: <{id}>"));
    }
    let body = match (&request.text_body, &request.html_body) {
        (Some(text), Some(html)) => {
            let boundary = format!("fily-{}", random_urlsafe(18));
            headers.push(format!(
                "Content-Type: multipart/alternative; boundary=\"{boundary}\""
            ));
            format!("--{boundary}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{text}\r\n--{boundary}\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n{html}\r\n--{boundary}--\r\n")
        }
        (Some(text), None) => {
            headers.push("Content-Type: text/plain; charset=UTF-8".into());
            text.clone()
        }
        (None, Some(html)) => {
            headers.push("Content-Type: text/html; charset=UTF-8".into());
            html.clone()
        }
        (None, None) => {
            headers.push("Content-Type: text/plain; charset=UTF-8".into());
            String::new()
        }
    };
    Ok(format!("{}\r\n\r\n{}", headers.join("\r\n"), body))
}

fn safe_rfc_message_id(value: &str) -> Option<String> {
    let value = value.trim().trim_start_matches('<').trim_end_matches('>');
    if value.is_empty()
        || value.len() > 998
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || !byte.is_ascii())
    {
        None
    } else {
        Some(value.to_owned())
    }
}

fn format_addresses(addresses: &[EmailAddress]) -> String {
    addresses
        .iter()
        .map(|address| match &address.display_name {
            Some(name) => format!(
                "\"{}\" <{}>",
                name.replace(['"', '\\'], ""),
                address.address
            ),
            None => address.address.clone(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}
