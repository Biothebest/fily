pub mod gmail;
pub mod gmail_oauth;
pub mod icloud;
pub mod imap;
pub mod yahoo;

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::domain::mail::{
    ConnectRequest, ConnectedAccount, DeleteDraftRequest, DisconnectRequest, DraftRequest,
    DraftResult, Folder, ListFoldersRequest, Message, MoveRequest, MutationRequest, MutationResult,
    ProviderKind, RetrieveRequest, SearchRequest, SearchResults, SendRequest, SendResult, SyncBatch,
    SyncRequest, Validate, ValidationError,
};
use crate::vault::CredentialVault;

pub type ProviderResult<T> = Result<T, ProviderError>;

/// A deliberately lossy error boundary. Provider/library errors must be mapped to one of these
/// variants rather than forwarded because upstream errors can contain tokens, server responses,
/// usernames, or unrestricted filesystem paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", content = "message", rename_all = "snake_case")]
pub enum ProviderError {
    InvalidInput,
    NotConfigured,
    Unauthorized,
    Authentication,
    Network,
    NotFound,
    Conflict,
    RateLimited,
    Unsupported,
    ProviderFailure,
}

impl ProviderError {
    /// Maps an untrusted provider error to a detail-free command-boundary error.
    /// The argument is intentionally discarded because even bounded upstream text can contain
    /// credentials, server responses, usernames, or unrestricted filesystem paths.
    pub fn safe_failure(_untrusted_message: impl AsRef<str>) -> Self {
        Self::ProviderFailure
    }
}

impl From<ValidationError> for ProviderError {
    fn from(_value: ValidationError) -> Self {
        Self::InvalidInput
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => f.write_str("invalid provider input"),
            Self::NotConfigured => f.write_str("provider is not configured"),
            Self::Unauthorized => f.write_str("operation is not authorized"),
            Self::Authentication => f.write_str("provider authentication failed"),
            Self::Network => f.write_str("provider network operation failed"),
            Self::NotFound => f.write_str("provider resource was not found"),
            Self::Conflict => f.write_str("provider resource changed concurrently"),
            Self::RateLimited => f.write_str("provider rate limit reached"),
            Self::Unsupported => f.write_str("provider operation is unsupported"),
            Self::ProviderFailure => f.write_str("provider operation failed"),
        }
    }
}

impl std::error::Error for ProviderError {}

/// Normalized capability surface implemented by every mail adapter. Implementations receive only
/// opaque vault record IDs and trusted-core attachment IDs; credential bytes and filesystem paths
/// are intentionally absent from this contract.
#[async_trait]
pub trait MailProvider: Send + Sync {
    fn kind(&self) -> ProviderKind;

    async fn connect(&self, request: ConnectRequest) -> ProviderResult<ConnectedAccount>;
    async fn list_folders(&self, request: ListFoldersRequest) -> ProviderResult<Vec<Folder>>;
    async fn incremental_sync(&self, request: SyncRequest) -> ProviderResult<SyncBatch>;
    async fn retrieve(&self, request: RetrieveRequest) -> ProviderResult<Message>;
    async fn search(&self, request: SearchRequest) -> ProviderResult<SearchResults>;
    async fn draft(&self, request: DraftRequest) -> ProviderResult<DraftResult>;
    async fn delete_draft(&self, request: DeleteDraftRequest) -> ProviderResult<()>;
    async fn send(&self, request: SendRequest) -> ProviderResult<SendResult>;
    async fn move_messages(&self, request: MoveRequest) -> ProviderResult<MutationResult>;
    async fn archive(&self, request: MutationRequest) -> ProviderResult<MutationResult>;
    async fn trash(&self, request: MutationRequest) -> ProviderResult<MutationResult>;
    async fn disconnect(&self, request: DisconnectRequest) -> ProviderResult<()>;
}

/// Fixed provider registry. It validates every request before dispatch and cannot be mutated by
/// presentation code, preventing a provider from being silently replaced after startup.
pub struct ProviderRegistry {
    providers: BTreeMap<ProviderKind, Arc<dyn MailProvider>>,
    send_authorizations: Mutex<BTreeMap<String, (ProviderKind, String, String)>>,
}

impl ProviderRegistry {
    pub fn new(
        gmail: Arc<dyn MailProvider>,
        imap: Arc<dyn MailProvider>,
        yahoo: Arc<dyn MailProvider>,
        icloud: Arc<dyn MailProvider>,
    ) -> ProviderResult<Self> {
        let expected = [
            (ProviderKind::Gmail, gmail),
            (ProviderKind::Imap, imap),
            (ProviderKind::Yahoo, yahoo),
            (ProviderKind::Icloud, icloud),
        ];
        let mut providers = BTreeMap::new();
        for (kind, provider) in expected {
            if provider.kind() != kind {
                return Err(ProviderError::NotConfigured);
            }
            providers.insert(kind, provider);
        }
        Ok(Self {
            providers,
            send_authorizations: Mutex::new(BTreeMap::new()),
        })
    }

    fn get(&self, kind: ProviderKind) -> ProviderResult<&Arc<dyn MailProvider>> {
        self.providers
            .get(&kind)
            .ok_or(ProviderError::NotConfigured)
    }

    pub async fn connect(&self, request: ConnectRequest) -> ProviderResult<ConnectedAccount> {
        request.validate()?;
        let kind = request.provider;
        let account_id = request.account_id.clone();
        let identity = request.identity.clone();
        let connected = self.get(kind)?.connect(request).await?;
        connected.identity.validate()?;
        if connected.provider != kind
            || connected.account_id != account_id
            || !connected
                .identity
                .address
                .eq_ignore_ascii_case(&identity.address)
        {
            return Err(ProviderError::Conflict);
        }
        Ok(connected)
    }

    pub async fn list_folders(
        &self,
        kind: ProviderKind,
        request: ListFoldersRequest,
    ) -> ProviderResult<Vec<Folder>> {
        request.validate()?;
        self.get(kind)?.list_folders(request).await
    }

    pub async fn incremental_sync(
        &self,
        kind: ProviderKind,
        request: SyncRequest,
    ) -> ProviderResult<SyncBatch> {
        request.validate()?;
        self.get(kind)?.incremental_sync(request).await
    }

    pub async fn retrieve(
        &self,
        kind: ProviderKind,
        request: RetrieveRequest,
    ) -> ProviderResult<Message> {
        request.validate()?;
        self.get(kind)?.retrieve(request).await
    }

    pub async fn search(
        &self,
        kind: ProviderKind,
        request: SearchRequest,
    ) -> ProviderResult<SearchResults> {
        request.validate()?;
        self.get(kind)?.search(request).await
    }

    pub async fn draft(
        &self,
        kind: ProviderKind,
        request: DraftRequest,
    ) -> ProviderResult<DraftResult> {
        request.validate()?;
        self.get(kind)?.draft(request).await
    }

    pub async fn delete_draft(
        &self,
        kind: ProviderKind,
        request: DeleteDraftRequest,
    ) -> ProviderResult<()> {
        request.validate()?;
        self.get(kind)?.delete_draft(request).await
    }

    pub(crate) fn issue_send_authorization(
        &self,
        kind: ProviderKind,
        request: &SendRequest,
    ) -> ProviderResult<()> {
        request.validate()?;
        let mut authorizations = self
            .send_authorizations
            .lock()
            .map_err(|_| ProviderError::ProviderFailure)?;
        if authorizations.contains_key(request.authorization_id.as_str()) {
            return Err(ProviderError::Conflict);
        }
        authorizations.insert(
            request.authorization_id.as_str().to_owned(),
            (
                kind,
                request.account_id.as_str().to_owned(),
                request.draft_id.as_str().to_owned(),
            ),
        );
        Ok(())
    }

    pub async fn send(
        &self,
        kind: ProviderKind,
        request: SendRequest,
    ) -> ProviderResult<SendResult> {
        request.validate()?;
        let expected = self
            .send_authorizations
            .lock()
            .map_err(|_| ProviderError::ProviderFailure)?
            .remove(request.authorization_id.as_str());
        let actual = (
            kind,
            request.account_id.as_str().to_owned(),
            request.draft_id.as_str().to_owned(),
        );
        if expected.as_ref() != Some(&actual) {
            return Err(ProviderError::Unauthorized);
        }
        self.get(kind)?.send(request).await
    }

    pub async fn move_messages(
        &self,
        kind: ProviderKind,
        request: MoveRequest,
    ) -> ProviderResult<MutationResult> {
        request.validate()?;
        self.get(kind)?.move_messages(request).await
    }

    pub async fn archive(
        &self,
        kind: ProviderKind,
        request: MutationRequest,
    ) -> ProviderResult<MutationResult> {
        request.validate()?;
        self.get(kind)?.archive(request).await
    }

    pub async fn trash(
        &self,
        kind: ProviderKind,
        request: MutationRequest,
    ) -> ProviderResult<MutationResult> {
        request.validate()?;
        self.get(kind)?.trash(request).await
    }

    pub async fn disconnect(
        &self,
        kind: ProviderKind,
        request: DisconnectRequest,
    ) -> ProviderResult<()> {
        request.validate()?;
        self.get(kind)?.disconnect(request).await
    }
}

/// The fixed production provider set. Gmail onboarding retains the same concrete provider used by
/// the trait-object registry so its newly vaulted session is immediately available to sync.
pub struct ProductionProviders {
    pub registry: ProviderRegistry,
    pub gmail_onboarding: gmail_oauth::GmailOAuthOnboarding,
}

/// Builds the fixed production providers. Authorization is consumed by the command boundary before
/// any registry write method is called; this private bridge prevents Gmail from introducing a
/// second, provider-specific authorization convention that the IMAP adapters would not share.
pub fn production_providers(vault: CredentialVault) -> ProviderResult<ProductionProviders> {
    let vault = Arc::new(vault);
    let gmail = Arc::new(gmail::GmailProvider::new(
        vault.clone(),
        Arc::new(CommandBoundaryAuthorization),
    )?);
    let gmail_onboarding = gmail_oauth::GmailOAuthOnboarding::new(gmail.clone());
    let imap = Arc::new(imap::GenericImapProvider::new(vault.clone()));
    let yahoo = Arc::new(yahoo::YahooProvider::new(vault.clone()));
    let icloud = Arc::new(icloud::ICloudProvider::new(vault));
    let registry = ProviderRegistry::new(gmail, imap, yahoo, icloud)?;
    Ok(ProductionProviders {
        registry,
        gmail_onboarding,
    })
}

#[derive(Debug)]
struct CommandBoundaryAuthorization;

impl gmail::GmailAuthorizationGate for CommandBoundaryAuthorization {
    fn authorize_draft(&self, _request: &DraftRequest) -> bool {
        true
    }
    fn authorize_delete_draft(&self, _request: &DeleteDraftRequest) -> bool {
        true
    }
    fn authorize_send(&self, _request: &SendRequest) -> bool {
        true
    }
    fn authorize_move(&self, _request: &MoveRequest) -> bool {
        true
    }
    fn authorize_archive(&self, _request: &MutationRequest) -> bool {
        true
    }
    fn authorize_trash(&self, _request: &MutationRequest) -> bool {
        true
    }
    fn authorize_disconnect(&self, _request: &DisconnectRequest) -> bool {
        true
    }
}
