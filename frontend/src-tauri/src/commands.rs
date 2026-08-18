use std::{
    cmp::Reverse,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, State};

use crate::{
    agent::{
        ActionPlan, AgentError, AgentPolicy, ExecutionRequest, PermissionLevel, PlanAction,
        PlanApproval, PlanPreview, PlanRequest, PlanState, PreviewChange, ResourceVersion,
    },
    domain::mail::{
        AccountId, ConnectRequest, ConnectedAccount, CredentialId, DisconnectRequest, DraftRequest,
        DraftResult, EmailAddress, FolderId, ListFoldersRequest, Message as ProviderMessage,
        MessageId, MoveRequest, OperationId, ProviderEndpoint, ProviderKind, RetrieveRequest,
        SyncChange, SyncRequest, Validate,
    },
    migration::{self, LegacyMigrationState, LegacyMigrationStatus, MigrationError},
    native_credentials::{
        capture_native_credential, NativeCredential, NativeCredentialError, NativeCredentialPrompt,
    },
    providers::{gmail_oauth::GmailOAuthOnboarding, ProviderError, ProviderRegistry},
    recovery::{RecoveryRecord as AuthorizedRecovery, RecoveryStore},
    storage::{
        AccountRecord, AuditRecord, FolderRecord, MessageBody, MessageRecord, PlanRecord,
        RecoveryRecord as StoredRecovery, Storage, StorageError, SyncCursorRecord,
    },
    vault::CredentialVault,
};

const MAX_PAGE_SIZE: u32 = 100;
const MAX_SEARCH_BYTES: usize = 1_000;
const MAX_CONFIRMATION_BYTES: usize = 256;
const PLAN_LIMIT: u32 = 100;
const PLAN_TTL_MS: u64 = 15 * 60 * 1_000;
const DISCONNECT_CONFIRMATION: &str = "DISCONNECT";
static AUDIT_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandError {
    pub code: &'static str,
    pub message: &'static str,
}

impl CommandError {
    const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    fn invalid() -> Self {
        Self::new("invalid_request", "The request is invalid.")
    }
    fn not_found() -> Self {
        Self::new("not_found", "The requested item was not found.")
    }
    fn unavailable() -> Self {
        Self::new("unavailable", "The trusted core is unavailable.")
    }
    fn denied() -> Self {
        Self::new("not_authorized", "This action is not authorized.")
    }
}

impl From<StorageError> for CommandError {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::InvalidInput(_) => Self::invalid(),
            StorageError::Authentication | StorageError::CorruptData => Self::new(
                "data_unavailable",
                "Encrypted application data is unavailable.",
            ),
            _ => Self::unavailable(),
        }
    }
}
impl From<MigrationError> for CommandError {
    fn from(error: MigrationError) -> Self {
        match error {
            MigrationError::InvalidSource => {
                Self::new("legacy_data_invalid", "Legacy Fily data could not be read.")
            }
            MigrationError::SourceChanged => Self::new(
                "legacy_data_changed",
                "Legacy Fily data changed during migration. Try again.",
            ),
            MigrationError::Storage(error) => error.into(),
            MigrationError::Source(_) => Self::new(
                "legacy_data_unavailable",
                "Legacy Fily data is unavailable.",
            ),
        }
    }
}

impl From<ProviderError> for CommandError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::InvalidInput => Self::invalid(),
            ProviderError::NotFound => Self::not_found(),
            ProviderError::Unauthorized | ProviderError::Authentication => Self::denied(),
            ProviderError::Conflict => Self::new(
                "conflict",
                "The provider item changed. Refresh and try again.",
            ),
            ProviderError::RateLimited => {
                Self::new("rate_limited", "The provider is temporarily rate limited.")
            }
            ProviderError::Network => Self::new("network", "The provider could not be reached."),
            ProviderError::NotConfigured | ProviderError::Unsupported => Self::new(
                "provider_unavailable",
                "This provider operation is unavailable.",
            ),
            ProviderError::ProviderFailure => {
                Self::new("provider_failed", "The provider operation failed.")
            }
        }
    }
}

impl From<AgentError> for CommandError {
    fn from(error: AgentError) -> Self {
        match error {
            AgentError::InvalidInput(_) => Self::invalid(),
            AgentError::PlanNotFound | AgentError::DuplicatePlan => Self::not_found(),
            AgentError::PlanExpired => Self::new("plan_expired", "This plan has expired."),
            AgentError::ConfirmationRequired => Self::new(
                "confirmation_required",
                "The required confirmation did not match.",
            ),
            AgentError::PlanNotPending | AgentError::PlanNotApproved => Self::new(
                "invalid_plan_state",
                "The plan is not in the required state.",
            ),
            AgentError::PermissionDenied(_) | AgentError::IntegrityMismatch => Self::denied(),
            AgentError::VersionDrift { .. } => Self::new(
                "version_conflict",
                "An affected item changed after the plan was created.",
            ),
        }
    }
}

pub struct AppState {
    storage: Storage,
    vault: CredentialVault,
    providers: Arc<ProviderRegistry>,
    gmail_onboarding: Option<Arc<GmailOAuthOnboarding>>,
    policy: Mutex<AgentPolicy>,
    recovery: Mutex<RecoveryStore>,
    legacy_source: Option<PathBuf>,
}

impl AppState {
    pub fn initialize(app: &AppHandle) -> Result<Self, CommandError> {
        let data_dir = app
            .path()
            .app_data_dir()
            .map_err(|_| CommandError::unavailable())?;
        let home_dir = app
            .path()
            .home_dir()
            .map_err(|_| CommandError::unavailable())?;
        let vault =
            CredentialVault::new("com.fily.desktop").map_err(|_| CommandError::unavailable())?;
        let storage = Storage::open_with_vault(data_dir.join("fily.db"), &vault)?;
        let production = crate::providers::production_providers(vault.clone())?;
        let mut state = Self::from_parts(storage, vault, Arc::new(production.registry))?;
        state.gmail_onboarding = Some(Arc::new(production.gmail_onboarding));
        state.legacy_source = Some(migration::legacy_database_path(&home_dir));
        Ok(state)
    }

    pub fn from_parts(
        storage: Storage,
        vault: CredentialVault,
        providers: Arc<ProviderRegistry>,
    ) -> Result<Self, CommandError> {
        let permissions = [
            PermissionLevel::Read,
            PermissionLevel::Organize,
            PermissionLevel::Draft,
            PermissionLevel::Send,
            PermissionLevel::Move,
            PermissionLevel::Delete,
        ];
        let mut policy = AgentPolicy::new(permissions, 24 * 60 * 60 * 1_000)?;
        for record in storage.list_plans(None, PLAN_LIMIT)? {
            if let Ok(payload) = serde_json::from_value::<StoredPlanPayload>(record.payload) {
                policy.restore_plan(payload.plan)?;
            }
        }
        let mut recovery = RecoveryStore::new();
        for record in storage.list_recovery(None)? {
            if let Ok(payload) = serde_json::from_value::<AuthorizedRecovery>(record.state) {
                recovery
                    .insert(payload)
                    .map_err(|_| CommandError::unavailable())?;
            }
        }
        Ok(Self {
            storage,
            vault,
            providers,
            gmail_onboarding: None,
            policy: Mutex::new(policy),
            recovery: Mutex::new(recovery),
            legacy_source: None,
        })
    }

    fn policy(&self) -> Result<MutexGuard<'_, AgentPolicy>, CommandError> {
        self.policy.lock().map_err(|_| CommandError::unavailable())
    }

    fn recovery(&self) -> Result<MutexGuard<'_, RecoveryStore>, CommandError> {
        self.recovery
            .lock()
            .map_err(|_| CommandError::unavailable())
    }

    fn account(&self, id: &str) -> Result<AccountRecord, CommandError> {
        validate_id(id)?;
        self.storage
            .get_account(id)?
            .ok_or_else(CommandError::not_found)
    }

    fn provider_for(&self, account: &AccountRecord) -> Result<ProviderKind, CommandError> {
        provider_kind(&account.provider)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootstrapRequest {
    pub message_limit: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapData {
    pub folders: Vec<MailboxFolder>,
    pub accounts: Vec<ConnectedAccountView>,
    pub messages: Vec<MessageSummaryView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailboxFolder {
    pub id: String,
    pub label: String,
    pub count: Option<u32>,
    pub unread_count: Option<u32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectedAccountView {
    pub id: String,
    pub provider: String,
    pub email: String,
    pub display_name: Option<String>,
    pub status: &'static str,
    pub last_synced_at: Option<String>,
    pub status_message: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MailAddressView {
    pub name: Option<String>,
    pub address: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageSummaryView {
    pub id: String,
    pub thread_id: String,
    pub account_id: String,
    pub folder_id: String,
    pub sender: MailAddressView,
    pub subject: String,
    pub snippet: String,
    pub received_at: String,
    pub unread: bool,
    pub starred: bool,
    pub has_attachments: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafeAttachment {
    pub id: String,
    pub filename: String,
    pub media_type: String,
    pub size_bytes: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SanitizedMessage {
    #[serde(flatten)]
    pub summary: MessageSummaryView,
    pub recipients: Vec<MailAddressView>,
    pub cc: Vec<MailAddressView>,
    pub body_text: String,
    pub remote_content_blocked: bool,
    pub attachments: Vec<SafeAttachment>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MessageRequest {
    pub message_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SearchMessagesRequest {
    pub query: String,
    pub limit: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchHitView {
    pub message: MessageSummaryView,
    pub matched_snippet: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListMessagesRequest {
    pub account_id: String,
    pub folder_id: Option<String>,
    pub limit: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImapPublicConfiguration {
    pub imap_host: String,
    pub imap_port: u16,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub username: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BeginAccountConnectionRequest {
    pub provider: ProviderKind,
    pub email: Option<String>,
    pub imap_configuration: Option<ImapPublicConfiguration>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountConnectionStatusRequest {
    pub connection_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountConnectionView {
    pub connection_id: String,
    pub provider: ProviderKind,
    pub phase: &'static str,
    pub authorization_url: Option<&'static str>,
    pub account: Option<ConnectedAccountView>,
    pub status_message: Option<&'static str>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartSyncRequest {
    pub account_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanIdRequest {
    pub plan_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovePlanRequest {
    pub plan_id: String,
    pub confirmation: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisconnectAccountRequest {
    pub account_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanStep {
    pub label: String,
    pub detail: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanPreviewField {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentPlanView {
    pub id: String,
    pub action: String,
    pub summary: String,
    pub rationale: String,
    pub risk: &'static str,
    pub status: &'static str,
    pub steps: Vec<PlanStep>,
    pub preview: Vec<PlanPreviewField>,
    pub required_confirmation: String,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanExecution {
    pub plan_id: String,
    pub status: &'static str,
    pub completed_at: Option<String>,
    pub summary: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UndoRequest {
    pub recovery_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UndoResult {
    pub recovery_id: String,
    pub status: &'static str,
    pub completed_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditRequest {
    pub limit: u32,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEventView {
    pub id: String,
    pub occurred_at: String,
    pub actor: String,
    pub action: String,
    pub outcome: String,
    pub summary: String,
    pub resource_label: Option<String>,
    pub plan_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditPage {
    pub events: Vec<AuditEventView>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PlannedOperation {
    Disconnect {
        account_id: String,
        provider: ProviderKind,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredPlanPayload {
    plan: ActionPlan,
    operation: PlannedOperation,
}

#[tauri::command]
pub fn legacy_migration_status(
    state: State<'_, AppState>,
) -> Result<LegacyMigrationStatus, CommandError> {
    let Some(source) = state.legacy_source.as_deref() else {
        return Ok(LegacyMigrationStatus {
            state: LegacyMigrationState::NotFound,
            accounts: 0,
            messages: 0,
            skipped: 0,
        });
    };
    migration::status(&state.storage, source).map_err(CommandError::from)
}

#[tauri::command]
pub fn migrate_legacy(state: State<'_, AppState>) -> Result<LegacyMigrationStatus, CommandError> {
    let Some(source) = state.legacy_source.as_deref() else {
        return Ok(LegacyMigrationStatus {
            state: LegacyMigrationState::NotFound,
            accounts: 0,
            messages: 0,
            skipped: 0,
        });
    };
    migration::migrate(&state.storage, source).map_err(CommandError::from)
}

#[tauri::command]
pub fn bootstrap(
    state: State<'_, AppState>,
    request: BootstrapRequest,
) -> Result<BootstrapData, CommandError> {
    validate_limit(request.message_limit)?;
    let account_records = state.storage.list_accounts()?;
    let accounts = account_records
        .iter()
        .map(|record| account_view(&state, record))
        .collect::<Result<Vec<_>, _>>()?;
    let mut folders = Vec::new();
    let mut messages = Vec::new();
    let mut remaining = request.message_limit;
    for account in &account_records {
        folders.extend(
            state
                .storage
                .list_folders(&account.id)?
                .into_iter()
                .map(folder_view),
        );
        if remaining > 0 {
            let records = state.storage.list_messages(&account.id, None, remaining)?;
            remaining = remaining.saturating_sub(records.len() as u32);
            messages.extend(records.into_iter().map(message_summary));
        }
    }
    messages.sort_by_key(|message| Reverse(message.received_at.clone()));
    Ok(BootstrapData {
        folders,
        accounts,
        messages,
    })
}

#[tauri::command]
pub fn list_accounts(
    state: State<'_, AppState>,
) -> Result<Vec<ConnectedAccountView>, CommandError> {
    state
        .storage
        .list_accounts()?
        .iter()
        .map(|record| account_view(&state, record))
        .collect()
}
#[tauri::command]
pub async fn begin_account_connection(
    app: AppHandle,
    state: State<'_, AppState>,
    request: BeginAccountConnectionRequest,
) -> Result<AccountConnectionView, CommandError> {
    let mut connected = match request.provider {
        ProviderKind::Gmail => {
            if request.email.is_some() || request.imap_configuration.is_some() {
                return Err(CommandError::invalid());
            }
            state
                .gmail_onboarding
                .as_ref()
                .ok_or_else(|| {
                    CommandError::new(
                        "provider_unavailable",
                        "This provider operation is unavailable.",
                    )
                })?
                .connect()
                .await?
        }
        provider => connect_password_provider(&app, &state, provider, request).await?,
    };
    reconcile_connected_identity(&state, &mut connected)?;
    persist_connected_account(&state, &connected).await?;
    connection_view(&state, &connected.account_id, connected.provider)
}

#[tauri::command]
pub fn account_connection_status(
    state: State<'_, AppState>,
    request: AccountConnectionStatusRequest,
) -> Result<AccountConnectionView, CommandError> {
    validate_id(&request.connection_id)?;
    let account = state.account(&request.connection_id)?;
    let provider = provider_kind(&account.provider)?;
    let account_id = AccountId::new(account.id).map_err(|_| CommandError::unavailable())?;
    connection_view(&state, &account_id, provider)
}

#[tauri::command]
pub fn complete_account_connection(
    state: State<'_, AppState>,
    request: AccountConnectionStatusRequest,
) -> Result<AccountConnectionView, CommandError> {
    validate_id(&request.connection_id)?;
    let account = state.account(&request.connection_id)?;
    let provider = provider_kind(&account.provider)?;
    let account_id = AccountId::new(account.id).map_err(|_| CommandError::unavailable())?;
    connection_view(&state, &account_id, provider)
}

async fn connect_password_provider(
    app: &AppHandle,
    state: &AppState,
    provider: ProviderKind,
    request: BeginAccountConnectionRequest,
) -> Result<ConnectedAccount, CommandError> {
    let address = request.email.ok_or_else(CommandError::invalid)?;
    let identity = EmailAddress {
        address: address.trim().to_ascii_lowercase(),
        display_name: None,
    };
    identity.validate().map_err(|_| CommandError::invalid())?;
    let (endpoint, username, host) = match provider {
        ProviderKind::Imap => {
            let config = request
                .imap_configuration
                .ok_or_else(CommandError::invalid)?;
            let endpoint = ProviderEndpoint {
                imap_host: config.imap_host,
                imap_port: config.imap_port,
                smtp_host: config.smtp_host,
                smtp_port: config.smtp_port,
                username: config.username,
                use_tls: true,
            };
            endpoint.validate().map_err(|_| CommandError::invalid())?;
            let username = endpoint.username.clone();
            let host = endpoint.imap_host.clone();
            (Some(endpoint), username, host)
        }
        ProviderKind::Yahoo => {
            if request.imap_configuration.is_some() {
                return Err(CommandError::invalid());
            }
            (None, identity.address.clone(), "imap.mail.yahoo.com".into())
        }
        ProviderKind::Icloud => {
            if request.imap_configuration.is_some() {
                return Err(CommandError::invalid());
            }
            (None, identity.address.clone(), "imap.mail.me.com".into())
        }
        ProviderKind::Gmail => return Err(CommandError::invalid()),
    };
    let account_id = existing_account_id(state, provider, &identity.address)?
        .map(AccountId::new)
        .transpose()
        .map_err(|_| CommandError::unavailable())?
        .unwrap_or(
            AccountId::new(random_opaque_id("account")).map_err(|_| CommandError::unavailable())?,
        );
    let credential_id = CredentialId::new(random_opaque_id("credential"))
        .map_err(|_| CommandError::unavailable())?;
    let provider_name = provider_slug(provider);
    let credential = capture_password_on_main_thread(app, provider_name, username, host)
        .await?
        .ok_or_else(|| {
            CommandError::new(
                "connection_cancelled",
                "The secure account connection was cancelled.",
            )
        })?;
    state
        .vault
        .set_secret(
            credential_id.as_str(),
            "imap-password",
            credential.expose_secret().as_bytes(),
        )
        .map_err(|_| CommandError::unavailable())?;
    if let Err(_error) = state.vault.set_secret(
        credential_id.as_str(),
        "smtp-password",
        credential.expose_secret().as_bytes(),
    ) {
        state
            .vault
            .delete_secret(credential_id.as_str(), "imap-password")
            .ok();
        return Err(CommandError::unavailable());
    }
    drop(credential);
    let connect = ConnectRequest {
        provider,
        account_id,
        credential_id: credential_id.clone(),
        identity,
        endpoint,
    };
    match state.providers.connect(connect).await {
        Ok(connected) => Ok(connected),
        Err(error) => {
            state
                .vault
                .delete_secret(credential_id.as_str(), "imap-password")
                .ok();
            state
                .vault
                .delete_secret(credential_id.as_str(), "smtp-password")
                .ok();
            Err(error.into())
        }
    }
}

async fn capture_password_on_main_thread(
    app: &AppHandle,
    provider: &'static str,
    username: String,
    host: String,
) -> Result<Option<NativeCredential>, CommandError> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    app.run_on_main_thread(move || {
        let captured = capture_native_credential(NativeCredentialPrompt {
            provider,
            username: &username,
            host: &host,
        });
        sender.send(captured).ok();
    })
    .map_err(|_| CommandError::unavailable())?;
    tauri::async_runtime::spawn_blocking(move || receiver.recv())
        .await
        .map_err(|_| CommandError::unavailable())?
        .map_err(|_| CommandError::unavailable())?
        .map_err(native_credential_error)
}

fn native_credential_error(error: NativeCredentialError) -> CommandError {
    match error {
        NativeCredentialError::UnsupportedProvider
        | NativeCredentialError::InvalidUsername
        | NativeCredentialError::InvalidHost
        | NativeCredentialError::InvalidSecret => CommandError::invalid(),
        NativeCredentialError::NotMainThread | NativeCredentialError::Unavailable => {
            CommandError::new(
                "native_capture_unavailable",
                "Native secure credential capture is unavailable.",
            )
        }
    }
}

fn existing_account_id(
    state: &AppState,
    provider: ProviderKind,
    address: &str,
) -> Result<Option<String>, CommandError> {
    Ok(state
        .storage
        .list_accounts()?
        .into_iter()
        .find(|account| {
            account
                .provider
                .eq_ignore_ascii_case(provider_slug(provider))
                && account.address.eq_ignore_ascii_case(address)
        })
        .map(|account| account.id))
}

fn reconcile_connected_identity(
    state: &AppState,
    connected: &mut ConnectedAccount,
) -> Result<(), CommandError> {
    let Some(existing_id) =
        existing_account_id(state, connected.provider, &connected.identity.address)?
    else {
        return Ok(());
    };
    if existing_id == connected.account_id.as_str() {
        return Ok(());
    }
    if connected.provider != ProviderKind::Gmail {
        return Err(CommandError::new(
            "account_conflict",
            "This provider account is already connected.",
        ));
    }
    let generated_key = format!(
        "gmail-account-{}",
        crate::agent::sha256_hex(connected.account_id.as_str().as_bytes())
    );
    let existing_key = format!(
        "gmail-account-{}",
        crate::agent::sha256_hex(existing_id.as_bytes())
    );
    let session = state
        .vault
        .get_secret(&generated_key, "gmail-oauth-token-v1")
        .map_err(|_| CommandError::unavailable())?
        .ok_or_else(CommandError::unavailable)?;
    state
        .vault
        .set_secret(&existing_key, "gmail-oauth-token-v1", session.as_ref())
        .map_err(|_| CommandError::unavailable())?;
    state
        .vault
        .delete_secret(&generated_key, "gmail-oauth-token-v1")
        .map_err(|_| CommandError::unavailable())?;
    connected.account_id = AccountId::new(existing_id).map_err(|_| CommandError::unavailable())?;
    Ok(())
}

async fn persist_connected_account(
    state: &AppState,
    connected: &ConnectedAccount,
) -> Result<(), CommandError> {
    connected
        .identity
        .validate()
        .map_err(|_| CommandError::unavailable())?;
    let now = now_ms()? as i64;
    state.storage.upsert_account(&AccountRecord {
        id: connected.account_id.as_str().to_owned(),
        provider: provider_slug(connected.provider).into(),
        address: connected.identity.address.clone(),
        display_name: connected.identity.display_name.clone(),
        created_at: now,
        updated_at: now,
    })?;
    let folders = state
        .providers
        .list_folders(
            connected.provider,
            ListFoldersRequest {
                account_id: connected.account_id.clone(),
            },
        )
        .await?;
    for folder in folders {
        state.storage.upsert_folder(&FolderRecord {
            id: folder.id.as_str().to_owned(),
            account_id: connected.account_id.as_str().to_owned(),
            remote_id: folder.id.as_str().to_owned(),
            parent_id: None,
            name: folder.name,
            role: Some(format!("{:?}", folder.role).to_ascii_lowercase()),
            unread_count: folder.unread_count.unwrap_or(0).min(u32::MAX as u64) as u32,
            total_count: folder.total_count.unwrap_or(0).min(u32::MAX as u64) as u32,
            updated_at: now,
        })?;
    }
    Ok(())
}

fn connection_view(
    state: &AppState,
    account_id: &AccountId,
    provider: ProviderKind,
) -> Result<AccountConnectionView, CommandError> {
    let record = state.account(account_id.as_str())?;
    Ok(AccountConnectionView {
        connection_id: account_id.as_str().to_owned(),
        provider,
        phase: "connected",
        authorization_url: None,
        account: Some(account_view(state, &record)?),
        status_message: Some("The account is connected and ready for its first bounded sync."),
    })
}

fn provider_slug(provider: ProviderKind) -> &'static str {
    match provider {
        ProviderKind::Gmail => "gmail",
        ProviderKind::Imap => "imap",
        ProviderKind::Yahoo => "yahoo",
        ProviderKind::Icloud => "icloud",
    }
}

fn random_opaque_id(prefix: &str) -> String {
    let mut random = [0_u8; 32];
    OsRng.fill_bytes(&mut random);
    format!("{prefix}:{}", crate::agent::sha256_hex(&random))
}

#[tauri::command]
pub fn list_folders(
    state: State<'_, AppState>,
    request: crate::domain::mail::ListFoldersRequest,
) -> Result<Vec<MailboxFolder>, CommandError> {
    request.validate().map_err(|_| CommandError::invalid())?;
    state.account(request.account_id.as_str())?;
    Ok(state
        .storage
        .list_folders(request.account_id.as_str())?
        .into_iter()
        .map(folder_view)
        .collect())
}

#[tauri::command]
pub fn list_messages(
    state: State<'_, AppState>,
    request: ListMessagesRequest,
) -> Result<Vec<MessageSummaryView>, CommandError> {
    validate_id(&request.account_id)?;
    if let Some(folder) = &request.folder_id {
        validate_id(folder)?;
    }
    validate_limit(request.limit)?;
    state.account(&request.account_id)?;
    Ok(state
        .storage
        .list_messages(
            &request.account_id,
            request.folder_id.as_deref(),
            request.limit,
        )?
        .into_iter()
        .map(message_summary)
        .collect())
}

#[tauri::command]
pub async fn get_message(
    state: State<'_, AppState>,
    request: MessageRequest,
) -> Result<SanitizedMessage, CommandError> {
    validate_id(&request.message_id)?;
    let stored = state
        .storage
        .get_message(&request.message_id)?
        .ok_or_else(CommandError::not_found)?;
    if stored.body.text.is_some() {
        return stored_message_view(&state.storage, stored);
    }
    let account = state.account(&stored.account_id)?;
    let message = state
        .providers
        .retrieve(
            state.provider_for(&account)?,
            RetrieveRequest {
                account_id: AccountId::new(account.id.clone())
                    .map_err(|_| CommandError::invalid())?,
                message_id: MessageId::new(stored.remote_id)
                    .map_err(|_| CommandError::invalid())?,
                include_body: true,
                max_attachment_bytes: 0,
            },
        )
        .await?;
    Ok(provider_message_view(account.id, message))
}

#[tauri::command]
pub fn search_messages(
    state: State<'_, AppState>,
    request: SearchMessagesRequest,
) -> Result<Vec<SearchHitView>, CommandError> {
    validate_search(&request.query)?;
    validate_limit(request.limit)?;
    let mut hits = Vec::new();
    for account in state.storage.list_accounts()? {
        for hit in state
            .storage
            .search_messages(&account.id, &request.query, request.limit)?
        {
            if let Some(message) = state.storage.get_message(&hit.message_id)? {
                hits.push((
                    hit.received_at,
                    SearchHitView {
                        message: message_summary(message),
                        matched_snippet: hit.snippet,
                    },
                ));
            }
        }
    }
    hits.sort_by_key(|(received_at, _)| Reverse(*received_at));
    hits.truncate(request.limit as usize);
    Ok(hits.into_iter().map(|(_, hit)| hit).collect())
}

#[tauri::command]
pub async fn create_draft(
    state: State<'_, AppState>,
    request: DraftRequest,
) -> Result<DraftResult, CommandError> {
    request.validate().map_err(|_| CommandError::invalid())?;
    let account = state.account(request.account_id.as_str())?;
    let result = state
        .providers
        .draft(state.provider_for(&account)?, request)
        .await?;
    append_audit(
        &state.storage,
        None,
        Some(&account.id),
        "draft_created",
        "allowed",
        "A draft was created.",
        now_ms()?,
    )?;
    Ok(result)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncOutcome {
    pub account_id: String,
    pub phase: &'static str,
    pub processed: u32,
    pub total: Option<u32>,
    pub has_more: bool,
    pub status_message: Option<&'static str>,
}

#[tauri::command]
pub async fn start_sync(
    state: State<'_, AppState>,
    app: AppHandle,
    request: StartSyncRequest,
) -> Result<SyncOutcome, CommandError> {
    validate_id(&request.account_id)?;
    let account = state.account(&request.account_id)?;
    emit_sync_progress(
        &app,
        SyncOutcome {
            account_id: account.id.clone(),
            phase: "starting",
            processed: 0,
            total: None,
            has_more: false,
            status_message: Some("Starting secure provider sync."),
        },
    );
    let cursor = state
        .storage
        .get_sync_cursor(&account.id, "account")?
        .map(|record| record.cursor);
    let folder_ids = state
        .storage
        .list_folders(&account.id)?
        .into_iter()
        .map(|folder| FolderId::new(folder.id).map_err(|_| CommandError::unavailable()))
        .collect::<Result<Vec<_>, _>>()?;
    let sync_request = SyncRequest {
        account_id: AccountId::new(account.id.clone()).map_err(|_| CommandError::unavailable())?,
        folder_ids,
        cursor,
        limit: MAX_PAGE_SIZE as u16,
    };
    sync_request
        .validate()
        .map_err(|_| CommandError::invalid())?;
    let batch = match state
        .providers
        .incremental_sync(state.provider_for(&account)?, sync_request)
        .await
    {
        Ok(batch) => batch,
        Err(error) => {
            emit_sync_progress(
                &app,
                SyncOutcome {
                    account_id: account.id.clone(),
                    phase: "failed",
                    processed: 0,
                    total: None,
                    has_more: false,
                    status_message: Some("The provider sync could not be completed."),
                },
            );
            return Err(error.into());
        }
    };
    let now = now_ms()? as i64;
    let total = u32::try_from(batch.changes.len()).unwrap_or(MAX_PAGE_SIZE);
    let mut changed = 0_u32;
    for change in batch.changes {
        match change {
            SyncChange::Delete(message_id) => {
                state.storage.delete_message(message_id.as_str())?;
            }
            SyncChange::Upsert(message) => {
                let sender = message
                    .from
                    .as_ref()
                    .map(|address| address.address.clone())
                    .unwrap_or_default();
                let recipients = message
                    .to
                    .iter()
                    .map(|address| address.address.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                let flags = match (message.unread, message.has_attachments) {
                    (true, true) => "unread,attachment",
                    (true, false) => "unread",
                    (false, true) => "attachment",
                    (false, false) => "",
                };
                state.storage.upsert_message(&MessageRecord {
                    id: message.id.as_str().to_owned(),
                    account_id: account.id.clone(),
                    folder_id: message.folder_ids.first().map(|id| id.as_str().to_owned()),
                    remote_id: message.id.as_str().to_owned(),
                    thread_id: message.thread_id,
                    subject: message.subject,
                    sender,
                    recipients,
                    snippet: message.preview,
                    flags: flags.into(),
                    sent_at: None,
                    received_at: message.received_at_ms,
                    size_bytes: 0,
                    body: MessageBody {
                        text: None,
                        html: None,
                    },
                    updated_at: now,
                })?;
            }
        }
        changed = changed.saturating_add(1);
        if changed % 10 == 0 || changed == total {
            emit_sync_progress(
                &app,
                SyncOutcome {
                    account_id: account.id.clone(),
                    phase: "syncing",
                    processed: changed,
                    total: Some(total),
                    has_more: batch.has_more,
                    status_message: Some("Indexing provider changes securely."),
                },
            );
        }
    }
    if let Some(cursor) = &batch.next_cursor {
        state.storage.upsert_sync_cursor(&SyncCursorRecord {
            account_id: account.id.clone(),
            scope: "account".into(),
            cursor: cursor.clone(),
            updated_at: now,
        })?;
    }
    let outcome = SyncOutcome {
        account_id: account.id,
        phase: if batch.has_more {
            "more_available"
        } else {
            "complete"
        },
        processed: changed,
        total: Some(total),
        has_more: batch.has_more,
        status_message: Some(if batch.has_more {
            "This bounded sync pass is complete; more changes are available."
        } else {
            "Secure sync is complete."
        }),
    };
    emit_sync_progress(&app, outcome.clone());
    Ok(outcome)
}

fn emit_sync_progress(app: &AppHandle, progress: SyncOutcome) {
    let _ = app.emit_to("main", "account-sync-progress", progress);
}

#[tauri::command]
pub fn disconnect_account(
    state: State<'_, AppState>,
    request: DisconnectAccountRequest,
) -> Result<AgentPlanView, CommandError> {
    let account = state.account(&request.account_id)?;
    let provider = state.provider_for(&account)?;
    let now = now_ms()?;
    let version = account.updated_at.to_string();
    let plan_request = PlanRequest {
        account_id: account.id.clone(),
        action: PlanAction::Disconnect,
        affected: vec![ResourceVersion { resource_id: account.id.clone(), version }],
        reason: "Disconnect this account and remove its provider credential from the operating-system vault.".into(),
        preview: PlanPreview {
            summary: format!("Disconnect {}", bounded_output(&account.address, 320)),
            affected_count: 1,
            changes: vec![PreviewChange { resource_id: account.id.clone(), description: "Stop synchronization and remove the local account session.".into() }],
        },
        expires_in_ms: PLAN_TTL_MS,
    };
    let plan = state.policy()?.create_plan(plan_request, now)?;
    let payload = StoredPlanPayload {
        plan: plan.clone(),
        operation: PlannedOperation::Disconnect {
            account_id: account.id,
            provider,
        },
    };
    persist_plan(&state.storage, &payload)?;
    append_audit(
        &state.storage,
        Some(&plan.plan_id),
        Some(&plan.account_id),
        "plan_created",
        "allowed",
        "A disconnect plan was created.",
        now,
    )?;
    Ok(plan_view(&plan))
}

#[tauri::command]
pub fn list_plans(state: State<'_, AppState>) -> Result<Vec<AgentPlanView>, CommandError> {
    state
        .storage
        .list_plans(None, PLAN_LIMIT)?
        .into_iter()
        .map(|record| {
            let payload: StoredPlanPayload =
                serde_json::from_value(record.payload).map_err(|_| CommandError::unavailable())?;
            Ok(plan_view(&payload.plan))
        })
        .collect()
}

#[tauri::command]
pub fn approve_plan(
    state: State<'_, AppState>,
    request: ApprovePlanRequest,
) -> Result<AgentPlanView, CommandError> {
    validate_id(&request.plan_id)?;
    validate_confirmation(&request.confirmation)?;
    let stored = load_plan(&state.storage, &request.plan_id)?;
    let required = required_confirmation(&stored.plan);
    if !required.is_empty() && request.confirmation != required {
        return Err(CommandError::new(
            "confirmation_required",
            "The required confirmation did not match.",
        ));
    }
    let now = now_ms()?;
    let approved = state.policy()?.approve_plan(
        PlanApproval {
            plan_id: stored.plan.plan_id.clone(),
            integrity_hash: stored.plan.integrity_hash.clone(),
            confirmed: required.is_empty() || request.confirmation == required,
        },
        now,
    )?;
    let payload = StoredPlanPayload {
        plan: approved.clone(),
        operation: stored.operation,
    };
    persist_plan(&state.storage, &payload)?;
    append_audit(
        &state.storage,
        Some(&approved.plan_id),
        Some(&approved.account_id),
        "plan_approved",
        "allowed",
        "The user approved a plan.",
        now,
    )?;
    Ok(plan_view(&approved))
}

#[tauri::command]
pub async fn execute_plan(
    state: State<'_, AppState>,
    request: PlanIdRequest,
) -> Result<PlanExecution, CommandError> {
    validate_id(&request.plan_id)?;
    let stored = load_plan(&state.storage, &request.plan_id)?;
    let current_versions = current_versions(&state.storage, &stored.plan)?;
    let now = now_ms()?;
    let authorization = state.policy()?.authorize_execution(
        ExecutionRequest {
            plan_id: stored.plan.plan_id.clone(),
            integrity_hash: stored.plan.integrity_hash.clone(),
            current_versions,
        },
        now,
    )?;
    persist_plan(
        &state.storage,
        &StoredPlanPayload {
            plan: authorization.plan.clone(),
            operation: stored.operation.clone(),
        },
    )?;

    let execution: Result<&'static str, CommandError> = async {
        match &stored.operation {
            PlannedOperation::Disconnect {
                account_id,
                provider,
            } => {
                let account_id =
                    AccountId::new(account_id.clone()).map_err(|_| CommandError::invalid())?;
                state
                    .providers
                    .disconnect(
                        *provider,
                        DisconnectRequest {
                            account_id: account_id.clone(),
                        },
                    )
                    .await?;
                for kind in ["oauth_refresh_token", "password", "smtp_password"] {
                    state
                        .vault
                        .delete_secret(account_id.as_str(), kind)
                        .map_err(|_| CommandError::unavailable())?;
                }
                state.storage.delete_account(account_id.as_str())?;
                Ok("The account was disconnected.")
            }
        }
    }
    .await;

    let result = match execution {
        Ok(result) => result,
        Err(error) => {
            append_audit(
                &state.storage,
                Some(&authorization.plan.plan_id),
                Some(&authorization.plan.account_id),
                "plan_executed",
                "failed",
                "A planned action failed.",
                now,
            )?;
            return Err(error);
        }
    };
    append_audit(
        &state.storage,
        Some(&authorization.plan.plan_id),
        None,
        "plan_executed",
        "allowed",
        result,
        now,
    )?;
    Ok(PlanExecution {
        plan_id: authorization.plan.plan_id,
        status: "executed",
        completed_at: Some(timestamp(now as i64)),
        summary: result.into(),
    })
}

#[tauri::command]
pub async fn undo_action(
    state: State<'_, AppState>,
    request: UndoRequest,
) -> Result<UndoResult, CommandError> {
    validate_id(&request.recovery_id)?;
    let stored = state
        .storage
        .get_recovery(&request.recovery_id)?
        .ok_or_else(CommandError::not_found)?;
    let record: AuthorizedRecovery =
        serde_json::from_value(stored.state).map_err(|_| CommandError::unavailable())?;
    if state.recovery()?.record(&record.recovery_id).is_none() {
        state
            .recovery()?
            .insert(record.clone())
            .map_err(|_| CommandError::unavailable())?;
    }
    let versions = current_recovery_versions(&state.storage, &record)?;
    let now = now_ms()?;
    let authorization = state
        .recovery()?
        .authorize_undo(&record.recovery_id, &versions, now)
        .map_err(|_| CommandError::denied())?;
    let destination = authorization
        .recovery
        .items
        .first()
        .and_then(|item| item.original_container_ids.first())
        .ok_or_else(CommandError::invalid)?;
    if authorization
        .recovery
        .items
        .iter()
        .any(|item| item.original_container_ids.first() != Some(destination))
    {
        state
            .recovery()?
            .finish_undo(&record.recovery_id, false, now)
            .map_err(|_| CommandError::unavailable())?;
        return Err(CommandError::new(
            "undo_unavailable",
            "This action cannot be undone as one provider operation.",
        ));
    }
    let account = state.account(&record.account_id)?;
    let move_request = MoveRequest {
        account_id: AccountId::new(record.account_id.clone())
            .map_err(|_| CommandError::invalid())?,
        message_ids: record
            .items
            .iter()
            .map(|item| {
                MessageId::new(item.resource_id.clone()).map_err(|_| CommandError::invalid())
            })
            .collect::<Result<Vec<_>, _>>()?,
        destination_folder_id: FolderId::new(destination.clone())
            .map_err(|_| CommandError::invalid())?,
        authorization_id: OperationId::new(record.recovery_id.clone())
            .map_err(|_| CommandError::invalid())?,
    };
    let succeeded = state
        .providers
        .move_messages(state.provider_for(&account)?, move_request)
        .await
        .is_ok();
    let finished = state
        .recovery()?
        .finish_undo(&record.recovery_id, succeeded, now)
        .map_err(|_| CommandError::unavailable())?;
    persist_recovery(&state.storage, &finished)?;
    if !succeeded {
        return Err(CommandError::new(
            "provider_failed",
            "The provider could not undo this action.",
        ));
    }
    append_audit(
        &state.storage,
        Some(&record.plan_id),
        Some(&record.account_id),
        "action_undone",
        "allowed",
        "A provider action was undone.",
        now,
    )?;
    Ok(UndoResult {
        recovery_id: record.recovery_id,
        status: "undone",
        completed_at: timestamp(now as i64),
    })
}

#[tauri::command]
pub fn list_audit(
    state: State<'_, AppState>,
    request: AuditRequest,
) -> Result<AuditPage, CommandError> {
    validate_limit(request.limit)?;
    if let Some(cursor) = &request.cursor {
        validate_id(cursor)?;
    }
    let records = state.storage.list_audit(None, 200)?;
    let start = match request.cursor {
        Some(cursor) => records
            .iter()
            .position(|record| record.id == cursor)
            .map(|position| position + 1)
            .ok_or_else(CommandError::not_found)?,
        None => 0,
    };
    let end = (start + request.limit as usize).min(records.len());
    let next_cursor = if end < records.len() {
        records
            .get(end.saturating_sub(1))
            .map(|record| record.id.clone())
    } else {
        None
    };
    let events = records[start..end].iter().map(audit_view).collect();
    Ok(AuditPage {
        events,
        next_cursor,
    })
}

fn account_view(
    state: &AppState,
    record: &AccountRecord,
) -> Result<ConnectedAccountView, CommandError> {
    let kind = provider_kind(&record.provider)?;
    let provider = provider_slug(kind);
    let gmail_authorized = if kind == ProviderKind::Gmail {
        let key = format!(
            "gmail-account-{}",
            crate::agent::sha256_hex(record.id.as_bytes())
        );
        state
            .vault
            .get_secret(&key, "gmail-oauth-token-v1")
            .ok()
            .flatten()
            .is_some()
    } else {
        true
    };
    Ok(ConnectedAccountView {
        id: record.id.clone(),
        provider: provider.into(),
        email: record.address.clone(),
        display_name: record.display_name.clone(),
        status: if gmail_authorized {
            "connected"
        } else {
            "attention"
        },
        last_synced_at: None,
        status_message: if gmail_authorized {
            None
        } else {
            Some("Connect this imported account to sync new mail.".into())
        },
    })
}

fn folder_view(record: FolderRecord) -> MailboxFolder {
    MailboxFolder {
        id: record.id,
        label: bounded_output(&record.name, 512),
        count: Some(record.total_count),
        unread_count: Some(record.unread_count),
    }
}

fn message_summary(record: MessageRecord) -> MessageSummaryView {
    let has_attachments = record.flags.split(',').any(|flag| flag == "attachment");
    MessageSummaryView {
        thread_id: record
            .thread_id
            .clone()
            .unwrap_or_else(|| record.id.clone()),
        folder_id: record.folder_id.clone().unwrap_or_else(|| "unfiled".into()),
        sender: MailAddressView {
            name: None,
            address: bounded_output(&record.sender, 320),
        },
        subject: bounded_output(&record.subject, 998),
        snippet: bounded_output(&record.snippet, 2_000),
        received_at: timestamp(record.received_at),
        unread: record.flags.split(',').any(|flag| flag == "unread"),
        starred: record.flags.split(',').any(|flag| flag == "starred"),
        has_attachments,
        id: record.id,
        account_id: record.account_id,
    }
}

fn stored_message_view(
    storage: &Storage,
    message: MessageRecord,
) -> Result<SanitizedMessage, CommandError> {
    let attachments: Vec<SafeAttachment> = storage
        .list_attachments(&message.id)?
        .into_iter()
        .map(|item| SafeAttachment {
            id: item.id,
            filename: safe_filename(&item.filename),
            media_type: bounded_output(&item.media_type, 255),
            size_bytes: item.size_bytes,
        })
        .collect();
    let remote_content_blocked = message.body.html.is_some();
    let recipients = parse_addresses(&message.recipients);
    let body_text = sanitize_body_text(message.body.text.as_deref().unwrap_or_default());
    let mut summary = message_summary(message);
    summary.has_attachments |= !attachments.is_empty();
    Ok(SanitizedMessage {
        summary,
        recipients,
        cc: Vec::new(),
        body_text,
        remote_content_blocked,
        attachments,
    })
}

fn provider_message_view(account_id: String, message: ProviderMessage) -> SanitizedMessage {
    let summary = message.summary;
    let sender = summary
        .from
        .map(|address| MailAddressView {
            name: address.display_name.map(|name| bounded_output(&name, 256)),
            address: bounded_output(&address.address, 320),
        })
        .unwrap_or_else(|| MailAddressView {
            name: None,
            address: String::new(),
        });
    let recipients = summary.to.into_iter().map(mail_address_view).collect();
    let cc = message.cc.into_iter().map(mail_address_view).collect();
    let attachments = message
        .attachments
        .into_iter()
        .map(|attachment| SafeAttachment {
            id: attachment.id.into_inner(),
            filename: safe_filename(&attachment.filename),
            media_type: bounded_output(&attachment.media_type, 255),
            size_bytes: attachment.size_bytes,
        })
        .collect();
    SanitizedMessage {
        summary: MessageSummaryView {
            thread_id: summary
                .thread_id
                .unwrap_or_else(|| summary.id.as_str().to_owned()),
            folder_id: summary
                .folder_ids
                .first()
                .map(|id| id.as_str().to_owned())
                .unwrap_or_else(|| "unfiled".into()),
            sender,
            subject: bounded_output(&summary.subject, 998),
            snippet: bounded_output(&summary.preview, 2_000),
            received_at: timestamp(summary.received_at_ms),
            unread: summary.unread,
            starred: false,
            has_attachments: summary.has_attachments,
            id: summary.id.into_inner(),
            account_id,
        },
        recipients,
        cc,
        body_text: sanitize_body_text(message.text_body.as_deref().unwrap_or_default()),
        remote_content_blocked: message.html_body.is_some(),
        attachments,
    }
}

fn mail_address_view(address: crate::domain::mail::EmailAddress) -> MailAddressView {
    MailAddressView {
        name: address.display_name.map(|name| bounded_output(&name, 256)),
        address: bounded_output(&address.address, 320),
    }
}

fn plan_view(plan: &ActionPlan) -> AgentPlanView {
    let risk = if plan.requires_confirmation {
        "high"
    } else if plan.is_bulk {
        "medium"
    } else {
        "low"
    };
    AgentPlanView {
        id: plan.plan_id.clone(),
        action: format!("{:?}", plan.action).to_lowercase(),
        summary: plan.preview.summary.clone(),
        rationale: plan.reason.clone(),
        risk,
        status: plan_status(plan.state),
        steps: plan
            .preview
            .changes
            .iter()
            .map(|change| PlanStep {
                label: "Affected item".into(),
                detail: change.description.clone(),
            })
            .collect(),
        preview: vec![PlanPreviewField {
            label: "Affected items".into(),
            value: plan.preview.affected_count.to_string(),
        }],
        required_confirmation: required_confirmation(plan).into(),
        created_at: timestamp(plan.created_at_ms as i64),
        expires_at: timestamp(plan.expires_at_ms as i64),
    }
}

fn plan_status(state: PlanState) -> &'static str {
    match state {
        PlanState::PendingApproval => "pending",
        PlanState::Approved => "approved",
        PlanState::Rejected => "rejected",
        PlanState::Executed => "executed",
    }
}

fn stored_plan_status(state: PlanState) -> &'static str {
    match state {
        PlanState::PendingApproval => "proposed",
        PlanState::Approved => "approved",
        PlanState::Rejected => "rejected",
        PlanState::Executed => "completed",
    }
}

fn required_confirmation(plan: &ActionPlan) -> &'static str {
    if !plan.requires_confirmation {
        ""
    } else {
        match plan.action {
            PlanAction::Disconnect => DISCONNECT_CONFIRMATION,
            PlanAction::Send => "SEND",
            PlanAction::Trash | PlanAction::Delete => "DELETE",
            _ => "CONFIRM",
        }
    }
}

fn persist_plan(storage: &Storage, payload: &StoredPlanPayload) -> Result<(), CommandError> {
    let plan = &payload.plan;
    storage.upsert_plan(&PlanRecord {
        id: plan.plan_id.clone(),
        account_id: Some(plan.account_id.clone()),
        action: format!("{:?}", plan.action).to_lowercase(),
        risk: if plan.requires_confirmation {
            "high".into()
        } else {
            "low".into()
        },
        status: stored_plan_status(plan.state).into(),
        payload: serde_json::to_value(payload).map_err(|_| CommandError::unavailable())?,
        created_at: plan.created_at_ms as i64,
        expires_at: Some(plan.expires_at_ms as i64),
        confirmed_at: plan.approved_at_ms.map(|value| value as i64),
    })?;
    Ok(())
}

fn load_plan(storage: &Storage, id: &str) -> Result<StoredPlanPayload, CommandError> {
    let record = storage.get_plan(id)?.ok_or_else(CommandError::not_found)?;
    serde_json::from_value(record.payload).map_err(|_| CommandError::unavailable())
}

fn persist_recovery(storage: &Storage, record: &AuthorizedRecovery) -> Result<(), CommandError> {
    storage.upsert_recovery(&StoredRecovery {
        id: record.recovery_id.clone(),
        account_id: Some(record.account_id.clone()),
        kind: format!("{:?}", record.operation).to_lowercase(),
        state: serde_json::to_value(record).map_err(|_| CommandError::unavailable())?,
        created_at: record.created_at_ms as i64,
        updated_at: record.undone_at_ms.unwrap_or(record.created_at_ms) as i64,
    })?;
    Ok(())
}

fn append_audit(
    storage: &Storage,
    plan_id: Option<&str>,
    account_id: Option<&str>,
    event: &str,
    outcome: &str,
    summary: &str,
    now: u64,
) -> Result<(), CommandError> {
    let seed = format!(
        "{event}:{now}:{}:{}:{}",
        plan_id.unwrap_or("system"),
        account_id.unwrap_or("global"),
        AUDIT_NONCE.fetch_add(1, Ordering::Relaxed)
    );
    let id = format!("audit:{}", crate::agent::sha256_hex(seed.as_bytes()));
    storage.append_audit(&AuditRecord {
        id,
        plan_id: plan_id.map(str::to_owned),
        account_id: account_id.map(str::to_owned),
        event: event.into(),
        details: json!({ "actor": "user", "outcome": outcome, "summary": summary }),
        occurred_at: now as i64,
    })?;
    Ok(())
}

fn audit_view(record: &AuditRecord) -> AuditEventView {
    let text = |key: &str, fallback: &str| {
        record
            .details
            .get(key)
            .and_then(Value::as_str)
            .map(|value| bounded_output(value, 512))
            .unwrap_or_else(|| fallback.into())
    };
    let actor = match text("actor", "system").as_str() {
        "user" => "user",
        "agent" => "agent",
        _ => "system",
    }
    .to_owned();
    let outcome = match text("outcome", "failed").as_str() {
        "allowed" => "allowed",
        "denied" => "denied",
        _ => "failed",
    }
    .to_owned();
    AuditEventView {
        id: record.id.clone(),
        occurred_at: timestamp(record.occurred_at),
        actor,
        action: bounded_output(&record.event, 128),
        outcome,
        summary: text("summary", "A trusted-core event occurred."),
        resource_label: None,
        plan_id: record.plan_id.clone(),
    }
}

fn current_versions(
    storage: &Storage,
    plan: &ActionPlan,
) -> Result<Vec<ResourceVersion>, CommandError> {
    plan.affected
        .iter()
        .map(|expected| {
            let account = storage
                .get_account(&expected.resource_id)?
                .ok_or_else(CommandError::not_found)?;
            Ok(ResourceVersion {
                resource_id: expected.resource_id.clone(),
                version: account.updated_at.to_string(),
            })
        })
        .collect()
}

fn current_recovery_versions(
    storage: &Storage,
    recovery: &AuthorizedRecovery,
) -> Result<Vec<ResourceVersion>, CommandError> {
    recovery
        .items
        .iter()
        .map(|item| {
            let message = storage
                .get_message(&item.resource_id)?
                .ok_or_else(CommandError::not_found)?;
            Ok(ResourceVersion {
                resource_id: item.resource_id.clone(),
                version: message.updated_at.to_string(),
            })
        })
        .collect()
}

fn provider_kind(value: &str) -> Result<ProviderKind, CommandError> {
    match value.to_ascii_lowercase().as_str() {
        "gmail" => Ok(ProviderKind::Gmail),
        "imap" => Ok(ProviderKind::Imap),
        "yahoo" => Ok(ProviderKind::Yahoo),
        "icloud" => Ok(ProviderKind::Icloud),
        _ => Err(CommandError::new(
            "provider_unavailable",
            "This provider is unavailable.",
        )),
    }
}

fn validate_id(value: &str) -> Result<(), CommandError> {
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
        })
    {
        Err(CommandError::invalid())
    } else {
        Ok(())
    }
}

fn validate_limit(value: u32) -> Result<(), CommandError> {
    if value == 0 || value > MAX_PAGE_SIZE {
        Err(CommandError::invalid())
    } else {
        Ok(())
    }
}

fn validate_search(value: &str) -> Result<(), CommandError> {
    if value.trim().is_empty()
        || value.len() > MAX_SEARCH_BYTES
        || value.chars().any(char::is_control)
    {
        Err(CommandError::invalid())
    } else {
        Ok(())
    }
}

fn validate_confirmation(value: &str) -> Result<(), CommandError> {
    if value.is_empty()
        || value.len() > MAX_CONFIRMATION_BYTES
        || value.chars().any(char::is_control)
    {
        Err(CommandError::invalid())
    } else {
        Ok(())
    }
}

fn parse_addresses(value: &str) -> Vec<MailAddressView> {
    value
        .split(',')
        .map(str::trim)
        .filter(|address| !address.is_empty() && address.len() <= 320 && address.contains('@'))
        .take(500)
        .map(|address| MailAddressView {
            name: None,
            address: address.to_owned(),
        })
        .collect()
}

fn safe_filename(value: &str) -> String {
    let leaf = value
        .rsplit(|character| character == '/' || character == '\\')
        .next()
        .unwrap_or("attachment");
    let leaf = bounded_output(leaf, 255);
    if leaf.is_empty() || leaf == "." || leaf == ".." {
        "attachment".into()
    } else {
        leaf
    }
}

fn bounded_output(value: &str, max: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(max)
        .collect()
}

fn sanitize_body_text(value: &str) -> String {
    value
        .split_whitespace()
        .map(|token| {
            let lower = token.to_ascii_lowercase();
            if lower.starts_with("http://")
                || lower.starts_with("https://")
                || lower.starts_with("file://")
            {
                "[remote link blocked]"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn now_ms() -> Result<u64, CommandError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .map_err(|_| CommandError::unavailable())
}

fn timestamp(milliseconds: i64) -> String {
    let seconds = milliseconds.div_euclid(1_000);
    let millis = milliseconds.rem_euclid(1_000);
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += if month <= 2 { 1 } else { 0 };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        day_seconds / 3_600,
        (day_seconds % 3_600) / 60,
        day_seconds % 60
    )
}
