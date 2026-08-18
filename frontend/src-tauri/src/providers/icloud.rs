use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    domain::mail::{
        ConnectRequest, ConnectedAccount, DeleteDraftRequest, DisconnectRequest, DraftRequest,
        DraftResult, Folder, ListFoldersRequest, Message, MoveRequest, MutationRequest,
        MutationResult, ProviderKind, RetrieveRequest, SearchRequest, SearchResults, SendRequest,
        SendResult, SyncBatch, SyncRequest,
    },
    providers::{
        imap::{GenericImapProvider, SmtpSecurity, TrustedImapConfig},
        MailProvider, ProviderResult,
    },
    vault::CredentialVault,
};

const ICLOUD_CONFIG: TrustedImapConfig = TrustedImapConfig {
    kind: ProviderKind::Icloud,
    imap_host: "imap.mail.me.com",
    imap_port: 993,
    smtp_host: "smtp.mail.me.com",
    smtp_port: 587,
    smtp_security: SmtpSecurity::StartTls,
    sent_folders: &["Sent Messages", "Sent"],
    draft_folders: &["Drafts"],
    archive_folders: &["Archive"],
    trash_folders: &["Deleted Messages", "Trash"],
    spam_folders: &["Junk", "Spam"],
};

/// iCloud Mail adapter using Apple's fixed implicit-TLS IMAP and required-STARTTLS SMTP endpoints.
/// The credential reference resolves to an app-specific password only inside the trusted core.
#[derive(Debug, Clone)]
pub struct ICloudProvider {
    inner: GenericImapProvider,
}

impl ICloudProvider {
    pub fn new(vault: Arc<CredentialVault>) -> Self {
        Self {
            inner: GenericImapProvider::with_trusted_config(vault, ICLOUD_CONFIG),
        }
    }
}

#[async_trait]
impl MailProvider for ICloudProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Icloud
    }

    async fn connect(&self, request: ConnectRequest) -> ProviderResult<ConnectedAccount> {
        self.inner.connect(request).await
    }
    async fn list_folders(&self, request: ListFoldersRequest) -> ProviderResult<Vec<Folder>> {
        self.inner.list_folders(request).await
    }
    async fn incremental_sync(&self, request: SyncRequest) -> ProviderResult<SyncBatch> {
        self.inner.incremental_sync(request).await
    }
    async fn retrieve(&self, request: RetrieveRequest) -> ProviderResult<Message> {
        self.inner.retrieve(request).await
    }
    async fn search(&self, request: SearchRequest) -> ProviderResult<SearchResults> {
        self.inner.search(request).await
    }
    async fn draft(&self, request: DraftRequest) -> ProviderResult<DraftResult> {
        self.inner.draft(request).await
    }
    async fn delete_draft(&self, request: DeleteDraftRequest) -> ProviderResult<()> {
        self.inner.delete_draft(request).await
    }
    async fn send(&self, request: SendRequest) -> ProviderResult<SendResult> {
        self.inner.send(request).await
    }
    async fn move_messages(&self, request: MoveRequest) -> ProviderResult<MutationResult> {
        self.inner.move_messages(request).await
    }
    async fn archive(&self, request: MutationRequest) -> ProviderResult<MutationResult> {
        self.inner.archive(request).await
    }
    async fn trash(&self, request: MutationRequest) -> ProviderResult<MutationResult> {
        self.inner.trash(request).await
    }
    async fn disconnect(&self, request: DisconnectRequest) -> ProviderResult<()> {
        self.inner.disconnect(request).await
    }
}
