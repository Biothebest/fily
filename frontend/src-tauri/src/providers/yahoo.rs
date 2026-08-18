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

const YAHOO_CONFIG: TrustedImapConfig = TrustedImapConfig {
    kind: ProviderKind::Yahoo,
    imap_host: "imap.mail.yahoo.com",
    imap_port: 993,
    smtp_host: "smtp.mail.yahoo.com",
    smtp_port: 465,
    smtp_security: SmtpSecurity::ImplicitTls,
    sent_folders: &["Sent"],
    draft_folders: &["Draft"],
    archive_folders: &["Archive"],
    trash_folders: &["Trash"],
    spam_folders: &["Bulk Mail", "Spam"],
};

/// Yahoo Mail adapter using Yahoo's fixed TLS endpoints and app-password credentials from the OS
/// vault. Presentation input cannot override either endpoint.
#[derive(Debug, Clone)]
pub struct YahooProvider {
    inner: GenericImapProvider,
}

impl YahooProvider {
    pub fn new(vault: Arc<CredentialVault>) -> Self {
        Self {
            inner: GenericImapProvider::with_trusted_config(vault, YAHOO_CONFIG),
        }
    }
}

#[async_trait]
impl MailProvider for YahooProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Yahoo
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
