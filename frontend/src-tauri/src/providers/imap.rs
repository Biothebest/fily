use std::{
    collections::{BTreeMap, HashMap},
    net::{TcpStream, ToSocketAddrs},
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use imap::{types::Flag, Session};
use lettre::{
    address::Envelope,
    message::{Mailbox, MultiPart, SinglePart},
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters, TlsVersion},
    },
    Message as SmtpMessage, SmtpTransport, Transport,
};
use mailparse::{MailAddr, MailHeaderMap, ParsedMail};
use native_tls::{Protocol, TlsConnector, TlsStream};
use zeroize::Zeroizing;

use crate::{
    domain::mail::{
        AccountId, Attachment, AttachmentId, ConnectRequest, ConnectedAccount, DisconnectRequest,
        DraftId, DraftRequest, DraftResult, EmailAddress, Folder, FolderId, FolderRole,
        ListFoldersRequest, Message, MessageId, MessageSummary, MoveRequest, MutationRequest,
        MutationResult, ProviderEndpoint, ProviderKind, RetrieveRequest, SearchRequest,
        SearchResults, SendRequest, SendResult, SyncBatch, SyncChange, SyncRequest, Validate,
    },
    providers::{MailProvider, ProviderError, ProviderResult},
    vault::CredentialVault,
};

const MAX_MESSAGE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_PREVIEW_BYTES: usize = 4 * 1024;
const MAX_MAILBOXES: usize = 256;
const IMAP_PASSWORD_KIND: &str = "imap-password";
const SMTP_PASSWORD_KIND: &str = "smtp-password";

type ImapSession = Session<TlsStream<TcpStream>>;

#[derive(Debug, Clone, Copy)]
pub(crate) enum SmtpSecurity {
    ImplicitTls,
    StartTls,
}

#[derive(Debug, Clone)]
pub(crate) struct TrustedImapConfig {
    pub kind: ProviderKind,
    pub imap_host: &'static str,
    pub imap_port: u16,
    pub smtp_host: &'static str,
    pub smtp_port: u16,
    pub smtp_security: SmtpSecurity,
    pub sent_folders: &'static [&'static str],
    pub draft_folders: &'static [&'static str],
    pub archive_folders: &'static [&'static str],
    pub trash_folders: &'static [&'static str],
    pub spam_folders: &'static [&'static str],
}

#[derive(Debug, Clone)]
struct AccountConfig {
    credential_id: String,
    identity: EmailAddress,
    username: String,
    imap_host: String,
    imap_port: u16,
    smtp_host: String,
    smtp_port: u16,
    smtp_security: SmtpSecurity,
}

#[derive(Debug)]
struct ProviderInner {
    vault: Arc<CredentialVault>,
    trusted: Option<TrustedImapConfig>,
    accounts: RwLock<HashMap<String, AccountConfig>>,
}

/// TLS-only IMAP/SMTP implementation. Account state contains only public connection metadata and
/// an opaque vault record reference; password bytes are loaded just-in-time from the OS vault.
#[derive(Debug, Clone)]
pub struct GenericImapProvider {
    inner: Arc<ProviderInner>,
}

pub type ImapSmtpProvider = GenericImapProvider;
impl GenericImapProvider {
    pub fn new(vault: Arc<CredentialVault>) -> Self {
        Self {
            inner: Arc::new(ProviderInner {
                vault,
                trusted: None,
                accounts: RwLock::new(HashMap::new()),
            }),
        }
    }

    pub(crate) fn with_trusted_config(
        vault: Arc<CredentialVault>,
        trusted: TrustedImapConfig,
    ) -> Self {
        Self {
            inner: Arc::new(ProviderInner {
                vault,
                trusted: Some(trusted),
                accounts: RwLock::new(HashMap::new()),
            }),
        }
    }

    fn provider_kind(&self) -> ProviderKind {
        self.inner
            .trusted
            .as_ref()
            .map(|config| config.kind)
            .unwrap_or(ProviderKind::Imap)
    }

    fn account(&self, account_id: &AccountId) -> ProviderResult<AccountConfig> {
        self.inner
            .accounts
            .read()
            .map_err(|_| ProviderError::Conflict)?
            .get(account_id.as_str())
            .cloned()
            .ok_or(ProviderError::NotConfigured)
    }

    fn password(&self, account: &AccountConfig, kind: &str) -> ProviderResult<Zeroizing<String>> {
        let bytes = self
            .inner
            .vault
            .get_secret(&account.credential_id, kind)
            .map_err(|_| ProviderError::Authentication)?
            .ok_or(ProviderError::Authentication)?;
        let password =
            String::from_utf8(bytes.to_vec()).map_err(|_| ProviderError::Authentication)?;
        Ok(Zeroizing::new(password))
    }

    fn smtp_password(&self, account: &AccountConfig) -> ProviderResult<Zeroizing<String>> {
        match self
            .inner
            .vault
            .get_secret(&account.credential_id, SMTP_PASSWORD_KIND)
        {
            Ok(Some(bytes)) => String::from_utf8(bytes.to_vec())
                .map(Zeroizing::new)
                .map_err(|_| ProviderError::Authentication),
            Ok(None) => self.password(account, IMAP_PASSWORD_KIND),
            Err(_) => Err(ProviderError::Authentication),
        }
    }

    fn open_session(&self, account: &AccountConfig) -> ProviderResult<ImapSession> {
        let password = self.password(account, IMAP_PASSWORD_KIND)?;
        let tls = TlsConnector::builder()
            .min_protocol_version(Some(Protocol::Tlsv12))
            .build()
            .map_err(|_| ProviderError::Network)?;
        let socket = (account.imap_host.as_str(), account.imap_port)
            .to_socket_addrs()
            .map_err(|_| ProviderError::Network)?
            .take(8)
            .find_map(|address| TcpStream::connect_timeout(&address, Duration::from_secs(15)).ok())
            .ok_or(ProviderError::Network)?;
        socket
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|_| ProviderError::Network)?;
        socket
            .set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|_| ProviderError::Network)?;
        let stream = tls
            .connect(account.imap_host.as_str(), socket)
            .map_err(|_| ProviderError::Network)?;
        let mut client = imap::Client::new(stream);
        client.read_greeting().map_err(|_| ProviderError::Network)?;
        client
            .login(&account.username, password.as_str())
            .map_err(|_| ProviderError::Authentication)
    }

    fn list_folders_blocking(&self, account: &AccountConfig) -> ProviderResult<Vec<Folder>> {
        let mut session = self.open_session(account)?;
        let names = session
            .list(None, Some("*"))
            .map_err(|_| ProviderError::Network)?;
        let mut folders = Vec::with_capacity(names.len().min(MAX_MAILBOXES));
        for name in names.iter().take(MAX_MAILBOXES) {
            let mailbox = name.name().to_owned();
            let attributes = format!("{:?}", name.attributes());
            if attributes.to_ascii_lowercase().contains("noselect") {
                continue;
            }
            folders.push(Folder {
                id: folder_id(&mailbox)?,
                name: mailbox.clone(),
                role: self.folder_role(&mailbox, &attributes),
                unread_count: None,
                total_count: None,
            });
        }
        let _ = session.logout();
        Ok(folders)
    }

    fn folder_role(&self, mailbox: &str, attributes: &str) -> FolderRole {
        let lower = mailbox.to_ascii_lowercase();
        let attrs = attributes.to_ascii_lowercase();
        if lower == "inbox" || attrs.contains("inbox") {
            return FolderRole::Inbox;
        }
        let trusted = self.inner.trusted.as_ref();
        let matches = |candidates: &[&str]| {
            candidates
                .iter()
                .any(|candidate| mailbox.eq_ignore_ascii_case(candidate))
        };
        if attrs.contains("sent")
            || lower == "sent"
            || lower == "sent messages"
            || trusted.is_some_and(|c| matches(c.sent_folders))
        {
            FolderRole::Sent
        } else if attrs.contains("draft")
            || lower == "draft"
            || lower == "drafts"
            || trusted.is_some_and(|c| matches(c.draft_folders))
        {
            FolderRole::Drafts
        } else if attrs.contains("archive")
            || lower == "archive"
            || trusted.is_some_and(|c| matches(c.archive_folders))
        {
            FolderRole::Archive
        } else if attrs.contains("trash")
            || attrs.contains("deleted")
            || lower == "trash"
            || lower == "deleted messages"
            || trusted.is_some_and(|c| matches(c.trash_folders))
        {
            FolderRole::Trash
        } else if attrs.contains("junk")
            || attrs.contains("spam")
            || lower == "junk"
            || lower == "spam"
            || trusted.is_some_and(|c| matches(c.spam_folders))
        {
            FolderRole::Spam
        } else {
            FolderRole::Other
        }
    }

    fn resolve_role_folder(
        &self,
        account: &AccountConfig,
        role: FolderRole,
    ) -> ProviderResult<String> {
        self.list_folders_blocking(account)?
            .into_iter()
            .find(|folder| folder.role == role)
            .map(|folder| folder.name)
            .ok_or(ProviderError::NotFound)
    }

    fn sync_blocking(
        &self,
        account: &AccountConfig,
        request: SyncRequest,
    ) -> ProviderResult<SyncBatch> {
        let folders = if request.folder_ids.is_empty() {
            self.list_folders_blocking(account)?
                .into_iter()
                .map(|folder| folder.id)
                .collect()
        } else {
            request.folder_ids
        };
        let mut cursor = decode_cursor(request.cursor.as_deref())?;
        let mut changes = Vec::new();
        let mut has_more = false;

        for folder_id_value in folders {
            if changes.len() >= usize::from(request.limit) {
                has_more = true;
                break;
            }
            let mailbox = decode_folder_id(&folder_id_value)?;
            let mut session = self.open_session(account)?;
            let selected = session
                .select(&mailbox)
                .map_err(|_| ProviderError::NotFound)?;
            let uid_validity = selected.uid_validity.unwrap_or(0);
            let previous = cursor.get(&mailbox).copied().unwrap_or((uid_validity, 0));
            let last_uid = if previous.0 == uid_validity {
                previous.1
            } else {
                0
            };
            let mut uids: Vec<u32> = session
                .uid_search(format!("UID {}:*", last_uid.saturating_add(1)))
                .map_err(|_| ProviderError::Network)?
                .into_iter()
                .filter(|uid| *uid > last_uid)
                .collect();
            uids.sort_unstable();
            let available = usize::from(request.limit).saturating_sub(changes.len());
            if uids.len() > available {
                has_more = true;
                uids.truncate(available);
            }
            let mut processed_uid = last_uid;
            for uid in uids {
                let summary = fetch_summary(&mut session, &mailbox, uid)?;
                processed_uid = uid;
                changes.push(SyncChange::Upsert(summary));
            }
            cursor.insert(mailbox, (uid_validity, processed_uid));
            let _ = session.logout();
        }

        let next_cursor = encode_cursor(&cursor);
        if next_cursor.len() > crate::domain::mail::MAX_CURSOR_BYTES {
            return Err(ProviderError::Unsupported);
        }
        Ok(SyncBatch {
            changes,
            next_cursor: Some(next_cursor),
            has_more,
        })
    }

    fn retrieve_blocking(
        &self,
        account: &AccountConfig,
        request: RetrieveRequest,
    ) -> ProviderResult<Message> {
        let (mailbox, uid) = decode_message_id(&request.message_id)?;
        let mut session = self.open_session(account)?;
        session
            .select(&mailbox)
            .map_err(|_| ProviderError::NotFound)?;
        let size_fetch = session
            .uid_fetch(uid.to_string(), "(UID RFC822.SIZE FLAGS)")
            .map_err(|_| ProviderError::Network)?;
        let size = size_fetch
            .iter()
            .next()
            .and_then(|fetch| fetch.size)
            .ok_or(ProviderError::NotFound)? as u64;
        if size > MAX_MESSAGE_BYTES {
            return Err(ProviderError::Unsupported);
        }
        drop(size_fetch);
        let query = format!("(UID FLAGS BODY.PEEK[]<0.{}>)", MAX_MESSAGE_BYTES + 1);
        let fetches = session
            .uid_fetch(uid.to_string(), query)
            .map_err(|_| ProviderError::Network)?;
        let fetch = fetches.iter().next().ok_or(ProviderError::NotFound)?;
        let body = fetch.body().ok_or(ProviderError::ProviderFailure)?;
        if body.len() as u64 > MAX_MESSAGE_BYTES {
            return Err(ProviderError::Unsupported);
        }
        let message = parse_message(
            &mailbox,
            uid,
            body,
            request.include_body,
            request.max_attachment_bytes,
            fetch
                .flags()
                .iter()
                .any(|flag| format!("{flag:?}") == "Seen"),
        )?;
        let _ = session.logout();
        Ok(message)
    }

    fn search_blocking(
        &self,
        account: &AccountConfig,
        request: SearchRequest,
    ) -> ProviderResult<SearchResults> {
        let folders = if request.folder_ids.is_empty() {
            self.list_folders_blocking(account)?
                .into_iter()
                .map(|folder| folder.id)
                .collect()
        } else {
            request.folder_ids
        };
        let offset = request
            .cursor
            .as_deref()
            .map(parse_offset_cursor)
            .transpose()?
            .unwrap_or(0);
        let limit = usize::from(request.limit);
        let mut skipped = 0_usize;
        let mut messages = Vec::with_capacity(limit);
        let mut has_more = false;
        'folders: for folder in folders {
            let mailbox = decode_folder_id(&folder)?;
            let mut session = self.open_session(account)?;
            session
                .select(&mailbox)
                .map_err(|_| ProviderError::NotFound)?;
            let query = format!("TEXT {}", quote_imap(&request.query));
            let mut uids: Vec<u32> = session
                .uid_search(query)
                .map_err(|_| ProviderError::Network)?
                .into_iter()
                .collect();
            uids.sort_unstable_by(|left, right| right.cmp(left));
            for uid in uids {
                if skipped < offset {
                    skipped += 1;
                } else if messages.len() < limit {
                    messages.push(fetch_summary(&mut session, &mailbox, uid)?);
                } else {
                    has_more = true;
                    let _ = session.logout();
                    break 'folders;
                }
            }
            let _ = session.logout();
        }
        Ok(SearchResults {
            next_cursor: has_more.then(|| format!("offset:{}", offset + messages.len())),
            messages,
        })
    }
    fn reply_headers(
        &self,
        account: &AccountConfig,
        message_id_value: &MessageId,
    ) -> ProviderResult<Option<(String, String)>> {
        let (mailbox, uid) = decode_message_id(message_id_value)?;
        let mut session = self.open_session(account)?;
        session
            .select(&mailbox)
            .map_err(|_| ProviderError::NotFound)?;
        let fetches = session
            .uid_fetch(
                uid.to_string(),
                format!("(UID BODY.PEEK[HEADER]<0.{MAX_HEADER_BYTES}>)"),
            )
            .map_err(|_| ProviderError::Network)?;
        let header = fetches
            .iter()
            .next()
            .and_then(|fetch| fetch.header())
            .ok_or(ProviderError::NotFound)?;
        let headers = mailparse::parse_headers(header)
            .map_err(|_| ProviderError::ProviderFailure)?
            .0;
        let Some(in_reply_to) = headers
            .get_first_value("Message-ID")
            .map(|value| safe_header_value(&value))
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        let references = headers
            .get_first_value("References")
            .map(|value| safe_header_value(&value))
            .filter(|value| !value.is_empty())
            .map(|value| format!("{value} {in_reply_to}"))
            .unwrap_or_else(|| in_reply_to.clone());
        let _ = session.logout();
        Ok(Some((
            in_reply_to,
            bounded_text(&references, MAX_HEADER_BYTES),
        )))
    }

    fn draft_blocking(
        &self,
        account: &AccountConfig,
        request: DraftRequest,
    ) -> ProviderResult<DraftResult> {
        if !request.attachment_ids.is_empty() {
            // Attachment IDs need the encrypted attachment store to resolve bytes. Accepting paths
            // or untrusted bytes here would violate the provider boundary.
            return Err(ProviderError::Unsupported);
        }
        let drafts = self.resolve_role_folder(account, FolderRole::Drafts)?;
        let existing = request.draft_id.as_ref().map(decode_draft_id).transpose()?;
        let reply_headers = request
            .in_reply_to
            .as_ref()
            .map(|message_id| self.reply_headers(account, message_id))
            .transpose()?
            .flatten();
        let rfc_message_id = new_rfc_message_id();
        let raw = build_draft(account, &request, &rfc_message_id, reply_headers.as_ref())?;
        if raw.len() as u64 > MAX_MESSAGE_BYTES {
            return Err(ProviderError::Unsupported);
        }
        let mut session = self.open_session(account)?;
        session
            .select(&drafts)
            .map_err(|_| ProviderError::NotFound)?;
        session
            .append_with_flags(&drafts, &raw, &[Flag::Draft])
            .map_err(|_| ProviderError::Network)?;
        let uids = session
            .uid_search(format!("HEADER Message-ID {}", quote_imap(&rfc_message_id)))
            .map_err(|_| ProviderError::Network)?;
        let uid = uids.into_iter().max().ok_or(ProviderError::Conflict)?;
        if let Some((existing_mailbox, existing_uid)) = existing {
            session
                .select(&existing_mailbox)
                .map_err(|_| ProviderError::NotFound)?;
            session
                .uid_store(existing_uid.to_string(), "+FLAGS.SILENT (\\Deleted)")
                .map_err(|_| ProviderError::Network)?;
            let _ = session.uid_expunge(existing_uid.to_string());
        }
        let _ = session.logout();
        Ok(DraftResult {
            draft_id: DraftId::new(encode_message_ref("draft", &drafts, uid))?,
            updated_at_ms: now_ms(),
        })
    }

    fn send_blocking(
        &self,
        account: &AccountConfig,
        request: SendRequest,
    ) -> ProviderResult<SendResult> {
        let (drafts, uid) = decode_draft_id(&request.draft_id)?;
        let mut session = self.open_session(account)?;
        session
            .select(&drafts)
            .map_err(|_| ProviderError::NotFound)?;
        let fetches = session
            .uid_fetch(
                uid.to_string(),
                format!("(UID RFC822.SIZE BODY.PEEK[]<0.{}>)", MAX_MESSAGE_BYTES + 1),
            )
            .map_err(|_| ProviderError::Network)?;
        let fetch = fetches.iter().next().ok_or(ProviderError::NotFound)?;
        if fetch.size.unwrap_or(u32::MAX) as u64 > MAX_MESSAGE_BYTES {
            return Err(ProviderError::Unsupported);
        }
        let raw = fetch.body().ok_or(ProviderError::NotFound)?.to_vec();
        drop(fetches);
        let parsed = mailparse::parse_mail(&raw).map_err(|_| ProviderError::ProviderFailure)?;
        let envelope = envelope_from_mail(&parsed)?;
        let outbound = strip_bcc_headers(&raw)?;
        let password = self.smtp_password(account)?;
        let credentials = Credentials::new(account.username.clone(), password.as_str().to_owned());
        let tls_parameters = TlsParameters::builder(account.smtp_host.clone())
            .set_min_tls_version(TlsVersion::Tlsv12)
            .build_native()
            .map_err(|_| ProviderError::Network)?;
        let tls = match account.smtp_security {
            SmtpSecurity::ImplicitTls => Tls::Wrapper(tls_parameters),
            SmtpSecurity::StartTls => Tls::Required(tls_parameters),
        };
        let transport = SmtpTransport::builder_dangerous(account.smtp_host.clone())
            .port(account.smtp_port)
            .tls(tls)
            .timeout(Some(Duration::from_secs(30)))
            .credentials(credentials)
            .build();
        transport
            .send_raw(&envelope, &outbound)
            .map_err(|_| ProviderError::Network)?;

        let sent = self.resolve_role_folder(account, FolderRole::Sent)?;
        session
            .append_with_flags(&sent, &outbound, &[Flag::Seen])
            .map_err(|_| ProviderError::Network)?;
        session
            .uid_store(uid.to_string(), "+FLAGS.SILENT (\\Deleted)")
            .map_err(|_| ProviderError::Network)?;
        let _ = session.uid_expunge(uid.to_string());
        let message_header = parsed.headers.get_first_value("Message-ID");
        drop(parsed);
        session.select(&sent).map_err(|_| ProviderError::NotFound)?;
        let sent_uid = if let Some(header) = message_header {
            session
                .uid_search(format!("HEADER Message-ID {}", quote_imap(&header)))
                .map_err(|_| ProviderError::Network)?
                .into_iter()
                .max()
                .ok_or(ProviderError::Conflict)?
        } else {
            return Err(ProviderError::Conflict);
        };
        let _ = session.logout();
        Ok(SendResult {
            message_id: message_id(&sent, sent_uid)?,
            sent_at_ms: now_ms(),
        })
    }

    fn move_blocking(
        &self,
        account: &AccountConfig,
        message_ids: &[MessageId],
        destination: &str,
    ) -> ProviderResult<u16> {
        let mut grouped: BTreeMap<String, Vec<u32>> = BTreeMap::new();
        for id in message_ids {
            let (mailbox, uid) = decode_message_id(id)?;
            grouped.entry(mailbox).or_default().push(uid);
        }
        for (mailbox, uids) in grouped {
            if mailbox == destination
                || (mailbox.eq_ignore_ascii_case("INBOX")
                    && destination.eq_ignore_ascii_case("INBOX"))
            {
                continue;
            }
            let sequence = uids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let destination_wire = quote_imap(destination);
            let mut session = self.open_session(account)?;
            session
                .select(&mailbox)
                .map_err(|_| ProviderError::NotFound)?;
            let (supports_move, supports_uidplus) = {
                let capabilities = session.capabilities().map_err(|_| ProviderError::Network)?;
                (
                    capabilities.has_str("MOVE"),
                    capabilities.has_str("UIDPLUS"),
                )
            };
            if supports_move {
                session
                    .uid_mv(&sequence, &destination_wire)
                    .map_err(|_| ProviderError::Network)?;
            } else {
                if !supports_uidplus {
                    return Err(ProviderError::Unsupported);
                }
                session
                    .uid_copy(&sequence, &destination_wire)
                    .map_err(|_| ProviderError::Network)?;
                session
                    .uid_store(&sequence, "+FLAGS.SILENT (\\Deleted)")
                    .map_err(|_| ProviderError::Network)?;
                session
                    .uid_expunge(&sequence)
                    .map_err(|_| ProviderError::Network)?;
            }
            let _ = session.logout();
        }
        u16::try_from(message_ids.len()).map_err(|_| ProviderError::Conflict)
    }
}

#[async_trait]
impl MailProvider for GenericImapProvider {
    fn kind(&self) -> ProviderKind {
        self.provider_kind()
    }

    async fn connect(&self, request: ConnectRequest) -> ProviderResult<ConnectedAccount> {
        request.validate()?;
        if request.provider != self.kind() {
            return Err(ProviderError::InvalidInput);
        }
        let endpoint = request.endpoint.clone();
        let account = account_config(self.inner.trusted.as_ref(), &request, endpoint.as_ref())?;
        let adapter = self.clone();
        let probe = account.clone();
        tauri::async_runtime::spawn_blocking(move || {
            let mut session = adapter.open_session(&probe)?;
            session.noop().map_err(|_| ProviderError::Network)?;
            let _ = session.logout();
            Ok::<_, ProviderError>(())
        })
        .await
        .map_err(|_| ProviderError::Network)??;
        self.inner
            .accounts
            .write()
            .map_err(|_| ProviderError::Conflict)?
            .insert(request.account_id.as_str().to_owned(), account);
        Ok(ConnectedAccount {
            account_id: request.account_id,
            provider: request.provider,
            identity: request.identity,
        })
    }

    async fn list_folders(&self, request: ListFoldersRequest) -> ProviderResult<Vec<Folder>> {
        request.validate()?;
        let account = self.account(&request.account_id)?;
        let adapter = self.clone();
        run_blocking(move || adapter.list_folders_blocking(&account)).await
    }

    async fn incremental_sync(&self, request: SyncRequest) -> ProviderResult<SyncBatch> {
        request.validate()?;
        let account = self.account(&request.account_id)?;
        let adapter = self.clone();
        run_blocking(move || adapter.sync_blocking(&account, request)).await
    }

    async fn retrieve(&self, request: RetrieveRequest) -> ProviderResult<Message> {
        request.validate()?;
        let account = self.account(&request.account_id)?;
        let adapter = self.clone();
        run_blocking(move || adapter.retrieve_blocking(&account, request)).await
    }

    async fn search(&self, request: SearchRequest) -> ProviderResult<SearchResults> {
        request.validate()?;
        let account = self.account(&request.account_id)?;
        let adapter = self.clone();
        run_blocking(move || adapter.search_blocking(&account, request)).await
    }

    async fn draft(&self, request: DraftRequest) -> ProviderResult<DraftResult> {
        request.validate()?;
        let account = self.account(&request.account_id)?;
        let adapter = self.clone();
        run_blocking(move || adapter.draft_blocking(&account, request)).await
    }

    async fn send(&self, request: SendRequest) -> ProviderResult<SendResult> {
        request.validate()?;
        let account = self.account(&request.account_id)?;
        let adapter = self.clone();
        run_blocking(move || adapter.send_blocking(&account, request)).await
    }

    async fn move_messages(&self, request: MoveRequest) -> ProviderResult<MutationResult> {
        request.validate()?;
        let account = self.account(&request.account_id)?;
        let destination = decode_folder_id(&request.destination_folder_id)?;
        let operation_id = request.authorization_id.clone();
        let messages = request.message_ids;
        let adapter = self.clone();
        let affected =
            run_blocking(move || adapter.move_blocking(&account, &messages, &destination)).await?;
        Ok(MutationResult {
            operation_id,
            affected,
        })
    }

    async fn archive(&self, request: MutationRequest) -> ProviderResult<MutationResult> {
        request.validate()?;
        let account = self.account(&request.account_id)?;
        let destination = {
            let adapter = self.clone();
            let account = account.clone();
            run_blocking(move || adapter.resolve_role_folder(&account, FolderRole::Archive)).await?
        };
        let operation_id = request.authorization_id.clone();
        let messages = request.message_ids;
        let adapter = self.clone();
        let affected =
            run_blocking(move || adapter.move_blocking(&account, &messages, &destination)).await?;
        Ok(MutationResult {
            operation_id,
            affected,
        })
    }

    async fn trash(&self, request: MutationRequest) -> ProviderResult<MutationResult> {
        request.validate()?;
        let account = self.account(&request.account_id)?;
        let destination = {
            let adapter = self.clone();
            let account = account.clone();
            run_blocking(move || adapter.resolve_role_folder(&account, FolderRole::Trash)).await?
        };
        let operation_id = request.authorization_id.clone();
        let messages = request.message_ids;
        let adapter = self.clone();
        let affected =
            run_blocking(move || adapter.move_blocking(&account, &messages, &destination)).await?;
        Ok(MutationResult {
            operation_id,
            affected,
        })
    }

    async fn disconnect(&self, request: DisconnectRequest) -> ProviderResult<()> {
        request.validate()?;
        let account = self.account(&request.account_id)?;
        let vault = self.inner.vault.clone();
        let credential_id = account.credential_id;
        run_blocking(move || {
            vault
                .delete_secret(&credential_id, IMAP_PASSWORD_KIND)
                .map_err(|_| ProviderError::Authentication)?;
            vault
                .delete_secret(&credential_id, SMTP_PASSWORD_KIND)
                .map_err(|_| ProviderError::Authentication)
        })
        .await?;
        self.inner
            .accounts
            .write()
            .map_err(|_| ProviderError::Conflict)?
            .remove(request.account_id.as_str());
        Ok(())
    }
}

fn account_config(
    trusted: Option<&TrustedImapConfig>,
    request: &ConnectRequest,
    endpoint: Option<&ProviderEndpoint>,
) -> ProviderResult<AccountConfig> {
    let (imap_host, imap_port, smtp_host, smtp_port, smtp_security, username) = match trusted {
        Some(config) => (
            config.imap_host.to_owned(),
            config.imap_port,
            config.smtp_host.to_owned(),
            config.smtp_port,
            config.smtp_security,
            request.identity.address.clone(),
        ),
        None => {
            let endpoint = endpoint.ok_or(ProviderError::NotConfigured)?;
            (
                endpoint.imap_host.clone(),
                endpoint.imap_port,
                endpoint.smtp_host.clone(),
                endpoint.smtp_port,
                if endpoint.smtp_port == 465 {
                    SmtpSecurity::ImplicitTls
                } else {
                    SmtpSecurity::StartTls
                },
                endpoint.username.clone(),
            )
        }
    };
    Ok(AccountConfig {
        credential_id: request.credential_id.as_str().to_owned(),
        identity: request.identity.clone(),
        username,
        imap_host,
        imap_port,
        smtp_host,
        smtp_port,
        smtp_security,
    })
}

async fn run_blocking<T: Send + 'static>(
    operation: impl FnOnce() -> ProviderResult<T> + Send + 'static,
) -> ProviderResult<T> {
    tauri::async_runtime::spawn_blocking(operation)
        .await
        .map_err(|_| ProviderError::Network)?
}

fn fetch_summary(
    session: &mut ImapSession,
    mailbox: &str,
    uid: u32,
) -> ProviderResult<MessageSummary> {
    let query = format!("(UID FLAGS BODY.PEEK[HEADER]<0.{MAX_HEADER_BYTES}>)");
    let fetches = session
        .uid_fetch(uid.to_string(), query)
        .map_err(|_| ProviderError::Network)?;
    let fetch = fetches.iter().next().ok_or(ProviderError::NotFound)?;
    let header = fetch.header().ok_or(ProviderError::ProviderFailure)?;
    let seen = fetch
        .flags()
        .iter()
        .any(|flag| format!("{flag:?}") == "Seen");
    summary_from_header(mailbox, uid, header, seen)
}

fn summary_from_header(
    mailbox: &str,
    uid: u32,
    header: &[u8],
    seen: bool,
) -> ProviderResult<MessageSummary> {
    let parsed = mailparse::parse_headers(header).map_err(|_| ProviderError::ProviderFailure)?;
    let headers = parsed.0;
    let subject = headers.get_first_value("Subject").unwrap_or_default();
    let from = headers
        .get_first_value("From")
        .and_then(|value| parse_addresses(&value).ok())
        .and_then(|mut values| values.drain(..).next());
    let to = headers
        .get_first_value("To")
        .and_then(|value| parse_addresses(&value).ok())
        .unwrap_or_default();
    let received_at_ms = headers
        .get_first_value("Date")
        .and_then(|value| mailparse::dateparse(&value).ok())
        .unwrap_or(0)
        .saturating_mul(1000);
    let content_type = headers
        .get_first_value("Content-Type")
        .unwrap_or_default()
        .to_ascii_lowercase();
    Ok(MessageSummary {
        id: message_id(mailbox, uid)?,
        folder_ids: vec![folder_id(mailbox)?],
        thread_id: headers.get_first_value("References"),
        subject: bounded_text(&subject, 998),
        from,
        to,
        received_at_ms,
        unread: !seen,
        has_attachments: content_type.contains("name=") || content_type.contains("multipart/mixed"),
        preview: String::new(),
    })
}

fn parse_message(
    mailbox: &str,
    uid: u32,
    raw: &[u8],
    include_body: bool,
    max_attachment_bytes: u64,
    seen: bool,
) -> ProviderResult<Message> {
    let parsed = mailparse::parse_mail(raw).map_err(|_| ProviderError::ProviderFailure)?;
    let summary = summary_from_header(mailbox, uid, parsed.get_headers().get_raw_bytes(), seen)?;
    let cc = header_addresses(&parsed, "Cc")?;
    let bcc = header_addresses(&parsed, "Bcc")?;
    let reply_to = header_addresses(&parsed, "Reply-To")?.into_iter().next();
    let mut text_body = None;
    let mut html_body = None;
    let mut attachments = Vec::new();
    collect_parts(
        &parsed,
        &summary.id,
        include_body,
        max_attachment_bytes,
        &mut text_body,
        &mut html_body,
        &mut attachments,
    )?;
    let mut summary = summary;
    summary.has_attachments = !attachments.is_empty();
    if let Some(text) = text_body.as_deref() {
        summary.preview = bounded_text(text.trim(), MAX_PREVIEW_BYTES);
    }
    Ok(Message {
        summary,
        cc,
        bcc,
        reply_to,
        text_body,
        // Raw HTML is never allowed across the trusted-core boundary. A later sanitizer can opt in
        // without weakening the current invariant.
        html_body,
        attachments,
    })
}

fn collect_parts(
    part: &ParsedMail<'_>,
    message_id_value: &MessageId,
    include_body: bool,
    max_attachment_bytes: u64,
    text_body: &mut Option<String>,
    html_body: &mut Option<String>,
    attachments: &mut Vec<Attachment>,
) -> ProviderResult<()> {
    if !part.subparts.is_empty() {
        for child in &part.subparts {
            collect_parts(
                child,
                message_id_value,
                include_body,
                max_attachment_bytes,
                text_body,
                html_body,
                attachments,
            )?;
        }
        return Ok(());
    }
    let disposition = part.get_content_disposition();
    let filename = disposition
        .params
        .get("filename")
        .or_else(|| part.ctype.params.get("name"))
        .map(|value| safe_filename(value));
    let is_attachment = filename.is_some()
        || format!("{:?}", disposition.disposition)
            .to_ascii_lowercase()
            .contains("attachment");
    if is_attachment {
        if attachments.len() >= crate::domain::mail::MAX_ATTACHMENTS {
            return Err(ProviderError::Unsupported);
        }
        let bytes = part
            .get_body_raw()
            .map_err(|_| ProviderError::ProviderFailure)?;
        if bytes.len() as u64 > max_attachment_bytes || bytes.len() as u64 > MAX_MESSAGE_BYTES {
            return Err(ProviderError::Unsupported);
        }
        let index = attachments.len();
        attachments.push(Attachment {
            id: AttachmentId::new(format!("{}:part:{index}", message_id_value.as_str()))?,
            filename: filename.unwrap_or_else(|| format!("attachment-{index}")),
            media_type: bounded_text(&part.ctype.mimetype, 255),
            size_bytes: bytes.len() as u64,
        });
    } else if include_body
        && part.ctype.mimetype.eq_ignore_ascii_case("text/plain")
        && text_body.is_none()
    {
        let value = part
            .get_body()
            .map_err(|_| ProviderError::ProviderFailure)?;
        *text_body = Some(bounded_text(&value, crate::domain::mail::MAX_BODY_BYTES));
    } else if include_body
        && part.ctype.mimetype.eq_ignore_ascii_case("text/html")
        && html_body.is_none()
    {
        let value = part
            .get_body()
            .map_err(|_| ProviderError::ProviderFailure)?;
        if text_body.is_none() {
            *text_body = Some(bounded_text(
                &strip_html(&value),
                crate::domain::mail::MAX_BODY_BYTES,
            ));
        }
        *html_body = Some(bounded_text(
            &sanitize_html(&value),
            crate::domain::mail::MAX_BODY_BYTES,
        ));
    }
    Ok(())
}

fn build_draft(
    account: &AccountConfig,
    request: &DraftRequest,
    message_id_value: &str,
    reply_headers: Option<&(String, String)>,
) -> ProviderResult<Vec<u8>> {
    if request.to.is_empty() && request.cc.is_empty() && request.bcc.is_empty() {
        return Ok(build_incomplete_draft(
            account,
            request,
            message_id_value,
            reply_headers,
        ));
    }
    let mut builder = SmtpMessage::builder()
        .from(to_mailbox(&account.identity)?)
        .subject(request.subject.clone())
        .message_id(Some(message_id_value.to_owned()))
        .date_now()
        .keep_bcc();
    if let Some((in_reply_to, references)) = reply_headers {
        builder = builder
            .in_reply_to(in_reply_to.clone())
            .references(references.clone());
    }
    for recipient in &request.to {
        builder = builder.to(to_mailbox(recipient)?);
    }
    for recipient in &request.cc {
        builder = builder.cc(to_mailbox(recipient)?);
    }
    for recipient in &request.bcc {
        builder = builder.bcc(to_mailbox(recipient)?);
    }
    let message = match (&request.text_body, &request.html_body) {
        (Some(text), Some(html)) => builder
            .multipart(MultiPart::alternative_plain_html(
                text.clone(),
                html.clone(),
            ))
            .map_err(|_| ProviderError::InvalidInput)?,
        (Some(text), None) => builder
            .singlepart(SinglePart::plain(text.clone()))
            .map_err(|_| ProviderError::InvalidInput)?,
        (None, Some(html)) => builder
            .singlepart(SinglePart::html(html.clone()))
            .map_err(|_| ProviderError::InvalidInput)?,
        (None, None) => builder
            .singlepart(SinglePart::plain(String::new()))
            .map_err(|_| ProviderError::InvalidInput)?,
    };
    Ok(message.formatted())
}

fn build_incomplete_draft(
    account: &AccountConfig,
    request: &DraftRequest,
    message_id_value: &str,
    reply_headers: Option<&(String, String)>,
) -> Vec<u8> {
    let (media_type, body) = match (&request.text_body, &request.html_body) {
        (Some(text), _) => ("text/plain", text.as_str()),
        (None, Some(html)) => ("text/html", html.as_str()),
        (None, None) => ("text/plain", ""),
    };
    let reply_header_block = reply_headers
        .map(|(in_reply_to, references)| {
            format!("In-Reply-To: {in_reply_to}\r\nReferences: {references}\r\n")
        })
        .unwrap_or_default();
    format!(
        "From: {}\r\nSubject: {}\r\nMessage-ID: {}\r\n{}MIME-Version: 1.0\r\nContent-Type: {}; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}",
        account.identity.address,
        request.subject,
        message_id_value,
        reply_header_block,
        media_type,
        body.replace("\r\n", "\n").replace('\n', "\r\n")
    )
    .into_bytes()
}

fn envelope_from_mail(mail: &ParsedMail<'_>) -> ProviderResult<Envelope> {
    let from = header_addresses(mail, "From")?
        .into_iter()
        .next()
        .ok_or(ProviderError::ProviderFailure)?
        .address
        .parse()
        .map_err(|_| ProviderError::ProviderFailure)?;
    let mut recipients = Vec::new();
    for header in ["To", "Cc", "Bcc"] {
        for address in header_addresses(mail, header)? {
            recipients.push(
                address
                    .address
                    .parse()
                    .map_err(|_| ProviderError::ProviderFailure)?,
            );
        }
    }
    Envelope::new(Some(from), recipients).map_err(|_| ProviderError::ProviderFailure)
}

fn to_mailbox(address: &EmailAddress) -> ProviderResult<Mailbox> {
    let parsed = address
        .address
        .parse()
        .map_err(|_| ProviderError::InvalidInput)?;
    Ok(Mailbox::new(address.display_name.clone(), parsed))
}

fn header_addresses(mail: &ParsedMail<'_>, name: &str) -> ProviderResult<Vec<EmailAddress>> {
    mail.headers
        .get_first_value(name)
        .map(|value| parse_addresses(&value))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn parse_addresses(value: &str) -> ProviderResult<Vec<EmailAddress>> {
    let parsed = mailparse::addrparse(value).map_err(|_| ProviderError::ProviderFailure)?;
    let mut result = Vec::new();
    for address in parsed.iter() {
        match address {
            MailAddr::Single(single) => result.push(EmailAddress {
                address: bounded_text(&single.addr, 320),
                display_name: single
                    .display_name
                    .as_deref()
                    .map(|name| bounded_text(name, 256)),
            }),
            MailAddr::Group(group) => {
                result.extend(group.addrs.iter().map(|single| {
                    EmailAddress {
                        address: bounded_text(&single.addr, 320),
                        display_name: single
                            .display_name
                            .as_deref()
                            .map(|name| bounded_text(name, 256)),
                    }
                }));
            }
        }
    }
    Ok(result)
}

fn folder_id(mailbox: &str) -> ProviderResult<FolderId> {
    FolderId::new(format!("imap-folder:{}", hex_encode(mailbox.as_bytes()))).map_err(Into::into)
}

fn decode_folder_id(id: &FolderId) -> ProviderResult<String> {
    let encoded = id
        .as_str()
        .strip_prefix("imap-folder:")
        .ok_or(ProviderError::InvalidInput)?;
    decode_mailbox(encoded)
}

fn message_id(mailbox: &str, uid: u32) -> ProviderResult<MessageId> {
    MessageId::new(encode_message_ref("message", mailbox, uid)).map_err(Into::into)
}

fn encode_message_ref(kind: &str, mailbox: &str, uid: u32) -> String {
    format!("imap-{kind}:{}:{uid}", hex_encode(mailbox.as_bytes()))
}

fn decode_message_id(id: &MessageId) -> ProviderResult<(String, u32)> {
    decode_message_ref(id.as_str(), "imap-message:", "messageId")
}

fn decode_draft_id(id: &DraftId) -> ProviderResult<(String, u32)> {
    decode_message_ref(id.as_str(), "imap-draft:", "draftId")
}

fn decode_message_ref(value: &str, prefix: &str, _field: &str) -> ProviderResult<(String, u32)> {
    let suffix = value
        .strip_prefix(prefix)
        .ok_or(ProviderError::InvalidInput)?;
    let (mailbox, uid) = suffix.rsplit_once(':').ok_or(ProviderError::InvalidInput)?;
    let mailbox = decode_mailbox(mailbox)?;
    let uid = uid
        .parse::<u32>()
        .map_err(|_| ProviderError::InvalidInput)?;
    if uid == 0 {
        return Err(ProviderError::InvalidInput);
    }
    Ok((mailbox, uid))
}
fn decode_mailbox(encoded: &str) -> ProviderResult<String> {
    let mailbox =
        String::from_utf8(hex_decode(encoded)?).map_err(|_| ProviderError::InvalidInput)?;
    if mailbox.is_empty() || mailbox.len() > 512 || mailbox.chars().any(char::is_control) {
        return Err(ProviderError::InvalidInput);
    }
    Ok(mailbox)
}

fn decode_cursor(value: Option<&str>) -> ProviderResult<BTreeMap<String, (u32, u32)>> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let payload = value
        .strip_prefix("imap-v1;")
        .ok_or_else(|| ProviderError::InvalidInput)?;
    let mut result = BTreeMap::new();
    if payload.is_empty() {
        return Ok(result);
    }
    for entry in payload.split(',') {
        let (folder, state) = entry
            .split_once('=')
            .ok_or_else(|| ProviderError::InvalidInput)?;
        let (validity, uid) = state
            .split_once(':')
            .ok_or_else(|| ProviderError::InvalidInput)?;
        let folder =
            String::from_utf8(hex_decode(folder)?).map_err(|_| ProviderError::InvalidInput)?;
        let validity = validity.parse().map_err(|_| ProviderError::InvalidInput)?;
        let uid = uid.parse().map_err(|_| ProviderError::InvalidInput)?;
        result.insert(folder, (validity, uid));
    }
    Ok(result)
}

fn encode_cursor(cursor: &BTreeMap<String, (u32, u32)>) -> String {
    let values = cursor
        .iter()
        .map(|(folder, (validity, uid))| {
            format!("{}={validity}:{uid}", hex_encode(folder.as_bytes()))
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("imap-v1;{values}")
}

fn parse_offset_cursor(value: &str) -> ProviderResult<usize> {
    value
        .strip_prefix("offset:")
        .and_then(|number| number.parse().ok())
        .ok_or_else(|| ProviderError::InvalidInput)
}

fn quote_imap(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn hex_decode(value: &str) -> ProviderResult<Vec<u8>> {
    if value.is_empty() || value.len() % 2 != 0 || value.len() > 1024 {
        return Err(ProviderError::InvalidInput);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> ProviderResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ProviderError::InvalidInput),
    }
}

fn bounded_text(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}
fn safe_header_value(value: &str) -> String {
    bounded_text(
        &value
            .chars()
            .filter(|character| !character.is_control())
            .collect::<String>(),
        MAX_HEADER_BYTES,
    )
    .trim()
    .to_owned()
}

fn safe_filename(value: &str) -> String {
    let basename = value
        .rsplit(|character| character == '/' || character == '\\')
        .next()
        .unwrap_or("attachment")
        .chars()
        .filter(|character| !character.is_control())
        .collect::<String>();
    let bounded = bounded_text(basename.trim(), 255);
    if bounded.is_empty() || bounded == "." || bounded == ".." {
        "attachment".into()
    } else {
        bounded
    }
}

fn strip_html(value: &str) -> String {
    let mut output = String::with_capacity(value.len().min(crate::domain::mail::MAX_BODY_BYTES));
    let mut in_tag = false;
    for character in value.chars() {
        match character {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                output.push(' ');
            }
            _ if !in_tag => output.push(character),
            _ => {}
        }
        if output.len() >= crate::domain::mail::MAX_BODY_BYTES {
            break;
        }
    }
    output
}

fn sanitize_html(value: &str) -> String {
    let remove: std::collections::HashSet<&str> = [
        "img", "form", "iframe", "object", "embed", "svg", "math", "style",
    ]
    .into_iter()
    .collect();
    let mut builder = ammonia::Builder::default();
    builder.rm_tags(remove);
    builder.clean(value).to_string()
}

fn strip_bcc_headers(raw: &[u8]) -> ProviderResult<Vec<u8>> {
    let boundary = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(ProviderError::ProviderFailure)?;
    let header =
        std::str::from_utf8(&raw[..boundary]).map_err(|_| ProviderError::ProviderFailure)?;
    let mut output = Vec::with_capacity(raw.len());
    let mut skipping_bcc = false;
    for line in header.split("\r\n") {
        if line.starts_with(' ') || line.starts_with('\t') {
            if skipping_bcc {
                continue;
            }
        } else {
            skipping_bcc = line
                .split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case("bcc"));
            if skipping_bcc {
                continue;
            }
        }
        output.extend_from_slice(line.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&raw[boundary + 4..]);
    Ok(output)
}

fn new_rfc_message_id() -> String {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("<fily.{nanos:x}.{counter:x}@localhost>")
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}
