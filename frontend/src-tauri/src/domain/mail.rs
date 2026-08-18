use serde::{Deserialize, Serialize};
use std::fmt;

pub const MAX_PAGE_SIZE: u16 = 500;
pub const MAX_FOLDER_FILTERS: usize = 256;
pub const MAX_MESSAGE_MUTATIONS: usize = 500;
pub const MAX_RECIPIENTS: usize = 500;
pub const MAX_ATTACHMENTS: usize = 100;
pub const MAX_SUBJECT_BYTES: usize = 998;
pub const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_QUERY_BYTES: usize = 4 * 1024;
pub const MAX_CURSOR_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ValidationError {
    Missing { field: String },
    TooLong { field: String, max_bytes: usize },
    TooMany { field: String, max_items: usize },
    Invalid { field: String, reason: String },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { field } => write!(f, "{field} is required"),
            Self::TooLong { field, max_bytes } => {
                write!(f, "{field} exceeds the {max_bytes}-byte limit")
            }
            Self::TooMany { field, max_items } => {
                write!(f, "{field} exceeds the {max_items}-item limit")
            }
            Self::Invalid { field, reason } => write!(f, "{field} is invalid: {reason}"),
        }
    }
}

impl std::error::Error for ValidationError {}

pub trait Validate {
    fn validate(&self) -> Result<(), ValidationError>;
}

fn validate_text(
    field: &str,
    value: &str,
    max_bytes: usize,
    empty: bool,
) -> Result<(), ValidationError> {
    if !empty && value.is_empty() {
        return Err(ValidationError::Missing {
            field: field.into(),
        });
    }
    if value.len() > max_bytes {
        return Err(ValidationError::TooLong {
            field: field.into(),
            max_bytes,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ValidationError::Invalid {
            field: field.into(),
            reason: "control characters are not allowed".into(),
        });
    }
    Ok(())
}
fn validate_body(field: &str, value: &str) -> Result<(), ValidationError> {
    if value.len() > MAX_BODY_BYTES {
        return Err(ValidationError::TooLong {
            field: field.into(),
            max_bytes: MAX_BODY_BYTES,
        });
    }
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(ValidationError::Invalid {
            field: field.into(),
            reason: "unsupported control characters are not allowed".into(),
        });
    }
    Ok(())
}

macro_rules! opaque_id {
    ($name:ident, $max:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
                let value = value.into();
                validate_text(stringify!($name), &value, $max, false)?;
                if value.trim() != value {
                    return Err(ValidationError::Invalid {
                        field: stringify!($name).into(),
                        reason: "leading or trailing whitespace is not allowed".into(),
                    });
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl Validate for $name {
            fn validate(&self) -> Result<(), ValidationError> {
                validate_text(stringify!($name), &self.0, $max, false)?;
                if self.0.trim() != self.0 {
                    return Err(ValidationError::Invalid {
                        field: stringify!($name).into(),
                        reason: "leading or trailing whitespace is not allowed".into(),
                    });
                }
                Ok(())
            }
        }
    };
}

opaque_id!(AccountId, 256);
opaque_id!(CredentialId, 256);
opaque_id!(FolderId, 512);
opaque_id!(MessageId, 1024);
opaque_id!(DraftId, 1024);
opaque_id!(AttachmentId, 1024);
opaque_id!(OperationId, 256);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Gmail,
    Imap,
    Yahoo,
    Icloud,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailAddress {
    pub address: String,
    pub display_name: Option<String>,
}

impl Validate for EmailAddress {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text("address", &self.address, 320, false)?;
        let Some((local, domain)) = self.address.rsplit_once('@') else {
            return Err(ValidationError::Invalid {
                field: "address".into(),
                reason: "a normalized email address is required".into(),
            });
        };
        if local.is_empty()
            || domain.is_empty()
            || local.contains('@')
            || self.address.chars().any(char::is_whitespace)
            || domain.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err(ValidationError::Invalid {
                field: "address".into(),
                reason: "a normalized email address is required".into(),
            });
        }
        validate_host("address", domain)?;
        if let Some(name) = &self.display_name {
            validate_text("displayName", name, 256, false)?;
            if name.trim() != name {
                return Err(ValidationError::Invalid {
                    field: "displayName".into(),
                    reason: "leading or trailing whitespace is not allowed".into(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderEndpoint {
    pub imap_host: String,
    pub imap_port: u16,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub username: String,
    pub use_tls: bool,
}

impl Validate for ProviderEndpoint {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_host("imapHost", &self.imap_host)?;
        validate_host("smtpHost", &self.smtp_host)?;
        validate_text("username", &self.username, 320, false)?;
        if self.username.trim() != self.username {
            return Err(ValidationError::Invalid {
                field: "username".into(),
                reason: "leading or trailing whitespace is not allowed".into(),
            });
        }
        if self.imap_port == 0 {
            return Err(ValidationError::Invalid {
                field: "imapPort".into(),
                reason: "must be non-zero".into(),
            });
        }
        if self.smtp_port == 0 {
            return Err(ValidationError::Invalid {
                field: "smtpPort".into(),
                reason: "must be non-zero".into(),
            });
        }
        if !self.use_tls {
            return Err(ValidationError::Invalid {
                field: "useTls".into(),
                reason: "mail provider connections must use transport encryption".into(),
            });
        }
        Ok(())
    }
}

fn validate_host(field: &str, host: &str) -> Result<(), ValidationError> {
    validate_text(field, host, 253, false)?;
    let valid = host.is_ascii()
        && host.bytes().all(|byte| !byte.is_ascii_uppercase())
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if !valid {
        return Err(ValidationError::Invalid {
            field: field.into(),
            reason: "must be a normalized DNS name or IPv4 address".into(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectRequest {
    pub provider: ProviderKind,
    pub account_id: AccountId,
    /// Opaque OS-vault record identifier. This is never credential material.
    pub credential_id: CredentialId,
    pub identity: EmailAddress,
    pub endpoint: Option<ProviderEndpoint>,
}

impl Validate for ConnectRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        self.account_id.validate()?;
        self.credential_id.validate()?;
        self.identity.validate()?;
        if let Some(endpoint) = &self.endpoint {
            endpoint.validate()?;
        }
        match (self.provider, self.endpoint.is_some()) {
            (ProviderKind::Imap, false) => Err(ValidationError::Missing {
                field: "endpoint".into(),
            }),
            (ProviderKind::Gmail | ProviderKind::Yahoo | ProviderKind::Icloud, true) => {
                Err(ValidationError::Invalid {
                    field: "endpoint".into(),
                    reason: "managed-provider endpoints are fixed by the trusted core".into(),
                })
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectedAccount {
    pub account_id: AccountId,
    pub provider: ProviderKind,
    pub identity: EmailAddress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderRole {
    Inbox,
    Sent,
    Drafts,
    Archive,
    Trash,
    Spam,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Folder {
    pub id: FolderId,
    pub name: String,
    pub role: FolderRole,
    pub unread_count: Option<u64>,
    pub total_count: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListFoldersRequest {
    pub account_id: AccountId,
}

impl Validate for ListFoldersRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        self.account_id.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncRequest {
    pub account_id: AccountId,
    pub folder_ids: Vec<FolderId>,
    pub cursor: Option<String>,
    pub limit: u16,
}

impl Validate for SyncRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        self.account_id.validate()?;
        if self.folder_ids.len() > MAX_FOLDER_FILTERS {
            return Err(ValidationError::TooMany {
                field: "folderIds".into(),
                max_items: MAX_FOLDER_FILTERS,
            });
        }
        for id in &self.folder_ids {
            id.validate()?;
        }
        if let Some(cursor) = &self.cursor {
            validate_text("cursor", cursor, MAX_CURSOR_BYTES, false)?;
        }
        if self.limit == 0 || self.limit > MAX_PAGE_SIZE {
            return Err(ValidationError::Invalid {
                field: "limit".into(),
                reason: format!("must be between 1 and {MAX_PAGE_SIZE}"),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageSummary {
    pub id: MessageId,
    pub folder_ids: Vec<FolderId>,
    pub thread_id: Option<String>,
    pub subject: String,
    pub from: Option<EmailAddress>,
    pub to: Vec<EmailAddress>,
    pub received_at_ms: i64,
    pub unread: bool,
    pub has_attachments: bool,
    pub preview: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum SyncChange {
    Upsert(MessageSummary),
    Delete(MessageId),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncBatch {
    pub changes: Vec<SyncChange>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetrieveRequest {
    pub account_id: AccountId,
    pub message_id: MessageId,
    pub include_body: bool,
    pub max_attachment_bytes: u64,
}

impl Validate for RetrieveRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        self.account_id.validate()?;
        self.message_id.validate()?;
        if self.max_attachment_bytes > 100 * 1024 * 1024 {
            return Err(ValidationError::Invalid {
                field: "maxAttachmentBytes".into(),
                reason: "must not exceed 100 MiB".into(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    pub id: AttachmentId,
    pub filename: String,
    pub media_type: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    pub summary: MessageSummary,
    pub cc: Vec<EmailAddress>,
    pub bcc: Vec<EmailAddress>,
    pub reply_to: Option<EmailAddress>,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    pub attachments: Vec<Attachment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchRequest {
    pub account_id: AccountId,
    pub query: String,
    pub folder_ids: Vec<FolderId>,
    pub cursor: Option<String>,
    pub limit: u16,
}

impl Validate for SearchRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        self.account_id.validate()?;
        validate_text("query", &self.query, MAX_QUERY_BYTES, false)?;
        if self.folder_ids.len() > MAX_FOLDER_FILTERS {
            return Err(ValidationError::TooMany {
                field: "folderIds".into(),
                max_items: MAX_FOLDER_FILTERS,
            });
        }
        for id in &self.folder_ids {
            id.validate()?;
        }
        if let Some(cursor) = &self.cursor {
            validate_text("cursor", cursor, MAX_CURSOR_BYTES, false)?;
        }
        if self.limit == 0 || self.limit > MAX_PAGE_SIZE {
            return Err(ValidationError::Invalid {
                field: "limit".into(),
                reason: format!("must be between 1 and {MAX_PAGE_SIZE}"),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResults {
    pub messages: Vec<MessageSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftRequest {
    pub account_id: AccountId,
    /// Existing provider draft to update; `None` creates a new draft.
    pub draft_id: Option<DraftId>,
    pub in_reply_to: Option<MessageId>,
    pub to: Vec<EmailAddress>,
    pub cc: Vec<EmailAddress>,
    pub bcc: Vec<EmailAddress>,
    pub subject: String,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    /// Trusted-core attachment IDs, never filesystem paths.
    pub attachment_ids: Vec<AttachmentId>,
}

impl Validate for DraftRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        self.account_id.validate()?;
        if let Some(id) = &self.draft_id {
            id.validate()?;
        }
        if let Some(id) = &self.in_reply_to {
            id.validate()?;
        }
        let recipient_count = self.to.len() + self.cc.len() + self.bcc.len();
        if recipient_count > MAX_RECIPIENTS {
            return Err(ValidationError::TooMany {
                field: "recipients".into(),
                max_items: MAX_RECIPIENTS,
            });
        }
        for address in self.to.iter().chain(&self.cc).chain(&self.bcc) {
            address.validate()?;
        }
        validate_text("subject", &self.subject, MAX_SUBJECT_BYTES, true)?;
        if let Some(body) = &self.text_body {
            validate_body("textBody", body)?;
        }
        if let Some(body) = &self.html_body {
            validate_body("htmlBody", body)?;
        }
        if self.attachment_ids.len() > MAX_ATTACHMENTS {
            return Err(ValidationError::TooMany {
                field: "attachmentIds".into(),
                max_items: MAX_ATTACHMENTS,
            });
        }
        for id in &self.attachment_ids {
            id.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftResult {
    pub draft_id: DraftId,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteDraftRequest {
    pub account_id: AccountId,
    pub draft_id: DraftId,
}

impl Validate for DeleteDraftRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        self.account_id.validate()?;
        self.draft_id.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendRequest {
    pub account_id: AccountId,
    pub draft_id: DraftId,
    /// One-use authorization issued after user confirmation of the send plan.
    pub authorization_id: OperationId,
}

impl Validate for SendRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        self.account_id.validate()?;
        self.draft_id.validate()?;
        self.authorization_id.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendResult {
    pub message_id: MessageId,
    pub sent_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MutationRequest {
    pub account_id: AccountId,
    pub message_ids: Vec<MessageId>,
    /// One-use authorization issued after user confirmation of the mutation plan.
    pub authorization_id: OperationId,
}

impl Validate for MutationRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        self.account_id.validate()?;
        validate_message_ids(&self.message_ids)?;
        self.authorization_id.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveRequest {
    pub account_id: AccountId,
    pub message_ids: Vec<MessageId>,
    pub destination_folder_id: FolderId,
    /// One-use authorization issued after user confirmation of the move plan.
    pub authorization_id: OperationId,
}

impl Validate for MoveRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        self.account_id.validate()?;
        validate_message_ids(&self.message_ids)?;
        self.destination_folder_id.validate()?;
        self.authorization_id.validate()
    }
}

fn validate_message_ids(ids: &[MessageId]) -> Result<(), ValidationError> {
    if ids.is_empty() {
        return Err(ValidationError::Missing {
            field: "messageIds".into(),
        });
    }
    if ids.len() > MAX_MESSAGE_MUTATIONS {
        return Err(ValidationError::TooMany {
            field: "messageIds".into(),
            max_items: MAX_MESSAGE_MUTATIONS,
        });
    }
    for id in ids {
        id.validate()?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MutationResult {
    pub operation_id: OperationId,
    pub affected: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisconnectRequest {
    pub account_id: AccountId,
}

impl Validate for DisconnectRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        self.account_id.validate()
    }
}
