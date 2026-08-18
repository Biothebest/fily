use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::storage::{
    AccountRecord, MessageBody, MessageRecord, MigrationCheckpointRecord, Storage, StorageError,
};

const MIGRATION_NAME: &str = "legacy-fily-library-v1";
const MAX_BODY_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_ENVELOPE_BYTES: usize = 64 * 1024;
const MAX_ID_BYTES: usize = 192;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LegacyMigrationState {
    NotFound,
    Ready,
    Completed,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LegacyMigrationStatus {
    pub state: LegacyMigrationState,
    pub accounts: u32,
    pub messages: u32,
    pub skipped: u32,
}

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("legacy source is unavailable")]
    Source(#[source] io::Error),
    #[error("legacy source is not a supported Fily database")]
    InvalidSource,
    #[error("legacy source changed during migration")]
    SourceChanged,
    #[error("encrypted storage operation failed")]
    Storage(#[from] StorageError),
}

/// Resolves the sole supported legacy location inside Rust. This path is never accepted from, or
/// returned to, the webview.
pub fn legacy_database_path(home: &Path) -> PathBuf {
    home.join("FilyLibrary").join(".fily").join("index.sqlite3")
}

pub fn status(storage: &Storage, source: &Path) -> Result<LegacyMigrationStatus, MigrationError> {
    let checkpoint = storage.get_migration_checkpoint(MIGRATION_NAME)?;
    if !source.try_exists().map_err(MigrationError::Source)? {
        return Ok(checkpoint.map_or(
            LegacyMigrationStatus {
                state: LegacyMigrationState::NotFound,
                accounts: 0,
                messages: 0,
                skipped: 0,
            },
            completed_status,
        ));
    }

    validate_source_path(source)?;
    let source_hash = source_digest(source)?;
    if let Some(checkpoint) = checkpoint.filter(|record| record.source_hash == source_hash) {
        Ok(completed_status(checkpoint))
    } else {
        Ok(LegacyMigrationStatus {
            state: LegacyMigrationState::Ready,
            accounts: 0,
            messages: 0,
            skipped: 0,
        })
    }
}

/// Imports only normalized Gmail envelope/body fields. Legacy credentials, action payloads,
/// arbitrary metadata, and indexed filesystem paths are never selected from the source database.
pub fn migrate(storage: &Storage, source: &Path) -> Result<LegacyMigrationStatus, MigrationError> {
    if !source.try_exists().map_err(MigrationError::Source)? {
        return status(storage, source);
    }
    validate_source_path(source)?;
    let source_hash = source_digest(source)?;
    if let Some(checkpoint) = storage
        .get_migration_checkpoint(MIGRATION_NAME)?
        .filter(|record| record.source_hash == source_hash)
    {
        return Ok(completed_status(checkpoint));
    }

    let source_connection = Connection::open_with_flags(
        source,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| MigrationError::InvalidSource)?;
    source_connection
        .execute_batch("PRAGMA query_only = ON; PRAGMA trusted_schema = OFF;")
        .map_err(|_| MigrationError::InvalidSource)?;
    validate_legacy_schema(&source_connection)?;

    let now = now_millis();
    let mut accounts_by_address: HashMap<String, String> = storage
        .list_accounts()?
        .into_iter()
        .filter(|account| account.provider == "gmail")
        .map(|account| (account.address.to_lowercase(), account.id))
        .collect();
    let mut migrated_accounts = HashSet::new();
    let mut migrated_messages = HashSet::new();
    let mut messages = 0_u32;
    let mut skipped = 0_u32;

    let mut statement = source_connection
        .prepare("SELECT text,metadata_json FROM documents ORDER BY id")
        .map_err(|_| MigrationError::InvalidSource)?;
    let mut rows = statement
        .query([])
        .map_err(|_| MigrationError::InvalidSource)?;
    while let Some(row) = rows.next().map_err(|_| MigrationError::InvalidSource)? {
        let text: String = match row.get(0) {
            Ok(value) => value,
            Err(_) => {
                increment(&mut skipped);
                continue;
            }
        };
        let metadata_json: String = match row.get(1) {
            Ok(value) => value,
            Err(_) => {
                increment(&mut skipped);
                continue;
            }
        };
        let Some(legacy) = normalize_legacy_message(&text, &metadata_json, now) else {
            increment(&mut skipped);
            continue;
        };

        let account_id = if let Some(id) = accounts_by_address.get(&legacy.address) {
            id.clone()
        } else {
            let id = stable_id("legacy-gmail-account", &legacy.address);
            storage.upsert_account(&AccountRecord {
                id: id.clone(),
                provider: "gmail".into(),
                address: legacy.address.clone(),
                display_name: None,
                created_at: legacy.received_at,
                updated_at: now,
            })?;
            accounts_by_address.insert(legacy.address.clone(), id.clone());
            id
        };
        migrated_accounts.insert(account_id.clone());
        let message_key = format!("{}\0{}", account_id, legacy.remote_id);
        if !migrated_messages.insert(message_key.clone()) {
            increment(&mut skipped);
            continue;
        }

        let message_id = storage
            .find_message_id_by_remote_id(&account_id, &legacy.remote_id)?
            .unwrap_or_else(|| stable_id("legacy-gmail-message", &message_key));
        storage.upsert_message(&MessageRecord {
            id: message_id,
            account_id,
            folder_id: None,
            remote_id: legacy.remote_id,
            thread_id: legacy.thread_id,
            subject: legacy.subject,
            sender: legacy.sender,
            recipients: legacy.recipients,
            snippet: legacy.snippet,
            flags: legacy.flags,
            sent_at: None,
            received_at: legacy.received_at,
            size_bytes: text.len() as u64,
            body: MessageBody {
                text: Some(text),
                html: None,
            },
            updated_at: now,
        })?;
        increment(&mut messages);
    }
    drop(rows);
    drop(statement);
    drop(source_connection);

    if source_digest(source)? != source_hash {
        return Err(MigrationError::SourceChanged);
    }

    let checkpoint = MigrationCheckpointRecord {
        name: MIGRATION_NAME.into(),
        source_hash,
        accounts: migrated_accounts.len().try_into().unwrap_or(u32::MAX),
        messages,
        skipped,
        completed_at: now,
    };
    storage.upsert_migration_checkpoint(&checkpoint)?;
    storage.checkpoint()?;
    Ok(completed_status(checkpoint))
}

struct NormalizedLegacyMessage {
    address: String,
    remote_id: String,
    thread_id: Option<String>,
    subject: String,
    sender: String,
    recipients: String,
    snippet: String,
    flags: String,
    received_at: i64,
}
#[derive(Deserialize)]
struct LegacyMetadata {
    source: Option<String>,
    account: Option<String>,
    account_hint: Option<String>,
    message_id: Option<String>,
    thread_id: Option<String>,
    subject: Option<String>,
    sender: Option<String>,
    recipients: Option<String>,
    snippet: Option<String>,
    labels: Option<Vec<String>>,
    internal_date: Option<Value>,
}

fn normalize_legacy_message(
    text: &str,
    metadata_json: &str,
    fallback_timestamp: i64,
) -> Option<NormalizedLegacyMessage> {
    if text.contains('\0') || json_string_bytes(text).saturating_add(23) > MAX_BODY_JSON_BYTES {
        return None;
    }
    let metadata: LegacyMetadata = serde_json::from_str(metadata_json).ok()?;
    if metadata.source.as_deref() != Some("gmail") {
        return None;
    }

    let address = metadata
        .account
        .as_deref()
        .or(metadata.account_hint.as_deref())?
        .trim()
        .to_lowercase();
    if address.is_empty()
        || address.len() > 512
        || !address.contains('@')
        || address.chars().any(char::is_control)
    {
        return None;
    }
    let remote_id = clean_id(metadata.message_id.as_deref())?;
    let thread_id = clean_id(metadata.thread_id.as_deref());
    let subject = bounded(metadata.subject.as_deref().unwrap_or(""));
    let sender = bounded(metadata.sender.as_deref().unwrap_or(""));
    let sender = if sender.is_empty() {
        "Unknown sender".into()
    } else {
        sender
    };
    let recipients = bounded(metadata.recipients.as_deref().unwrap_or(""));
    let snippet = metadata
        .snippet
        .as_deref()
        .map(bounded)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| bounded_prefix(text, 512));
    let flags = metadata
        .labels
        .as_ref()
        .map(|labels| {
            let unread = labels.iter().any(|label| label == "UNREAD");
            let starred = labels.iter().any(|label| label == "STARRED");
            match (unread, starred) {
                (true, true) => "unread,starred",
                (true, false) => "unread",
                (false, true) => "starred",
                (false, false) => "",
            }
        })
        .unwrap_or("")
        .to_owned();
    let received_at = metadata
        .internal_date
        .as_ref()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string())
        })
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value >= 0)
        .unwrap_or(fallback_timestamp);

    Some(NormalizedLegacyMessage {
        address,
        remote_id,
        thread_id,
        subject,
        sender,
        recipients,
        snippet,
        flags,
        received_at,
    })
}

fn validate_source_path(source: &Path) -> Result<(), MigrationError> {
    for path in [
        source.to_path_buf(),
        source.parent().unwrap_or(source).to_path_buf(),
        source
            .parent()
            .and_then(Path::parent)
            .unwrap_or(source)
            .to_path_buf(),
    ] {
        let metadata = fs::symlink_metadata(path).map_err(MigrationError::Source)?;
        if metadata.file_type().is_symlink() {
            return Err(MigrationError::InvalidSource);
        }
    }
    if !fs::metadata(source)
        .map_err(MigrationError::Source)?
        .is_file()
    {
        return Err(MigrationError::InvalidSource);
    }
    Ok(())
}

fn validate_legacy_schema(connection: &Connection) -> Result<(), MigrationError> {
    let mut statement = connection
        .prepare("PRAGMA table_info(documents)")
        .map_err(|_| MigrationError::InvalidSource)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|_| MigrationError::InvalidSource)?
        .collect::<Result<HashSet<_>, _>>()
        .map_err(|_| MigrationError::InvalidSource)?;
    if ["id", "text", "metadata_json"]
        .iter()
        .all(|column| columns.contains(*column))
    {
        Ok(())
    } else {
        Err(MigrationError::InvalidSource)
    }
}

fn source_digest(source: &Path) -> Result<String, MigrationError> {
    let mut digest = Sha256::new();
    hash_file(&mut digest, b"database", source)?;
    let mut wal_name = source.as_os_str().to_os_string();
    wal_name.push("-wal");
    let wal = PathBuf::from(wal_name);
    if wal.try_exists().map_err(MigrationError::Source)? {
        if fs::symlink_metadata(&wal)
            .map_err(MigrationError::Source)?
            .file_type()
            .is_symlink()
        {
            return Err(MigrationError::InvalidSource);
        }
        hash_file(&mut digest, b"wal", &wal)?;
    } else {
        digest.update(b"no-wal");
    }
    Ok(hex(&digest.finalize()))
}

fn hash_file(digest: &mut Sha256, kind: &[u8], path: &Path) -> Result<(), MigrationError> {
    digest.update(kind);
    let mut file = File::open(path).map_err(MigrationError::Source)?;
    let length = file.metadata().map_err(MigrationError::Source)?.len();
    digest.update(length.to_le_bytes());
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(MigrationError::Source)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(())
}

fn completed_status(checkpoint: MigrationCheckpointRecord) -> LegacyMigrationStatus {
    LegacyMigrationStatus {
        state: LegacyMigrationState::Completed,
        accounts: checkpoint.accounts,
        messages: checkpoint.messages,
        skipped: checkpoint.skipped,
    }
}

fn clean_id(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty() || value.len() > MAX_ID_BYTES || value.chars().any(char::is_control) {
        None
    } else {
        Some(value.to_owned())
    }
}

fn bounded(value: &str) -> String {
    if value.contains('\0') {
        let cleaned: String = value
            .chars()
            .filter(|character| *character != '\0')
            .collect();
        bounded_prefix(&cleaned, MAX_ENVELOPE_BYTES)
    } else {
        bounded_prefix(value, MAX_ENVELOPE_BYTES)
    }
}

fn bounded_prefix(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn json_string_bytes(value: &str) -> usize {
    value.chars().fold(0_usize, |length, character| {
        length.saturating_add(match character {
            '"' | '\\' | '\u{0008}' | '\u{000c}' | '\n' | '\r' | '\t' => 2,
            '\u{0000}'..='\u{001f}' => 6,
            _ => character.len_utf8(),
        })
    })
}

fn stable_id(namespace: &str, value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(namespace.as_bytes());
    digest.update([0]);
    digest.update(value.as_bytes());
    format!("{namespace}:{}", hex(&digest.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

fn increment(value: &mut u32) {
    *value = value.saturating_add(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process;
    use zeroize::Zeroizing;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("fily-legacy-migration-{}-{nonce}", process::id()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn migration_is_read_only_idempotent_and_encrypts_message_bodies() {
        let root = TestDirectory::create();
        let source = root.0.join("FilyLibrary/.fily/index.sqlite3");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        let body = "migration-body-that-must-not-appear-in-the-destination";
        let credential = "legacy-refresh-token-that-must-not-be-migrated";
        {
            let legacy = Connection::open(&source).unwrap();
            legacy
                .execute_batch(
                    "CREATE TABLE documents (
                       id INTEGER PRIMARY KEY, path TEXT NOT NULL, text TEXT NOT NULL,
                       metadata_json TEXT NOT NULL);
                     CREATE TABLE credentials (refresh_token TEXT NOT NULL);",
                )
                .unwrap();
            let metadata = serde_json::json!({
                "source": "gmail",
                "account": "Person@Gmail.com",
                "message_id": "legacy-message-1",
                "thread_id": "legacy-thread-1",
                "subject": "Imported",
                "sender": "Sender <sender@example.com>",
                "recipients": "person@gmail.com",
                "snippet": "Migration sample",
                "labels": ["INBOX", "UNREAD"],
                "internal_date": "1700000000000",
                "refresh_token": credential
            });
            legacy
                .execute(
                    "INSERT INTO documents (path,text,metadata_json) VALUES (?1,?2,?3)",
                    rusqlite::params!["gmail://legacy-message-1", body, metadata.to_string()],
                )
                .unwrap();
            legacy
                .execute(
                    "INSERT INTO credentials (refresh_token) VALUES (?1)",
                    [credential],
                )
                .unwrap();
        }
        let source_before = fs::read(&source).unwrap();

        let destination = root.0.join("destination/fily.db");
        let storage = Storage::open(&destination, Zeroizing::new([7_u8; 32])).unwrap();
        assert_eq!(
            status(&storage, &source).unwrap().state,
            LegacyMigrationState::Ready
        );

        let first = migrate(&storage, &source).unwrap();
        assert_eq!(
            first,
            LegacyMigrationStatus {
                state: LegacyMigrationState::Completed,
                accounts: 1,
                messages: 1,
                skipped: 0,
            }
        );
        let second = migrate(&storage, &source).unwrap();
        assert_eq!(second, first);

        let accounts = storage.list_accounts().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].address, "person@gmail.com");
        let messages = storage.list_messages(&accounts[0].id, None, 10).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].remote_id, "legacy-message-1");
        assert_eq!(messages[0].body.text.as_deref(), Some(body));
        assert_eq!(messages[0].flags, "unread");

        assert_eq!(fs::read(&source).unwrap(), source_before);
        let encrypted = fs::read(destination).unwrap();
        assert!(!contains(&encrypted, body.as_bytes()));
        assert!(!contains(&encrypted, credential.as_bytes()));
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|candidate| candidate == needle)
    }
}
