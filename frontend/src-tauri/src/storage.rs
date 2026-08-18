use std::{
    collections::BTreeSet,
    fs,
    path::Path,
    sync::{Mutex, MutexGuard},
};

use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Transaction};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::vault::{CredentialVault, VaultError};

const SCHEMA_VERSION: i64 = 3;
const NONCE_LEN: usize = 24;
const MAX_ID_LEN: usize = 1_024;
const MAX_REMOTE_FOLDER_ID_LEN: usize = 512;
const MAX_REMOTE_MESSAGE_ID_LEN: usize = 1_024;
const MAX_SHORT_TEXT: usize = 512;
const MAX_LONG_TEXT: usize = 64 * 1024;
const MAX_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_ATTACHMENT_BYTES: usize = 100 * 1024 * 1024;
const MAX_SEARCH_RESULTS: u32 = 200;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database operation failed")]
    Database(#[source] rusqlite::Error),
    #[error("encrypted data could not be authenticated")]
    Authentication,
    #[error("stored encrypted data is invalid")]
    CorruptData,
    #[error("invalid {0}")]
    InvalidInput(&'static str),
    #[error("storage lock is unavailable")]
    LockUnavailable,
    #[error("credential vault operation failed")]
    Vault(#[from] VaultError),
    #[error("filesystem operation failed")]
    Filesystem(#[source] std::io::Error),
}

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountRecord {
    pub id: String,
    pub provider: String,
    pub address: String,
    pub display_name: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FolderRecord {
    pub id: String,
    pub account_id: String,
    pub remote_id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub role: Option<String>,
    pub unread_count: u32,
    pub total_count: u32,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageBody {
    pub text: Option<String>,
    pub html: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageRecord {
    pub id: String,
    pub account_id: String,
    pub folder_id: Option<String>,
    pub remote_id: String,
    pub thread_id: Option<String>,
    pub subject: String,
    pub sender: String,
    pub recipients: String,
    pub snippet: String,
    pub flags: String,
    pub sent_at: Option<i64>,
    pub received_at: i64,
    pub size_bytes: u64,
    pub body: MessageBody,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncCursorRecord {
    pub account_id: String,
    pub scope: String,
    pub cursor: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachmentRecord {
    pub id: String,
    pub message_id: String,
    pub remote_id: Option<String>,
    pub filename: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub content_id: Option<String>,
    pub content: Vec<u8>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DraftRecord {
    pub id: String,
    pub account_id: String,
    pub remote_id: String,
    pub payload: Value,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlanRecord {
    pub id: String,
    pub account_id: Option<String>,
    pub action: String,
    pub risk: String,
    pub status: String,
    pub payload: Value,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub confirmed_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditRecord {
    pub id: String,
    pub plan_id: Option<String>,
    pub account_id: Option<String>,
    pub event: String,
    pub details: Value,
    pub occurred_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecoveryRecord {
    pub id: String,
    pub account_id: Option<String>,
    pub kind: String,
    pub state: Value,
    pub created_at: i64,
    pub updated_at: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationCheckpointRecord {
    pub name: String,
    pub source_hash: String,
    pub accounts: u32,
    pub messages: u32,
    pub skipped: u32,
    pub completed_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchHit {
    pub message_id: String,
    pub account_id: String,
    pub subject: String,
    pub sender: String,
    pub snippet: String,
    pub received_at: i64,
}

/// Thread-safe owner of a SQLCipher connection and the separate authenticated-encryption key used
/// for sensitive record fields. Callers should obtain the key only from `CredentialVault`.
pub struct Storage {
    connection: Mutex<Connection>,
    field_key: Zeroizing<[u8; 32]>,
}

impl Storage {
    pub fn open_with_vault(
        path: impl AsRef<Path>,
        vault: &CredentialVault,
    ) -> Result<Self, StorageError> {
        let key = vault.load_or_create_application_key()?;
        Self::open(path, key)
    }

    pub fn open(path: impl AsRef<Path>, key: Zeroizing<[u8; 32]>) -> Result<Self, StorageError> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(StorageError::Filesystem)?;
            restrict_directory(parent)?;
        }

        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let database_key = derive_key(&key, b"fily/sqlcipher/v1")?;
        let field_key = derive_key(&key, b"fily/record-aead/v1")?;
        apply_database_key(&connection, &database_key)?;
        connection.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))?;
        connection.execute_batch(
            "PRAGMA cipher_memory_security = ON;
             PRAGMA foreign_keys = ON;
             PRAGMA secure_delete = ON;
             PRAGMA trusted_schema = OFF;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA wal_autocheckpoint = 1000;
             PRAGMA busy_timeout = 5000;",
        )?;
        initialize_schema(&mut connection)?;
        restrict_file(path)?;

        Ok(Self {
            connection: Mutex::new(connection),
            field_key,
        })
    }

    pub fn upsert_account(&self, record: &AccountRecord) -> Result<(), StorageError> {
        validate_account(record)?;
        self.lock()?.execute(
            "INSERT INTO accounts (id, provider, address, display_name, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET provider=excluded.provider, address=excluded.address,
               display_name=excluded.display_name, updated_at=excluded.updated_at",
            params![
                record.id,
                record.provider,
                record.address,
                record.display_name,
                record.created_at,
                record.updated_at
            ],
        )?;
        Ok(())
    }

    pub fn get_account(&self, id: &str) -> Result<Option<AccountRecord>, StorageError> {
        validate_id(id, "account id")?;
        self.lock()?
            .query_row(
                "SELECT id, provider, address, display_name, created_at, updated_at FROM accounts WHERE id=?1",
                [id],
                |row| Ok(AccountRecord { id: row.get(0)?, provider: row.get(1)?, address: row.get(2)?, display_name: row.get(3)?, created_at: row.get(4)?, updated_at: row.get(5)? }),
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub fn list_accounts(&self) -> Result<Vec<AccountRecord>, StorageError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT id, provider, address, display_name, created_at, updated_at FROM accounts ORDER BY address, id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(AccountRecord {
                id: row.get(0)?,
                provider: row.get(1)?,
                address: row.get(2)?,
                display_name: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            })
        })?;
        collect_rows(rows)
    }

    pub fn delete_account(&self, id: &str) -> Result<bool, StorageError> {
        validate_id(id, "account id")?;
        Ok(self
            .lock()?
            .execute("DELETE FROM accounts WHERE id=?1", [id])?
            == 1)
    }

    pub fn upsert_folder(&self, record: &FolderRecord) -> Result<(), StorageError> {
        validate_folder(record)?;
        self.lock()?.execute(
            "INSERT INTO folders (id, account_id, remote_id, parent_id, name, role, unread_count, total_count, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
             ON CONFLICT(id) DO UPDATE SET account_id=excluded.account_id, remote_id=excluded.remote_id,
               parent_id=excluded.parent_id, name=excluded.name, role=excluded.role,
               unread_count=excluded.unread_count, total_count=excluded.total_count, updated_at=excluded.updated_at",
            params![record.id, record.account_id, record.remote_id, record.parent_id, record.name, record.role, record.unread_count, record.total_count, record.updated_at],
        )?;
        Ok(())
    }
    pub fn get_folder(&self, id: &str) -> Result<Option<FolderRecord>, StorageError> {
        validate_id(id, "folder id")?;
        self.lock()?
            .query_row(
                "SELECT id,account_id,remote_id,parent_id,name,role,unread_count,total_count,updated_at
                 FROM folders WHERE id=?1",
                [id],
                |row| Ok(FolderRecord {
                    id: row.get(0)?,
                    account_id: row.get(1)?,
                    remote_id: row.get(2)?,
                    parent_id: row.get(3)?,
                    name: row.get(4)?,
                    role: row.get(5)?,
                    unread_count: row.get(6)?,
                    total_count: row.get(7)?,
                    updated_at: row.get(8)?,
                }),
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub fn list_folders(&self, account_id: &str) -> Result<Vec<FolderRecord>, StorageError> {
        validate_id(account_id, "account id")?;
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT id, account_id, remote_id, parent_id, name, role, unread_count, total_count, updated_at
             FROM folders WHERE account_id=?1 ORDER BY name, id",
        )?;
        let rows = statement.query_map([account_id], |row| {
            Ok(FolderRecord {
                id: row.get(0)?,
                account_id: row.get(1)?,
                remote_id: row.get(2)?,
                parent_id: row.get(3)?,
                name: row.get(4)?,
                role: row.get(5)?,
                unread_count: row.get(6)?,
                total_count: row.get(7)?,
                updated_at: row.get(8)?,
            })
        })?;
        collect_rows(rows)
    }

    /// Replaces an account's provider folder snapshot in one transaction. Removed folders only
    /// remove their associations; messages remain available until the provider reports deletion.
    pub fn reconcile_folders(
        &self,
        account_id: &str,
        records: &[FolderRecord],
    ) -> Result<(), StorageError> {
        validate_id(account_id, "account id")?;
        let mut retained = BTreeSet::new();
        for record in records {
            validate_folder(record)?;
            if record.account_id != account_id {
                return Err(StorageError::InvalidInput("folder account"));
            }
            retained.insert(record.id.clone());
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        for record in records {
            transaction.execute(
                "INSERT INTO folders (id,account_id,remote_id,parent_id,name,role,unread_count,total_count,updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
                 ON CONFLICT(id) DO UPDATE SET account_id=excluded.account_id,
                   remote_id=excluded.remote_id,parent_id=excluded.parent_id,name=excluded.name,
                   role=excluded.role,unread_count=excluded.unread_count,
                   total_count=excluded.total_count,updated_at=excluded.updated_at",
                params![record.id,record.account_id,record.remote_id,record.parent_id,record.name,record.role,record.unread_count,record.total_count,record.updated_at],
            )?;
        }
        let stale_ids = {
            let mut statement =
                transaction.prepare("SELECT id FROM folders WHERE account_id=?1")?;
            let rows = statement.query_map([account_id], |row| row.get::<_, String>(0))?;
            collect_rows(rows)?
                .into_iter()
                .filter(|id| !retained.contains(id))
                .collect::<Vec<_>>()
        };
        for id in stale_ids {
            transaction.execute(
                "DELETE FROM folders WHERE id=?1 AND account_id=?2",
                params![id, account_id],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn delete_folder(&self, id: &str) -> Result<bool, StorageError> {
        validate_id(id, "folder id")?;
        Ok(self
            .lock()?
            .execute("DELETE FROM folders WHERE id=?1", [id])?
            == 1)
    }

    pub fn upsert_message(&self, record: &MessageRecord) -> Result<(), StorageError> {
        validate_message(record)?;
        let (nonce, ciphertext) = self.encrypt("messages", &record.id, "body", &record.body)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO messages (id,account_id,folder_id,remote_id,thread_id,subject,sender,recipients,snippet,flags,sent_at,received_at,size_bytes,body_nonce,body_ciphertext,updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)
             ON CONFLICT(id) DO UPDATE SET account_id=excluded.account_id, folder_id=excluded.folder_id,
               remote_id=excluded.remote_id, thread_id=excluded.thread_id, subject=excluded.subject,
               sender=excluded.sender, recipients=excluded.recipients, snippet=excluded.snippet,
               flags=excluded.flags, sent_at=excluded.sent_at, received_at=excluded.received_at,
               size_bytes=excluded.size_bytes, body_nonce=excluded.body_nonce,
               body_ciphertext=excluded.body_ciphertext, updated_at=excluded.updated_at",
            params![record.id,record.account_id,record.folder_id,record.remote_id,record.thread_id,record.subject,record.sender,record.recipients,record.snippet,record.flags,record.sent_at,record.received_at,record.size_bytes,nonce,ciphertext,record.updated_at],
        )?;
        transaction.execute(
            "DELETE FROM message_folders WHERE message_id=?1",
            [&record.id],
        )?;
        if let Some(folder_id) = &record.folder_id {
            let inserted = transaction.execute(
                "INSERT INTO message_folders(message_id,folder_id)
                 SELECT ?1,id FROM folders WHERE id=?2 AND account_id=?3",
                params![record.id, folder_id, record.account_id],
            )?;
            if inserted != 1 {
                return Err(StorageError::InvalidInput("message folder"));
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Persists one provider summary and replaces its complete folder membership atomically.
    ///
    /// Metadata-only sync must not erase a body fetched earlier, so conflict updates intentionally
    /// retain the existing encrypted body and size.
    pub fn upsert_synced_message(
        &self,
        record: &MessageRecord,
        folder_ids: &[String],
    ) -> Result<String, StorageError> {
        validate_message(record)?;
        for folder_id in folder_ids {
            validate_id(folder_id, "folder id")?;
        }
        if record
            .folder_id
            .as_ref()
            .is_some_and(|primary| !folder_ids.iter().any(|folder| folder == primary))
        {
            return Err(StorageError::InvalidInput("primary folder"));
        }
        let mut connection = self.lock()?;
        let effective_id = connection
            .query_row(
                "SELECT id FROM messages WHERE account_id=?1 AND remote_id=?2",
                params![record.account_id, record.remote_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_else(|| record.id.clone());
        let (nonce, ciphertext) = self.encrypt("messages", &effective_id, "body", &record.body)?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO messages (id,account_id,folder_id,remote_id,thread_id,subject,sender,recipients,snippet,flags,sent_at,received_at,size_bytes,body_nonce,body_ciphertext,updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)
             ON CONFLICT(id) DO UPDATE SET account_id=excluded.account_id, folder_id=excluded.folder_id,
               remote_id=excluded.remote_id, thread_id=excluded.thread_id, subject=excluded.subject,
               sender=excluded.sender, recipients=excluded.recipients, snippet=excluded.snippet,
               flags=excluded.flags, sent_at=excluded.sent_at, received_at=excluded.received_at,
               updated_at=excluded.updated_at",
            params![effective_id,record.account_id,record.folder_id,record.remote_id,record.thread_id,record.subject,record.sender,record.recipients,record.snippet,record.flags,record.sent_at,record.received_at,record.size_bytes,nonce,ciphertext,record.updated_at],
        )?;
        transaction.execute(
            "DELETE FROM message_folders WHERE message_id=?1",
            [&effective_id],
        )?;
        for folder_id in folder_ids {
            let inserted = transaction.execute(
                "INSERT INTO message_folders (message_id,folder_id)
                 SELECT ?1,id FROM folders WHERE id=?2 AND account_id=?3",
                params![effective_id, folder_id, record.account_id],
            )?;
            if inserted != 1 {
                return Err(StorageError::InvalidInput("message folder"));
            }
        }
        transaction.commit()?;
        Ok(effective_id)
    }

    pub fn get_message(&self, id: &str) -> Result<Option<MessageRecord>, StorageError> {
        validate_id(id, "message id")?;
        let stored = self.lock()?.query_row(
            "SELECT id,account_id,folder_id,remote_id,thread_id,subject,sender,recipients,snippet,flags,sent_at,received_at,size_bytes,body_nonce,body_ciphertext,updated_at FROM messages WHERE id=?1",
            [id],
            |row| Ok((MessageRecord { id: row.get(0)?, account_id: row.get(1)?, folder_id: row.get(2)?, remote_id: row.get(3)?, thread_id: row.get(4)?, subject: row.get(5)?, sender: row.get(6)?, recipients: row.get(7)?, snippet: row.get(8)?, flags: row.get(9)?, sent_at: row.get(10)?, received_at: row.get(11)?, size_bytes: row.get(12)?, body: MessageBody { text: None, html: None }, updated_at: row.get(15)? }, row.get::<_, Vec<u8>>(13)?, row.get::<_, Vec<u8>>(14)?)),
        ).optional()?;
        stored
            .map(|(mut record, nonce, ciphertext)| {
                record.body = self.decrypt("messages", &record.id, "body", &nonce, &ciphertext)?;
                Ok(record)
            })
            .transpose()
    }
    pub fn find_message_id_by_remote_id(
        &self,
        account_id: &str,
        remote_id: &str,
    ) -> Result<Option<String>, StorageError> {
        validate_id(account_id, "account id")?;
        validate_opaque_id(remote_id, MAX_REMOTE_MESSAGE_ID_LEN, "remote message id")?;
        self.lock()?
            .query_row(
                "SELECT id FROM messages WHERE account_id=?1 AND remote_id=?2",
                params![account_id, remote_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub fn list_messages(
        &self,
        account_id: &str,
        folder_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<MessageRecord>, StorageError> {
        validate_id(account_id, "account id")?;
        if let Some(folder_id) = folder_id {
            validate_id(folder_id, "folder id")?;
        }
        validate_limit(limit)?;
        let ids = {
            let connection = self.lock()?;
            let mut statement = connection.prepare(
                "SELECT m.id FROM messages m
                 WHERE m.account_id=?1 AND (
                   ?2 IS NULL OR EXISTS (
                     SELECT 1 FROM message_folders mf
                     WHERE mf.message_id=m.id AND mf.folder_id=?2
                   )
                 )
                 ORDER BY m.received_at DESC, m.id LIMIT ?3",
            )?;
            let rows = statement.query_map(params![account_id, folder_id, limit], |row| {
                row.get::<_, String>(0)
            })?;
            collect_rows(rows)?
        };
        ids.iter()
            .map(|id| self.get_message(id)?.ok_or(StorageError::CorruptData))
            .collect()
    }
    pub fn list_messages_page(
        &self,
        account_id: &str,
        folder_id: Option<&str>,
        after_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<MessageRecord>, StorageError> {
        validate_id(account_id, "account id")?;
        if let Some(folder_id) = folder_id {
            validate_id(folder_id, "folder id")?;
        }
        validate_limit(limit)?;
        let after = after_id
            .map(|id| {
                let record = self
                    .get_message(id)?
                    .ok_or(StorageError::InvalidInput("message cursor"))?;
                if record.account_id != account_id {
                    return Err(StorageError::InvalidInput("message cursor"));
                }
                Ok((record.received_at, record.id))
            })
            .transpose()?;
        let ids = {
            let connection = self.lock()?;
            let mut statement = connection.prepare(
                "SELECT m.id FROM messages m
                 WHERE m.account_id=?1
                   AND (?2 IS NULL OR EXISTS (
                     SELECT 1 FROM message_folders mf
                     WHERE mf.message_id=m.id AND mf.folder_id=?2
                   ))
                   AND (?3 IS NULL OR m.received_at < ?3
                        OR (m.received_at = ?3 AND m.id > ?4))
                 ORDER BY m.received_at DESC, m.id LIMIT ?5",
            )?;
            let rows = statement.query_map(
                params![
                    account_id,
                    folder_id,
                    after.as_ref().map(|value| value.0),
                    after.as_ref().map(|value| value.1.as_str()),
                    limit
                ],
                |row| row.get::<_, String>(0),
            )?;
            collect_rows(rows)?
        };
        ids.iter()
            .map(|id| self.get_message(id)?.ok_or(StorageError::CorruptData))
            .collect()
    }

    pub fn delete_message(&self, id: &str) -> Result<bool, StorageError> {
        validate_id(id, "message id")?;
        Ok(self
            .lock()?
            .execute("DELETE FROM messages WHERE id=?1", [id])?
            == 1)
    }

    pub fn delete_message_by_remote_id(
        &self,
        account_id: &str,
        remote_id: &str,
    ) -> Result<bool, StorageError> {
        validate_id(account_id, "account id")?;
        validate_opaque_id(remote_id, MAX_REMOTE_MESSAGE_ID_LEN, "remote message id")?;
        Ok(self.lock()?.execute(
            "DELETE FROM messages WHERE account_id=?1 AND remote_id=?2",
            params![account_id, remote_id],
        )? == 1)
    }

    pub fn upsert_draft(&self, record: &DraftRecord) -> Result<(), StorageError> {
        validate_draft(record)?;
        let (nonce, ciphertext) = self.encrypt("drafts", &record.id, "payload", &record.payload)?;
        self.lock()?.execute(
            "INSERT INTO drafts (id,account_id,remote_id,payload_nonce,payload_ciphertext,updated_at)
             VALUES (?1,?2,?3,?4,?5,?6)
             ON CONFLICT(id) DO UPDATE SET account_id=excluded.account_id,
               remote_id=excluded.remote_id, payload_nonce=excluded.payload_nonce,
               payload_ciphertext=excluded.payload_ciphertext, updated_at=excluded.updated_at",
            params![
                record.id,
                record.account_id,
                record.remote_id,
                nonce,
                ciphertext,
                record.updated_at
            ],
        )?;
        Ok(())
    }

    pub fn get_draft(&self, id: &str) -> Result<Option<DraftRecord>, StorageError> {
        validate_id(id, "draft id")?;
        let stored = self
            .lock()?
            .query_row(
                "SELECT id,account_id,remote_id,payload_nonce,payload_ciphertext,updated_at
                 FROM drafts WHERE id=?1",
                [id],
                |row| {
                    Ok((
                        DraftRecord {
                            id: row.get(0)?,
                            account_id: row.get(1)?,
                            remote_id: row.get(2)?,
                            payload: Value::Null,
                            updated_at: row.get(5)?,
                        },
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()?;
        stored
            .map(|(mut record, nonce, ciphertext)| {
                record.payload =
                    self.decrypt("drafts", &record.id, "payload", &nonce, &ciphertext)?;
                Ok(record)
            })
            .transpose()
    }

    pub fn list_drafts(
        &self,
        account_id: &str,
        after_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<DraftRecord>, StorageError> {
        validate_id(account_id, "account id")?;
        validate_limit(limit)?;
        let after = after_id
            .map(|id| {
                let record = self
                    .get_draft(id)?
                    .ok_or(StorageError::InvalidInput("draft cursor"))?;
                if record.account_id != account_id {
                    return Err(StorageError::InvalidInput("draft cursor"));
                }
                Ok((record.updated_at, record.id))
            })
            .transpose()?;
        let ids = {
            let connection = self.lock()?;
            let mut statement = connection.prepare(
                "SELECT id FROM drafts
                 WHERE account_id=?1
                   AND (?2 IS NULL OR updated_at < ?2 OR (updated_at = ?2 AND id < ?3))
                 ORDER BY updated_at DESC, id DESC LIMIT ?4",
            )?;
            let rows = statement.query_map(
                params![
                    account_id,
                    after.as_ref().map(|value| value.0),
                    after.as_ref().map(|value| value.1.as_str()),
                    limit
                ],
                |row| row.get::<_, String>(0),
            )?;
            collect_rows(rows)?
        };
        ids.iter()
            .map(|id| self.get_draft(id)?.ok_or(StorageError::CorruptData))
            .collect()
    }

    pub fn delete_draft(&self, id: &str) -> Result<bool, StorageError> {
        validate_id(id, "draft id")?;
        Ok(self
            .lock()?
            .execute("DELETE FROM drafts WHERE id=?1", [id])?
            == 1)
    }

    /// Searches the persistent FTS5 index. Bodies remain AEAD-encrypted and are intentionally not
    /// copied into FTS shadow tables; searchable fields are non-secret envelope metadata only.
    pub fn search_messages(
        &self,
        account_id: &str,
        query: &str,
        limit: u32,
    ) -> Result<Vec<SearchHit>, StorageError> {
        validate_id(account_id, "account id")?;
        validate_limit(limit)?;
        let query = fts_query(query)?;
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT m.id,m.account_id,m.subject,m.sender,m.snippet,m.received_at
             FROM message_search JOIN messages m ON m.id=message_search.message_id
             WHERE message_search MATCH ?1 AND m.account_id=?2
             ORDER BY bm25(message_search), m.received_at DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(params![query, account_id, limit], |row| {
            Ok(SearchHit {
                message_id: row.get(0)?,
                account_id: row.get(1)?,
                subject: row.get(2)?,
                sender: row.get(3)?,
                snippet: row.get(4)?,
                received_at: row.get(5)?,
            })
        })?;
        collect_rows(rows)
    }

    pub fn upsert_sync_cursor(&self, record: &SyncCursorRecord) -> Result<(), StorageError> {
        validate_id(&record.account_id, "account id")?;
        validate_text(&record.scope, MAX_SHORT_TEXT, "sync scope")?;
        validate_text(&record.cursor, MAX_LONG_TEXT, "sync cursor")?;
        self.lock()?.execute(
            "INSERT INTO sync_cursors (account_id,scope,cursor,updated_at) VALUES (?1,?2,?3,?4)
             ON CONFLICT(account_id,scope) DO UPDATE SET cursor=excluded.cursor,updated_at=excluded.updated_at",
            params![record.account_id, record.scope, record.cursor, record.updated_at],
        )?;
        Ok(())
    }

    pub fn get_sync_cursor(
        &self,
        account_id: &str,
        scope: &str,
    ) -> Result<Option<SyncCursorRecord>, StorageError> {
        validate_id(account_id, "account id")?;
        validate_text(scope, MAX_SHORT_TEXT, "sync scope")?;
        self.lock()?.query_row(
            "SELECT account_id,scope,cursor,updated_at FROM sync_cursors WHERE account_id=?1 AND scope=?2",
            params![account_id, scope],
            |row| Ok(SyncCursorRecord { account_id: row.get(0)?, scope: row.get(1)?, cursor: row.get(2)?, updated_at: row.get(3)? }),
        ).optional().map_err(StorageError::from)
    }
    pub fn list_sync_cursors(
        &self,
        account_id: &str,
    ) -> Result<Vec<SyncCursorRecord>, StorageError> {
        validate_id(account_id, "account id")?;
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT account_id,scope,cursor,updated_at FROM sync_cursors
             WHERE account_id=?1 ORDER BY scope",
        )?;
        let rows = statement.query_map([account_id], |row| {
            Ok(SyncCursorRecord {
                account_id: row.get(0)?,
                scope: row.get(1)?,
                cursor: row.get(2)?,
                updated_at: row.get(3)?,
            })
        })?;
        collect_rows(rows)
    }

    pub fn delete_sync_cursor(&self, account_id: &str, scope: &str) -> Result<bool, StorageError> {
        validate_id(account_id, "account id")?;
        validate_text(scope, MAX_SHORT_TEXT, "sync scope")?;
        Ok(self.lock()?.execute(
            "DELETE FROM sync_cursors WHERE account_id=?1 AND scope=?2",
            params![account_id, scope],
        )? == 1)
    }

    pub fn begin_sync_snapshot(&self, account_id: &str, now: i64) -> Result<(), StorageError> {
        validate_id(account_id, "account id")?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "DELETE FROM sync_snapshot_seen WHERE account_id=?1",
            [account_id],
        )?;
        transaction.execute(
            "INSERT INTO sync_cursors(account_id,scope,cursor,updated_at)
             VALUES (?1,'account-snapshot','in_progress',?2)
             ON CONFLICT(account_id,scope) DO UPDATE SET cursor='in_progress',updated_at=excluded.updated_at",
            params![account_id, now],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn mark_sync_snapshot_message(
        &self,
        account_id: &str,
        message_id: &str,
    ) -> Result<(), StorageError> {
        validate_id(account_id, "account id")?;
        validate_id(message_id, "message id")?;
        self.lock()?.execute(
            "INSERT OR IGNORE INTO sync_snapshot_seen(account_id,message_id)
             SELECT ?1,?2 WHERE EXISTS (
               SELECT 1 FROM sync_cursors WHERE account_id=?1 AND scope='account-snapshot'
             )",
            params![account_id, message_id],
        )?;
        Ok(())
    }

    /// Completes a full bounded snapshot. Only messages absent from every completed page are
    /// removed, making provider moves and deletes safe across continuation requests and crashes.
    pub fn finish_sync_snapshot(&self, account_id: &str) -> Result<u64, StorageError> {
        validate_id(account_id, "account id")?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let active: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM sync_cursors
             WHERE account_id=?1 AND scope='account-snapshot')",
            [account_id],
            |row| row.get(0),
        )?;
        if !active {
            transaction.commit()?;
            return Ok(0);
        }
        let deleted = transaction.execute(
            "DELETE FROM messages
             WHERE account_id=?1 AND NOT EXISTS (
               SELECT 1 FROM sync_snapshot_seen seen
               WHERE seen.account_id=?1 AND seen.message_id=messages.id
             )",
            [account_id],
        )?;
        transaction.execute(
            "DELETE FROM sync_snapshot_seen WHERE account_id=?1",
            [account_id],
        )?;
        transaction.execute(
            "DELETE FROM sync_cursors WHERE account_id=?1 AND scope='account-snapshot'",
            [account_id],
        )?;
        transaction.commit()?;
        Ok(deleted as u64)
    }

    pub fn upsert_attachment(&self, record: &AttachmentRecord) -> Result<(), StorageError> {
        validate_attachment(record)?;
        let (nonce, ciphertext) =
            self.encrypt_bytes("attachments", &record.id, "content", &record.content)?;
        self.lock()?.execute(
            "INSERT INTO attachments (id,message_id,remote_id,filename,media_type,size_bytes,content_id,content_nonce,content_ciphertext,created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(id) DO UPDATE SET message_id=excluded.message_id,remote_id=excluded.remote_id,
               filename=excluded.filename,media_type=excluded.media_type,size_bytes=excluded.size_bytes,
               content_id=excluded.content_id,content_nonce=excluded.content_nonce,content_ciphertext=excluded.content_ciphertext",
            params![record.id,record.message_id,record.remote_id,record.filename,record.media_type,record.size_bytes,record.content_id,nonce,ciphertext,record.created_at],
        )?;
        Ok(())
    }

    pub fn get_attachment(&self, id: &str) -> Result<Option<AttachmentRecord>, StorageError> {
        validate_id(id, "attachment id")?;
        let stored = self.lock()?.query_row(
            "SELECT id,message_id,remote_id,filename,media_type,size_bytes,content_id,content_nonce,content_ciphertext,created_at FROM attachments WHERE id=?1",
            [id],
            |row| Ok((AttachmentRecord { id: row.get(0)?, message_id: row.get(1)?, remote_id: row.get(2)?, filename: row.get(3)?, media_type: row.get(4)?, size_bytes: row.get(5)?, content_id: row.get(6)?, content: Vec::new(), created_at: row.get(9)? }, row.get::<_, Vec<u8>>(7)?, row.get::<_, Vec<u8>>(8)?)),
        ).optional()?;
        stored
            .map(|(mut record, nonce, ciphertext)| {
                record.content =
                    self.decrypt_bytes("attachments", &record.id, "content", &nonce, &ciphertext)?;
                Ok(record)
            })
            .transpose()
    }

    pub fn list_attachments(
        &self,
        message_id: &str,
    ) -> Result<Vec<AttachmentRecord>, StorageError> {
        validate_id(message_id, "message id")?;
        let ids = {
            let connection = self.lock()?;
            let mut statement = connection
                .prepare("SELECT id FROM attachments WHERE message_id=?1 ORDER BY filename,id")?;
            let rows = statement.query_map([message_id], |row| row.get::<_, String>(0))?;
            collect_rows(rows)?
        };
        ids.iter()
            .map(|id| self.get_attachment(id)?.ok_or(StorageError::CorruptData))
            .collect()
    }

    pub fn delete_attachment(&self, id: &str) -> Result<bool, StorageError> {
        validate_id(id, "attachment id")?;
        Ok(self
            .lock()?
            .execute("DELETE FROM attachments WHERE id=?1", [id])?
            == 1)
    }

    pub fn upsert_plan(&self, record: &PlanRecord) -> Result<(), StorageError> {
        validate_plan(record)?;
        let (nonce, ciphertext) = self.encrypt("plans", &record.id, "payload", &record.payload)?;
        self.lock()?.execute(
            "INSERT INTO plans (id,account_id,action,risk,status,payload_nonce,payload_ciphertext,created_at,expires_at,confirmed_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(id) DO UPDATE SET account_id=excluded.account_id,action=excluded.action,risk=excluded.risk,
               status=excluded.status,payload_nonce=excluded.payload_nonce,payload_ciphertext=excluded.payload_ciphertext,
               expires_at=excluded.expires_at,confirmed_at=excluded.confirmed_at",
            params![record.id,record.account_id,record.action,record.risk,record.status,nonce,ciphertext,record.created_at,record.expires_at,record.confirmed_at],
        )?;
        Ok(())
    }

    pub fn get_plan(&self, id: &str) -> Result<Option<PlanRecord>, StorageError> {
        validate_id(id, "plan id")?;
        let stored = self.lock()?.query_row(
            "SELECT id,account_id,action,risk,status,payload_nonce,payload_ciphertext,created_at,expires_at,confirmed_at FROM plans WHERE id=?1",
            [id],
            |row| Ok((PlanRecord { id: row.get(0)?, account_id: row.get(1)?, action: row.get(2)?, risk: row.get(3)?, status: row.get(4)?, payload: Value::Null, created_at: row.get(7)?, expires_at: row.get(8)?, confirmed_at: row.get(9)? }, row.get::<_, Vec<u8>>(5)?, row.get::<_, Vec<u8>>(6)?)),
        ).optional()?;
        stored
            .map(|(mut record, nonce, ciphertext)| {
                record.payload =
                    self.decrypt("plans", &record.id, "payload", &nonce, &ciphertext)?;
                Ok(record)
            })
            .transpose()
    }

    pub fn list_plans(
        &self,
        status: Option<&str>,
        limit: u32,
    ) -> Result<Vec<PlanRecord>, StorageError> {
        if let Some(status) = status {
            validate_plan_status(status)?;
        }
        validate_limit(limit)?;
        let ids = {
            let connection = self.lock()?;
            let mut statement = connection.prepare(
                "SELECT id FROM plans WHERE (?1 IS NULL OR status=?1) ORDER BY created_at DESC,id LIMIT ?2",
            )?;
            let rows =
                statement.query_map(params![status, limit], |row| row.get::<_, String>(0))?;
            collect_rows(rows)?
        };
        ids.iter()
            .map(|id| self.get_plan(id)?.ok_or(StorageError::CorruptData))
            .collect()
    }

    pub fn delete_plan(&self, id: &str) -> Result<bool, StorageError> {
        validate_id(id, "plan id")?;
        Ok(self
            .lock()?
            .execute("DELETE FROM plans WHERE id=?1", [id])?
            == 1)
    }

    pub fn append_audit(&self, record: &AuditRecord) -> Result<(), StorageError> {
        validate_audit(record)?;
        let (nonce, ciphertext) = self.encrypt("audit", &record.id, "details", &record.details)?;
        self.lock()?.execute(
            "INSERT INTO audit (id,plan_id,account_id,event,details_nonce,details_ciphertext,occurred_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![record.id,record.plan_id,record.account_id,record.event,nonce,ciphertext,record.occurred_at],
        )?;
        Ok(())
    }

    pub fn get_audit(&self, id: &str) -> Result<Option<AuditRecord>, StorageError> {
        validate_id(id, "audit id")?;
        let stored = self
            .lock()?
            .query_row(
                "SELECT id,plan_id,account_id,event,details_nonce,details_ciphertext,occurred_at
             FROM audit WHERE id=?1",
                [id],
                |row| {
                    Ok((
                        AuditRecord {
                            id: row.get(0)?,
                            plan_id: row.get(1)?,
                            account_id: row.get(2)?,
                            event: row.get(3)?,
                            details: Value::Null,
                            occurred_at: row.get(6)?,
                        },
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )
            .optional()?;
        stored
            .map(|(mut record, nonce, ciphertext)| {
                record.details =
                    self.decrypt("audit", &record.id, "details", &nonce, &ciphertext)?;
                Ok(record)
            })
            .transpose()
    }

    pub fn list_audit(
        &self,
        account_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<AuditRecord>, StorageError> {
        if let Some(account_id) = account_id {
            validate_id(account_id, "account id")?;
        }
        validate_limit(limit)?;
        let stored = {
            let connection = self.lock()?;
            let mut statement = connection.prepare(
                "SELECT id,plan_id,account_id,event,details_nonce,details_ciphertext,occurred_at
                 FROM audit WHERE (?1 IS NULL OR account_id=?1) ORDER BY occurred_at DESC,id LIMIT ?2",
            )?;
            let rows = statement.query_map(params![account_id, limit], |row| {
                Ok((
                    AuditRecord {
                        id: row.get(0)?,
                        plan_id: row.get(1)?,
                        account_id: row.get(2)?,
                        event: row.get(3)?,
                        details: Value::Null,
                        occurred_at: row.get(6)?,
                    },
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            })?;
            collect_rows(rows)?
        };
        stored
            .into_iter()
            .map(|(mut record, nonce, ciphertext)| {
                record.details =
                    self.decrypt("audit", &record.id, "details", &nonce, &ciphertext)?;
                Ok(record)
            })
            .collect()
    }

    pub fn prune_audit_before(&self, occurred_before: i64) -> Result<usize, StorageError> {
        self.lock()?
            .execute(
                "DELETE FROM audit WHERE occurred_at < ?1",
                [occurred_before],
            )
            .map_err(StorageError::from)
    }

    pub fn upsert_recovery(&self, record: &RecoveryRecord) -> Result<(), StorageError> {
        validate_recovery(record)?;
        let (nonce, ciphertext) = self.encrypt("recovery", &record.id, "state", &record.state)?;
        self.lock()?.execute(
            "INSERT INTO recovery (id,account_id,kind,state_nonce,state_ciphertext,created_at,updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(id) DO UPDATE SET account_id=excluded.account_id,kind=excluded.kind,
               state_nonce=excluded.state_nonce,state_ciphertext=excluded.state_ciphertext,updated_at=excluded.updated_at",
            params![record.id,record.account_id,record.kind,nonce,ciphertext,record.created_at,record.updated_at],
        )?;
        Ok(())
    }

    pub fn get_recovery(&self, id: &str) -> Result<Option<RecoveryRecord>, StorageError> {
        validate_id(id, "recovery id")?;
        let stored = self.lock()?.query_row(
            "SELECT id,account_id,kind,state_nonce,state_ciphertext,created_at,updated_at FROM recovery WHERE id=?1",
            [id],
            |row| Ok((RecoveryRecord { id: row.get(0)?, account_id: row.get(1)?, kind: row.get(2)?, state: Value::Null, created_at: row.get(5)?, updated_at: row.get(6)? }, row.get::<_, Vec<u8>>(3)?, row.get::<_, Vec<u8>>(4)?)),
        ).optional()?;
        stored
            .map(|(mut record, nonce, ciphertext)| {
                record.state =
                    self.decrypt("recovery", &record.id, "state", &nonce, &ciphertext)?;
                Ok(record)
            })
            .transpose()
    }
    pub fn list_recovery(
        &self,
        account_id: Option<&str>,
    ) -> Result<Vec<RecoveryRecord>, StorageError> {
        if let Some(account_id) = account_id {
            validate_id(account_id, "account id")?;
        }
        let ids = {
            let connection = self.lock()?;
            let mut statement = connection.prepare(
                "SELECT id FROM recovery WHERE (?1 IS NULL OR account_id=?1)
                 ORDER BY updated_at DESC,id",
            )?;
            let rows = statement.query_map([account_id], |row| row.get::<_, String>(0))?;
            collect_rows(rows)?
        };
        ids.iter()
            .map(|id| self.get_recovery(id)?.ok_or(StorageError::CorruptData))
            .collect()
    }

    pub fn delete_recovery(&self, id: &str) -> Result<bool, StorageError> {
        validate_id(id, "recovery id")?;
        Ok(self
            .lock()?
            .execute("DELETE FROM recovery WHERE id=?1", [id])?
            == 1)
    }

    pub fn get_migration_checkpoint(
        &self,
        name: &str,
    ) -> Result<Option<MigrationCheckpointRecord>, StorageError> {
        validate_id(name, "migration name")?;
        self.lock()?
            .query_row(
                "SELECT name,source_hash,accounts,messages,skipped,completed_at
                 FROM migration_checkpoints WHERE name=?1",
                [name],
                |row| {
                    Ok(MigrationCheckpointRecord {
                        name: row.get(0)?,
                        source_hash: row.get(1)?,
                        accounts: row.get(2)?,
                        messages: row.get(3)?,
                        skipped: row.get(4)?,
                        completed_at: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(StorageError::from)
    }

    pub fn upsert_migration_checkpoint(
        &self,
        record: &MigrationCheckpointRecord,
    ) -> Result<(), StorageError> {
        validate_id(&record.name, "migration name")?;
        validate_text(&record.source_hash, MAX_SHORT_TEXT, "migration source hash")?;
        self.lock()?.execute(
            "INSERT INTO migration_checkpoints
               (name,source_hash,accounts,messages,skipped,completed_at)
             VALUES (?1,?2,?3,?4,?5,?6)
             ON CONFLICT(name) DO UPDATE SET source_hash=excluded.source_hash,
               accounts=excluded.accounts,messages=excluded.messages,
               skipped=excluded.skipped,completed_at=excluded.completed_at",
            params![
                record.name,
                record.source_hash,
                record.accounts,
                record.messages,
                record.skipped,
                record.completed_at
            ],
        )?;
        Ok(())
    }

    pub fn checkpoint(&self) -> Result<(), StorageError> {
        self.lock()?
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, StorageError> {
        self.connection
            .lock()
            .map_err(|_| StorageError::LockUnavailable)
    }

    fn encrypt<T: Serialize>(
        &self,
        table: &str,
        id: &str,
        field: &str,
        value: &T,
    ) -> Result<(Vec<u8>, Vec<u8>), StorageError> {
        let mut plaintext = Zeroizing::new(
            serde_json::to_vec(value)
                .map_err(|_| StorageError::InvalidInput("serialized value"))?,
        );
        if plaintext.len() > MAX_JSON_BYTES {
            return Err(StorageError::InvalidInput("serialized value length"));
        }
        let result = self.encrypt_bytes(table, id, field, plaintext.as_ref());
        plaintext.zeroize();
        result
    }

    fn decrypt<T: DeserializeOwned>(
        &self,
        table: &str,
        id: &str,
        field: &str,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<T, StorageError> {
        let plaintext = Zeroizing::new(self.decrypt_bytes(table, id, field, nonce, ciphertext)?);
        serde_json::from_slice(plaintext.as_ref()).map_err(|_| StorageError::CorruptData)
    }

    fn encrypt_bytes(
        &self,
        table: &str,
        id: &str,
        field: &str,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), StorageError> {
        let cipher = XChaCha20Poly1305::new(self.field_key.as_ref().into());
        let mut nonce = vec![0_u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let aad = associated_data(table, id, field);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| StorageError::Authentication)?;
        Ok((nonce, ciphertext))
    }

    fn decrypt_bytes(
        &self,
        table: &str,
        id: &str,
        field: &str,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, StorageError> {
        if nonce.len() != NONCE_LEN {
            return Err(StorageError::CorruptData);
        }
        let cipher = XChaCha20Poly1305::new(self.field_key.as_ref().into());
        let aad = associated_data(table, id, field);
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| StorageError::Authentication)
    }
}

fn initialize_schema(connection: &mut Connection) -> Result<(), StorageError> {
    let transaction = connection.transaction()?;
    let version: i64 = transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(StorageError::InvalidInput("database schema version"));
    }
    if version == 0 {
        create_schema(&transaction)?;
    } else {
        if version < 2 {
            create_migration_checkpoint_schema(&transaction)?;
        }
        if version < 3 {
            create_mailbox_sync_schema(&transaction, true)?;
        }
    }
    if version < SCHEMA_VERSION {
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    }
    transaction.commit()?;
    Ok(())
}

fn create_schema(transaction: &Transaction<'_>) -> Result<(), StorageError> {
    transaction.execute_batch(
        "CREATE TABLE accounts (
           id TEXT PRIMARY KEY, provider TEXT NOT NULL, address TEXT NOT NULL, display_name TEXT,
           created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, UNIQUE(provider,address));
         CREATE TABLE folders (
           id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
           remote_id TEXT NOT NULL, parent_id TEXT REFERENCES folders(id) ON DELETE SET NULL,
           name TEXT NOT NULL, role TEXT, unread_count INTEGER NOT NULL, total_count INTEGER NOT NULL,
           updated_at INTEGER NOT NULL, UNIQUE(account_id,remote_id));
         CREATE TABLE messages (
           id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
           folder_id TEXT REFERENCES folders(id) ON DELETE SET NULL, remote_id TEXT NOT NULL,
           thread_id TEXT, subject TEXT NOT NULL, sender TEXT NOT NULL, recipients TEXT NOT NULL,
           snippet TEXT NOT NULL, flags TEXT NOT NULL, sent_at INTEGER, received_at INTEGER NOT NULL,
           size_bytes INTEGER NOT NULL, body_nonce BLOB NOT NULL CHECK(length(body_nonce)=24),
           body_ciphertext BLOB NOT NULL, updated_at INTEGER NOT NULL, UNIQUE(account_id,remote_id));
         CREATE INDEX messages_account_received ON messages(account_id,received_at DESC);
         CREATE INDEX messages_folder_received ON messages(folder_id,received_at DESC);
         CREATE TABLE sync_cursors (
           account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, scope TEXT NOT NULL,
           cursor TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY(account_id,scope));
         CREATE TABLE attachments (
           id TEXT PRIMARY KEY, message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
           remote_id TEXT, filename TEXT NOT NULL, media_type TEXT NOT NULL, size_bytes INTEGER NOT NULL,
           content_id TEXT, content_nonce BLOB NOT NULL CHECK(length(content_nonce)=24),
           content_ciphertext BLOB NOT NULL, created_at INTEGER NOT NULL);
         CREATE INDEX attachments_message ON attachments(message_id);
         CREATE TABLE plans (
           id TEXT PRIMARY KEY, account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL,
           action TEXT NOT NULL, risk TEXT NOT NULL, status TEXT NOT NULL,
           payload_nonce BLOB NOT NULL CHECK(length(payload_nonce)=24), payload_ciphertext BLOB NOT NULL,
           created_at INTEGER NOT NULL, expires_at INTEGER, confirmed_at INTEGER);
         CREATE INDEX plans_status_created ON plans(status,created_at DESC);
         CREATE TABLE audit (
           sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
           plan_id TEXT REFERENCES plans(id) ON DELETE SET NULL,
           account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL, event TEXT NOT NULL,
           details_nonce BLOB NOT NULL CHECK(length(details_nonce)=24), details_ciphertext BLOB NOT NULL,
           occurred_at INTEGER NOT NULL);
         CREATE INDEX audit_account_occurred ON audit(account_id,occurred_at DESC);
         CREATE TABLE recovery (
           id TEXT PRIMARY KEY, account_id TEXT REFERENCES accounts(id) ON DELETE CASCADE,
           kind TEXT NOT NULL, state_nonce BLOB NOT NULL CHECK(length(state_nonce)=24),
           state_ciphertext BLOB NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
         CREATE VIRTUAL TABLE message_search USING fts5(
           message_id UNINDEXED, subject, sender, recipients, snippet,
           tokenize='unicode61 remove_diacritics 2');
         CREATE TRIGGER messages_search_insert AFTER INSERT ON messages BEGIN
           INSERT INTO message_search(message_id,subject,sender,recipients,snippet)
           VALUES(new.id,new.subject,new.sender,new.recipients,new.snippet);
         END;
         CREATE TRIGGER messages_search_update AFTER UPDATE OF subject,sender,recipients,snippet ON messages BEGIN
           DELETE FROM message_search WHERE message_id=old.id;
           INSERT INTO message_search(message_id,subject,sender,recipients,snippet)
           VALUES(new.id,new.subject,new.sender,new.recipients,new.snippet);
         END;
         CREATE TRIGGER messages_search_delete AFTER DELETE ON messages BEGIN
           DELETE FROM message_search WHERE message_id=old.id;
         END;",
    )?;
    create_migration_checkpoint_schema(transaction)?;
    create_mailbox_sync_schema(transaction, false)?;
    Ok(())
}

fn create_migration_checkpoint_schema(transaction: &Transaction<'_>) -> Result<(), StorageError> {
    transaction.execute_batch(
        "CREATE TABLE migration_checkpoints (
           name TEXT PRIMARY KEY, source_hash TEXT NOT NULL,
           accounts INTEGER NOT NULL, messages INTEGER NOT NULL, skipped INTEGER NOT NULL,
           completed_at INTEGER NOT NULL);",
    )?;
    Ok(())
}

fn create_mailbox_sync_schema(
    transaction: &Transaction<'_>,
    backfill_membership: bool,
) -> Result<(), StorageError> {
    transaction.execute_batch(
        "CREATE TABLE message_folders (
           message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
           folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
           PRIMARY KEY(message_id,folder_id));
         CREATE INDEX message_folders_folder ON message_folders(folder_id,message_id);
         CREATE TABLE sync_snapshot_seen (
           account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
           message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
           PRIMARY KEY(account_id,message_id));
         CREATE TABLE drafts (
           id TEXT PRIMARY KEY,
           account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
           remote_id TEXT NOT NULL,
           payload_nonce BLOB NOT NULL CHECK(length(payload_nonce)=24),
           payload_ciphertext BLOB NOT NULL,
           updated_at INTEGER NOT NULL,
           UNIQUE(account_id,remote_id));",
    )?;
    if backfill_membership {
        transaction.execute(
            "INSERT INTO message_folders(message_id,folder_id)
             SELECT id,folder_id FROM messages WHERE folder_id IS NOT NULL",
            [],
        )?;
    }
    Ok(())
}

fn apply_database_key(connection: &Connection, key: &[u8; 32]) -> Result<(), StorageError> {
    let mut encoded = Zeroizing::new(String::with_capacity(64));
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in key {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    let mut pragma_key = Zeroizing::new(String::with_capacity(67));
    pragma_key.push_str("x'");
    pragma_key.push_str(encoded.as_str());
    pragma_key.push('\'');
    connection.pragma_update(None, "key", pragma_key.as_str())?;
    encoded.zeroize();
    pragma_key.zeroize();
    Ok(())
}

fn derive_key(
    application_key: &[u8; 32],
    purpose: &[u8],
) -> Result<Zeroizing<[u8; 32]>, StorageError> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"fily-storage-key-derivation-v1"), application_key);
    let mut derived = Zeroizing::new([0_u8; 32]);
    hkdf.expand(purpose, derived.as_mut())
        .map_err(|_| StorageError::InvalidInput("key derivation purpose"))?;
    Ok(derived)
}

fn associated_data(table: &str, id: &str, field: &str) -> String {
    format!("fily:v1:{table}:{id}:{field}")
}

fn collect_rows<T>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>>,
) -> Result<Vec<T>, StorageError> {
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(StorageError::from)
}

fn validate_account(record: &AccountRecord) -> Result<(), StorageError> {
    validate_id(&record.id, "account id")?;
    validate_text(&record.provider, MAX_SHORT_TEXT, "provider")?;
    validate_text(&record.address, MAX_SHORT_TEXT, "account address")?;
    validate_optional_text(
        record.display_name.as_deref(),
        MAX_SHORT_TEXT,
        "display name",
    )
}

fn validate_folder(record: &FolderRecord) -> Result<(), StorageError> {
    validate_id(&record.id, "folder id")?;
    validate_id(&record.account_id, "account id")?;
    validate_opaque_id(
        &record.remote_id,
        MAX_REMOTE_FOLDER_ID_LEN,
        "remote folder id",
    )?;
    if let Some(parent) = &record.parent_id {
        validate_id(parent, "parent folder id")?;
        if parent == &record.id {
            return Err(StorageError::InvalidInput("parent folder id"));
        }
    }
    validate_text(&record.name, MAX_SHORT_TEXT, "folder name")?;
    validate_optional_text(record.role.as_deref(), MAX_SHORT_TEXT, "folder role")
}

fn validate_message(record: &MessageRecord) -> Result<(), StorageError> {
    validate_id(&record.id, "message id")?;
    validate_id(&record.account_id, "account id")?;
    validate_opaque_id(
        &record.remote_id,
        MAX_REMOTE_MESSAGE_ID_LEN,
        "remote message id",
    )?;
    if let Some(folder) = &record.folder_id {
        validate_id(folder, "folder id")?;
    }
    if let Some(thread) = &record.thread_id {
        validate_opaque_id(thread, MAX_REMOTE_MESSAGE_ID_LEN, "thread id")?;
    }
    validate_text_allow_empty(&record.subject, MAX_LONG_TEXT, "subject")?;
    validate_text(&record.sender, MAX_LONG_TEXT, "sender")?;
    validate_text_allow_empty(&record.recipients, MAX_LONG_TEXT, "recipients")?;
    validate_text_allow_empty(&record.snippet, MAX_LONG_TEXT, "snippet")?;
    validate_text_allow_empty(&record.flags, MAX_LONG_TEXT, "flags")?;
    if record.size_bytes > i64::MAX as u64 {
        return Err(StorageError::InvalidInput("message size"));
    }
    validate_optional_text(record.body.text.as_deref(), MAX_JSON_BYTES, "text body")?;
    validate_optional_text(record.body.html.as_deref(), MAX_JSON_BYTES, "HTML body")
}

fn validate_attachment(record: &AttachmentRecord) -> Result<(), StorageError> {
    validate_id(&record.id, "attachment id")?;
    validate_id(&record.message_id, "message id")?;
    if let Some(remote) = &record.remote_id {
        validate_opaque_id(remote, MAX_REMOTE_MESSAGE_ID_LEN, "remote attachment id")?;
    }
    validate_text(&record.filename, MAX_SHORT_TEXT, "attachment filename")?;
    validate_text(&record.media_type, MAX_SHORT_TEXT, "attachment media type")?;
    validate_optional_text(
        record.content_id.as_deref(),
        MAX_SHORT_TEXT,
        "attachment content id",
    )?;
    if record.content.len() > MAX_ATTACHMENT_BYTES
        || record.size_bytes != record.content.len() as u64
    {
        return Err(StorageError::InvalidInput("attachment size"));
    }
    Ok(())
}

fn validate_draft(record: &DraftRecord) -> Result<(), StorageError> {
    validate_id(&record.id, "draft id")?;
    validate_id(&record.account_id, "account id")?;
    validate_opaque_id(
        &record.remote_id,
        MAX_REMOTE_MESSAGE_ID_LEN,
        "remote draft id",
    )?;
    validate_json_size(&record.payload)
}

fn validate_plan(record: &PlanRecord) -> Result<(), StorageError> {
    validate_id(&record.id, "plan id")?;
    if let Some(account) = &record.account_id {
        validate_id(account, "account id")?;
    }
    validate_text(&record.action, MAX_SHORT_TEXT, "plan action")?;
    if !matches!(record.risk.as_str(), "low" | "medium" | "high") {
        return Err(StorageError::InvalidInput("plan risk"));
    }
    validate_plan_status(&record.status)?;
    validate_json_size(&record.payload)
}

fn validate_plan_status(status: &str) -> Result<(), StorageError> {
    if matches!(
        status,
        "proposed"
            | "approved"
            | "executing"
            | "completed"
            | "rejected"
            | "expired"
            | "cancelled"
            | "failed"
    ) {
        Ok(())
    } else {
        Err(StorageError::InvalidInput("plan status"))
    }
}

fn validate_audit(record: &AuditRecord) -> Result<(), StorageError> {
    validate_id(&record.id, "audit id")?;
    if let Some(plan) = &record.plan_id {
        validate_id(plan, "plan id")?;
    }
    if let Some(account) = &record.account_id {
        validate_id(account, "account id")?;
    }
    validate_text(&record.event, MAX_SHORT_TEXT, "audit event")?;
    validate_json_size(&record.details)
}

fn validate_recovery(record: &RecoveryRecord) -> Result<(), StorageError> {
    validate_id(&record.id, "recovery id")?;
    if let Some(account) = &record.account_id {
        validate_id(account, "account id")?;
    }
    validate_text(&record.kind, MAX_SHORT_TEXT, "recovery kind")?;
    validate_json_size(&record.state)
}

fn validate_json_size(value: &Value) -> Result<(), StorageError> {
    let encoded = Zeroizing::new(
        serde_json::to_vec(value).map_err(|_| StorageError::InvalidInput("JSON value"))?,
    );
    if encoded.len() > MAX_JSON_BYTES {
        Err(StorageError::InvalidInput("JSON value length"))
    } else {
        Ok(())
    }
}

fn validate_id(value: &str, field: &'static str) -> Result<(), StorageError> {
    validate_opaque_id(value, MAX_ID_LEN, field)
}

fn validate_opaque_id(value: &str, max: usize, field: &'static str) -> Result<(), StorageError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        Err(StorageError::InvalidInput(field))
    } else {
        Ok(())
    }
}

fn validate_text(value: &str, max: usize, field: &'static str) -> Result<(), StorageError> {
    if value.is_empty() {
        return Err(StorageError::InvalidInput(field));
    }
    validate_text_allow_empty(value, max, field)
}

fn validate_text_allow_empty(
    value: &str,
    max: usize,
    field: &'static str,
) -> Result<(), StorageError> {
    if value.len() > max || value.contains('\0') {
        Err(StorageError::InvalidInput(field))
    } else {
        Ok(())
    }
}

fn validate_optional_text(
    value: Option<&str>,
    max: usize,
    field: &'static str,
) -> Result<(), StorageError> {
    value.map_or(Ok(()), |value| validate_text_allow_empty(value, max, field))
}

fn validate_limit(limit: u32) -> Result<(), StorageError> {
    if limit == 0 || limit > MAX_SEARCH_RESULTS {
        Err(StorageError::InvalidInput("result limit"))
    } else {
        Ok(())
    }
}

fn fts_query(query: &str) -> Result<String, StorageError> {
    if query.is_empty() || query.len() > MAX_SHORT_TEXT || query.contains('\0') {
        return Err(StorageError::InvalidInput("search query"));
    }
    let terms: Vec<String> = query
        .split_whitespace()
        .map(|term| format!("\"{}\"", term.replace('"', "\"\"")))
        .collect();
    if terms.is_empty() {
        Err(StorageError::InvalidInput("search query"))
    } else {
        Ok(terms.join(" AND "))
    }
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(StorageError::Filesystem)
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> Result<(), StorageError> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(StorageError::Filesystem)
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> Result<(), StorageError> {
    Ok(())
}
