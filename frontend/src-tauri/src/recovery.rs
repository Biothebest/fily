//! Recovery metadata and single-use undo authorization.
//!
//! Recovery records contain only the inverse routing metadata needed by a
//! provider. Message bodies, credentials, and unrestricted paths do not belong
//! in this module.

use crate::agent::{sha256_hex, validate_opaque_id, ResourceVersion};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_RECOVERY_ITEMS: usize = 1_000;
const MAX_CONTAINERS_PER_ITEM: usize = 64;
const MAX_RECOVERY_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
static RECOVERY_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryOperation {
    Move,
    Archive,
    Trash,
}

/// Provider-neutral inverse metadata. Container IDs are opaque folder/label
/// IDs, never filesystem paths. `version_after_action` protects undo from
/// overwriting a change made after the original operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryItem {
    pub resource_id: String,
    pub original_container_ids: Vec<String>,
    pub resulting_container_ids: Vec<String>,
    pub version_after_action: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryState {
    Available,
    UndoInProgress,
    Undone,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryRecord {
    pub recovery_id: String,
    pub plan_id: String,
    pub account_id: String,
    pub operation: RecoveryOperation,
    pub items: Vec<RecoveryItem>,
    pub created_at_ms: u64,
    pub undo_until_ms: u64,
    pub integrity_hash: String,
    pub state: RecoveryState,
    pub undone_at_ms: Option<u64>,
}

impl RecoveryRecord {
    pub fn new(
        plan_id: String,
        account_id: String,
        operation: RecoveryOperation,
        items: Vec<RecoveryItem>,
        created_at_ms: u64,
        undo_until_ms: u64,
    ) -> Result<Self, RecoveryError> {
        validate_opaque_id(&plan_id)
            .map_err(|_| RecoveryError::InvalidMetadata("plan ID is invalid"))?;
        validate_opaque_id(&account_id)
            .map_err(|_| RecoveryError::InvalidMetadata("account ID is invalid"))?;
        validate_items(&items)?;
        if undo_until_ms <= created_at_ms
            || undo_until_ms - created_at_ms > MAX_RECOVERY_RETENTION_MS
        {
            return Err(RecoveryError::InvalidMetadata(
                "undo expiration is out of range",
            ));
        }

        let nonce = RECOVERY_NONCE.fetch_add(1, Ordering::Relaxed);
        let id_bytes = serde_json::to_vec(&(
            &plan_id,
            &account_id,
            operation,
            &items,
            created_at_ms,
            nonce,
        ))
        .map_err(|_| RecoveryError::InvalidMetadata("recovery record cannot be encoded"))?;
        let recovery_id = sha256_hex(&id_bytes);
        let mut record = Self {
            recovery_id,
            plan_id,
            account_id,
            operation,
            items,
            created_at_ms,
            undo_until_ms,
            integrity_hash: String::new(),
            state: RecoveryState::Available,
            undone_at_ms: None,
        };
        record.integrity_hash = recovery_integrity_hash(&record)?;
        Ok(record)
    }

    pub fn expected_versions(&self) -> Vec<ResourceVersion> {
        self.items
            .iter()
            .map(|item| ResourceVersion {
                resource_id: item.resource_id.clone(),
                version: item.version_after_action.clone(),
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum UndoAvailability {
    Available { undo_until_ms: u64 },
    Expired,
    VersionDrift { resource_id: String },
    InProgress,
    AlreadyUndone,
    NotFound,
    IntegrityFailure,
}

/// Provider code receives this only after recovery integrity, expiry, state,
/// and post-action versions are checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoAuthorization {
    pub recovery: RecoveryRecord,
    pub authorized_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryError {
    InvalidMetadata(&'static str),
    DuplicateRecord,
    NotFound,
    Expired,
    IntegrityMismatch,
    UndoNotAvailable,
    VersionDrift { resource_id: String },
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMetadata(message) => write!(f, "invalid recovery metadata: {message}"),
            Self::DuplicateRecord => f.write_str("recovery record already exists"),
            Self::NotFound => f.write_str("recovery record was not found"),
            Self::Expired => f.write_str("undo period has expired"),
            Self::IntegrityMismatch => f.write_str("recovery integrity check failed"),
            Self::UndoNotAvailable => f.write_str("undo is not available"),
            Self::VersionDrift { resource_id } => {
                write!(
                    f,
                    "resource changed after the recoverable operation: {resource_id}"
                )
            }
        }
    }
}

impl std::error::Error for RecoveryError {}

/// Owns canonical recovery records and prevents concurrent or repeated undo.
#[derive(Debug, Default)]
pub struct RecoveryStore {
    records: HashMap<String, RecoveryRecord>,
}

impl RecoveryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_records(records: Vec<RecoveryRecord>) -> Result<Self, RecoveryError> {
        let mut store = Self::new();
        for record in records {
            store.insert(record)?;
        }
        Ok(store)
    }

    pub fn records(&self) -> Vec<RecoveryRecord> {
        let mut records = self.records.values().cloned().collect::<Vec<_>>();
        records.sort_by(|left, right| {
            left.created_at_ms
                .cmp(&right.created_at_ms)
                .then_with(|| left.recovery_id.cmp(&right.recovery_id))
        });
        records
    }

    pub fn insert(&mut self, record: RecoveryRecord) -> Result<(), RecoveryError> {
        validate_record(&record)?;
        if self.records.contains_key(&record.recovery_id) {
            return Err(RecoveryError::DuplicateRecord);
        }
        self.records.insert(record.recovery_id.clone(), record);
        Ok(())
    }

    pub fn record(&self, recovery_id: &str) -> Option<RecoveryRecord> {
        self.records.get(recovery_id).cloned()
    }

    pub fn undo_availability(
        &self,
        recovery_id: &str,
        current_versions: &[ResourceVersion],
        now_ms: u64,
    ) -> UndoAvailability {
        let Some(record) = self.records.get(recovery_id) else {
            return UndoAvailability::NotFound;
        };
        if validate_record(record).is_err() {
            return UndoAvailability::IntegrityFailure;
        }
        match record.state {
            RecoveryState::UndoInProgress => return UndoAvailability::InProgress,
            RecoveryState::Undone => return UndoAvailability::AlreadyUndone,
            RecoveryState::Expired => return UndoAvailability::Expired,
            RecoveryState::Available => {}
        }
        if now_ms >= record.undo_until_ms {
            return UndoAvailability::Expired;
        }
        match verify_versions(&record.items, current_versions) {
            Ok(()) => UndoAvailability::Available {
                undo_until_ms: record.undo_until_ms,
            },
            Err(RecoveryError::VersionDrift { resource_id }) => {
                UndoAvailability::VersionDrift { resource_id }
            }
            Err(_) => UndoAvailability::IntegrityFailure,
        }
    }

    /// Reserves a recovery record for one undo attempt. Provider code must call
    /// `finish_undo` after attempting the inverse operation.
    pub fn authorize_undo(
        &mut self,
        recovery_id: &str,
        current_versions: &[ResourceVersion],
        now_ms: u64,
    ) -> Result<UndoAuthorization, RecoveryError> {
        match self.undo_availability(recovery_id, current_versions, now_ms) {
            UndoAvailability::Available { .. } => {}
            UndoAvailability::Expired => {
                if let Some(record) = self.records.get_mut(recovery_id) {
                    record.state = RecoveryState::Expired;
                }
                return Err(RecoveryError::Expired);
            }
            UndoAvailability::VersionDrift { resource_id } => {
                return Err(RecoveryError::VersionDrift { resource_id });
            }
            UndoAvailability::IntegrityFailure => return Err(RecoveryError::IntegrityMismatch),
            UndoAvailability::NotFound => return Err(RecoveryError::NotFound),
            UndoAvailability::InProgress | UndoAvailability::AlreadyUndone => {
                return Err(RecoveryError::UndoNotAvailable);
            }
        }

        let record = self
            .records
            .get_mut(recovery_id)
            .ok_or(RecoveryError::NotFound)?;
        record.state = RecoveryState::UndoInProgress;
        Ok(UndoAuthorization {
            recovery: record.clone(),
            authorized_at_ms: now_ms,
        })
    }

    /// Completes the reserved attempt. A failed attempt becomes available again
    /// only while its retention window remains open.
    pub fn finish_undo(
        &mut self,
        recovery_id: &str,
        succeeded: bool,
        now_ms: u64,
    ) -> Result<RecoveryRecord, RecoveryError> {
        let record = self
            .records
            .get_mut(recovery_id)
            .ok_or(RecoveryError::NotFound)?;
        if record.state != RecoveryState::UndoInProgress {
            return Err(RecoveryError::UndoNotAvailable);
        }
        if succeeded {
            record.state = RecoveryState::Undone;
            record.undone_at_ms = Some(now_ms);
        } else if now_ms < record.undo_until_ms {
            record.state = RecoveryState::Available;
        } else {
            record.state = RecoveryState::Expired;
        }
        Ok(record.clone())
    }
}

#[derive(Serialize)]
struct RecoveryHashMaterial<'a> {
    recovery_id: &'a str,
    plan_id: &'a str,
    account_id: &'a str,
    operation: RecoveryOperation,
    items: &'a [RecoveryItem],
    created_at_ms: u64,
    undo_until_ms: u64,
}

fn recovery_integrity_hash(record: &RecoveryRecord) -> Result<String, RecoveryError> {
    let bytes = serde_json::to_vec(&RecoveryHashMaterial {
        recovery_id: &record.recovery_id,
        plan_id: &record.plan_id,
        account_id: &record.account_id,
        operation: record.operation,
        items: &record.items,
        created_at_ms: record.created_at_ms,
        undo_until_ms: record.undo_until_ms,
    })
    .map_err(|_| RecoveryError::InvalidMetadata("recovery record cannot be encoded"))?;
    Ok(sha256_hex(&bytes))
}

fn validate_record(record: &RecoveryRecord) -> Result<(), RecoveryError> {
    validate_opaque_id(&record.recovery_id)
        .map_err(|_| RecoveryError::InvalidMetadata("recovery ID is invalid"))?;
    validate_opaque_id(&record.plan_id)
        .map_err(|_| RecoveryError::InvalidMetadata("plan ID is invalid"))?;
    validate_opaque_id(&record.account_id)
        .map_err(|_| RecoveryError::InvalidMetadata("account ID is invalid"))?;
    validate_items(&record.items)?;
    if record.undo_until_ms <= record.created_at_ms
        || record.undo_until_ms - record.created_at_ms > MAX_RECOVERY_RETENTION_MS
    {
        return Err(RecoveryError::InvalidMetadata(
            "undo expiration is out of range",
        ));
    }
    match (record.state, record.undone_at_ms) {
        (
            RecoveryState::Available | RecoveryState::UndoInProgress | RecoveryState::Expired,
            None,
        ) => {}
        (RecoveryState::Undone, Some(undone_at_ms)) if undone_at_ms >= record.created_at_ms => {}
        _ => return Err(RecoveryError::IntegrityMismatch),
    }
    let expected = recovery_integrity_hash(record)?;
    if expected != record.integrity_hash {
        return Err(RecoveryError::IntegrityMismatch);
    }
    Ok(())
}

fn validate_items(items: &[RecoveryItem]) -> Result<(), RecoveryError> {
    if items.is_empty() || items.len() > MAX_RECOVERY_ITEMS {
        return Err(RecoveryError::InvalidMetadata(
            "recovery item count is out of range",
        ));
    }
    let mut resources = BTreeSet::new();
    for item in items {
        validate_opaque_id(&item.resource_id)
            .map_err(|_| RecoveryError::InvalidMetadata("resource ID is invalid"))?;
        if !resources.insert(item.resource_id.as_str()) {
            return Err(RecoveryError::InvalidMetadata(
                "resource IDs must be unique",
            ));
        }
        if item.version_after_action.is_empty()
            || item.version_after_action.len() > 128
            || item
                .version_after_action
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(RecoveryError::InvalidMetadata(
                "resource version is invalid",
            ));
        }
        if item.original_container_ids.len() > MAX_CONTAINERS_PER_ITEM
            || item.resulting_container_ids.len() > MAX_CONTAINERS_PER_ITEM
        {
            return Err(RecoveryError::InvalidMetadata(
                "container count is out of range",
            ));
        }
        for container_id in item
            .original_container_ids
            .iter()
            .chain(&item.resulting_container_ids)
        {
            validate_opaque_id(container_id)
                .map_err(|_| RecoveryError::InvalidMetadata("container ID is invalid"))?;
        }
    }
    Ok(())
}

fn verify_versions(
    expected: &[RecoveryItem],
    current: &[ResourceVersion],
) -> Result<(), RecoveryError> {
    if expected.len() != current.len() {
        return Err(RecoveryError::VersionDrift {
            resource_id: "resource_set".to_owned(),
        });
    }
    let mut versions = HashMap::with_capacity(current.len());
    for resource in current {
        validate_opaque_id(&resource.resource_id)
            .map_err(|_| RecoveryError::InvalidMetadata("resource ID is invalid"))?;
        if versions
            .insert(resource.resource_id.as_str(), resource.version.as_str())
            .is_some()
        {
            return Err(RecoveryError::InvalidMetadata(
                "current resource IDs must be unique",
            ));
        }
    }
    for item in expected {
        if versions.get(item.resource_id.as_str()).copied()
            != Some(item.version_after_action.as_str())
        {
            return Err(RecoveryError::VersionDrift {
                resource_id: item.resource_id.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> RecoveryRecord {
        RecoveryRecord::new(
            "plan-1".to_owned(),
            "account-1".to_owned(),
            RecoveryOperation::Move,
            vec![RecoveryItem {
                resource_id: "message-1".to_owned(),
                original_container_ids: vec!["inbox".to_owned()],
                resulting_container_ids: vec!["archive".to_owned()],
                version_after_action: "v2".to_owned(),
            }],
            100,
            1_000,
        )
        .unwrap()
    }

    #[test]
    fn undo_is_available_only_for_matching_post_action_version() {
        let record = record();
        let id = record.recovery_id.clone();
        let mut store = RecoveryStore::new();
        store.insert(record).unwrap();

        assert!(matches!(
            store.undo_availability(
                &id,
                &[ResourceVersion {
                    resource_id: "message-1".to_owned(),
                    version: "v3".to_owned(),
                }],
                200,
            ),
            UndoAvailability::VersionDrift { .. }
        ));

        let authorization = store
            .authorize_undo(
                &id,
                &[ResourceVersion {
                    resource_id: "message-1".to_owned(),
                    version: "v2".to_owned(),
                }],
                200,
            )
            .unwrap();
        assert_eq!(authorization.recovery.recovery_id, id);
        store.finish_undo(&id, true, 201).unwrap();
        assert_eq!(
            store.undo_availability(&id, &[], 202),
            UndoAvailability::AlreadyUndone
        );
    }

    #[test]
    fn expired_and_tampered_recovery_cannot_be_used() {
        let expired = record();
        let id = expired.recovery_id.clone();
        let versions = expired.expected_versions();
        let mut store = RecoveryStore::new();
        store.insert(expired).unwrap();
        assert_eq!(
            store.authorize_undo(&id, &versions, 1_000),
            Err(RecoveryError::Expired)
        );

        let mut changed = record();
        changed.items[0].version_after_action = "attacker-version".to_owned();
        assert_eq!(
            RecoveryStore::new().insert(changed),
            Err(RecoveryError::IntegrityMismatch)
        );
    }
}
