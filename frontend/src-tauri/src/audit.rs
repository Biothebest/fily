//! Append-only, privacy-conscious security audit records.
//!
//! Audit payloads are deliberately closed and metadata-only: there is no field
//! capable of accepting message bodies, draft contents, credentials, tokens,
//! filesystem paths, or provider error text.

use crate::agent::{sha256_hex, validate_opaque_id, PermissionLevel};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditActor {
    User,
    Agent,
    System,
    Provider,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    PlanCreated,
    PlanApproved,
    PlanRejected,
    ExecutionAuthorized,
    ExecutionSucceeded,
    ExecutionFailed,
    PermissionDenied,
    RuleChanged,
    RecoveryCreated,
    UndoAuthorized,
    UndoSucceeded,
    UndoFailed,
    ProviderConnected,
    ProviderDisconnected,
    SyncCompleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Pending,
    Succeeded,
    Denied,
    Failed,
}

/// The only accepted audit payload. Counts and opaque identifiers provide
/// accountability without copying content into a long-lived log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub kind: AuditKind,
    pub actor: AuditActor,
    pub outcome: AuditOutcome,
    pub permission: Option<PermissionLevel>,
    pub account_id: Option<String>,
    pub plan_id: Option<String>,
    pub recovery_id: Option<String>,
    pub resource_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub event_id: String,
    pub sequence: u64,
    pub occurred_at_ms: u64,
    pub event: AuditEvent,
    /// Hash of the previous entry, or the SHA-256 empty digest for the first.
    pub previous_hash: String,
    /// Hash of this entry and `previous_hash`; makes removal/reordering visible.
    pub entry_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    InvalidMetadata(&'static str),
    InvalidChain { sequence: u64 },
    SequenceOverflow,
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMetadata(message) => write!(f, "invalid audit metadata: {message}"),
            Self::InvalidChain { sequence } => {
                write!(f, "audit integrity check failed at sequence {sequence}")
            }
            Self::SequenceOverflow => f.write_str("audit sequence is exhausted"),
        }
    }
}

impl std::error::Error for AuditError {}

/// An append-only ledger. No API exposes mutable entries or supports deletion.
#[derive(Debug, Clone, Default)]
pub struct AuditLedger {
    entries: Vec<AuditEntry>,
}

impl AuditLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Restores persisted entries only after validating the complete hash chain.
    pub fn from_entries(entries: Vec<AuditEntry>) -> Result<Self, AuditError> {
        let ledger = Self { entries };
        ledger.verify_integrity()?;
        Ok(ledger)
    }

    pub fn append(
        &mut self,
        event: AuditEvent,
        occurred_at_ms: u64,
    ) -> Result<AuditEntry, AuditError> {
        validate_event(&event)?;
        if self
            .entries
            .last()
            .is_some_and(|entry| occurred_at_ms < entry.occurred_at_ms)
        {
            return Err(AuditError::InvalidMetadata(
                "event timestamp moves backwards",
            ));
        }
        let sequence = self.entries.last().map_or(Ok(1_u64), |entry| {
            entry
                .sequence
                .checked_add(1)
                .ok_or(AuditError::SequenceOverflow)
        })?;
        let previous_hash = self
            .entries
            .last()
            .map(|entry| entry.entry_hash.clone())
            .unwrap_or_else(|| sha256_hex(&[]));
        let entry_hash = calculate_hash(sequence, occurred_at_ms, &event, &previous_hash)?;
        let event_id = sha256_hex(
            serde_json::to_string(&(sequence, occurred_at_ms, &entry_hash))
                .map_err(|_| AuditError::InvalidMetadata("event cannot be encoded"))?
                .as_bytes(),
        );
        let entry = AuditEntry {
            event_id,
            sequence,
            occurred_at_ms,
            event,
            previous_hash,
            entry_hash,
        };
        self.entries.push(entry.clone());
        Ok(entry)
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    pub fn verify_integrity(&self) -> Result<(), AuditError> {
        let mut previous_hash = sha256_hex(&[]);
        let mut previous_time = None;
        for (index, entry) in self.entries.iter().enumerate() {
            let expected_sequence = (index as u64)
                .checked_add(1)
                .ok_or(AuditError::SequenceOverflow)?;
            let expected_hash = calculate_hash(
                entry.sequence,
                entry.occurred_at_ms,
                &entry.event,
                &entry.previous_hash,
            )?;
            let expected_event_id = sha256_hex(
                serde_json::to_string(&(entry.sequence, entry.occurred_at_ms, &entry.entry_hash))
                    .map_err(|_| AuditError::InvalidMetadata("event cannot be encoded"))?
                    .as_bytes(),
            );
            let timestamp_moves_backwards =
                previous_time.is_some_and(|time| entry.occurred_at_ms < time);
            if entry.sequence != expected_sequence
                || entry.previous_hash != previous_hash
                || entry.entry_hash != expected_hash
                || entry.event_id != expected_event_id
                || timestamp_moves_backwards
            {
                return Err(AuditError::InvalidChain {
                    sequence: entry.sequence,
                });
            }
            validate_event(&entry.event)?;
            previous_hash.clone_from(&entry.entry_hash);
            previous_time = Some(entry.occurred_at_ms);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct AuditHashMaterial<'a> {
    sequence: u64,
    occurred_at_ms: u64,
    event: &'a AuditEvent,
    previous_hash: &'a str,
}

fn calculate_hash(
    sequence: u64,
    occurred_at_ms: u64,
    event: &AuditEvent,
    previous_hash: &str,
) -> Result<String, AuditError> {
    let bytes = serde_json::to_vec(&AuditHashMaterial {
        sequence,
        occurred_at_ms,
        event,
        previous_hash,
    })
    .map_err(|_| AuditError::InvalidMetadata("event cannot be encoded"))?;
    Ok(sha256_hex(&bytes))
}

fn validate_event(event: &AuditEvent) -> Result<(), AuditError> {
    for id in [
        event.account_id.as_deref(),
        event.plan_id.as_deref(),
        event.recovery_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_opaque_id(id).map_err(|_| AuditError::InvalidMetadata("opaque ID is invalid"))?;
    }
    if event.resource_count > 1_000_000 {
        return Err(AuditError::InvalidMetadata(
            "resource count is out of range",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> AuditEvent {
        AuditEvent {
            kind: AuditKind::ExecutionSucceeded,
            actor: AuditActor::Agent,
            outcome: AuditOutcome::Succeeded,
            permission: Some(PermissionLevel::Move),
            account_id: Some("account-1".to_owned()),
            plan_id: Some("plan-1".to_owned()),
            recovery_id: Some("recovery-1".to_owned()),
            resource_count: 2,
        }
    }

    #[test]
    fn audit_schema_contains_metadata_only() {
        let encoded = serde_json::to_string(&event()).unwrap();
        for forbidden in ["body", "secret", "token", "password", "path", "content"] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[test]
    fn ledger_is_chained_and_detects_changes() {
        let mut ledger = AuditLedger::new();
        ledger.append(event(), 10).unwrap();
        ledger.append(event(), 20).unwrap();
        assert!(ledger.verify_integrity().is_ok());

        let mut persisted = ledger.entries().to_vec();
        persisted[0].event.resource_count = 99;
        assert!(matches!(
            AuditLedger::from_entries(persisted),
            Err(AuditError::InvalidChain { .. })
        ));
    }
}
