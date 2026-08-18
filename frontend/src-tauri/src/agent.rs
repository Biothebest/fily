//! Approval-first authorization for agent actions.
//!
//! Plans are immutable once proposed. The trusted core stores the canonical
//! copy and only executes a plan after its integrity hash, approval, expiry,
//! and every affected resource version have been checked.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

const DEFAULT_MAX_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
const MAX_AFFECTED_RESOURCES: usize = 1_000;
const MAX_REASON_BYTES: usize = 2_000;
const MAX_PREVIEW_BYTES: usize = 4_000;
const MAX_PREVIEW_CHANGES: usize = 1_000;
static PLAN_NONCE: AtomicU64 = AtomicU64::new(1);

/// Capabilities are explicit. They are never inferred from prompt text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionLevel {
    Read,
    Organize,
    Draft,
    Send,
    Move,
    Delete,
}

/// The concrete operation determines the capability a plan must hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanAction {
    Read,
    Organize,
    CreateDraft,
    UpdateDraft,
    Send,
    Move,
    Archive,
    Trash,
    Delete,
    Disconnect,
    CreateRule,
    UpdateRule,
    DeleteRule,
}

impl PlanAction {
    pub const fn required_permission(self) -> PermissionLevel {
        match self {
            Self::Read => PermissionLevel::Read,
            Self::Organize => PermissionLevel::Organize,
            Self::CreateDraft | Self::UpdateDraft => PermissionLevel::Draft,
            Self::Send => PermissionLevel::Send,
            Self::Move | Self::Archive => PermissionLevel::Move,
            Self::Trash | Self::Delete | Self::Disconnect => PermissionLevel::Delete,
            Self::CreateRule | Self::UpdateRule | Self::DeleteRule => PermissionLevel::Organize,
        }
    }

    pub const fn is_rule_change(self) -> bool {
        matches!(self, Self::CreateRule | Self::UpdateRule | Self::DeleteRule)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceVersion {
    pub resource_id: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviewChange {
    pub resource_id: String,
    /// A bounded, presentation-only description such as "Inbox -> Archive".
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanPreview {
    pub summary: String,
    pub affected_count: u32,
    pub changes: Vec<PreviewChange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanRequest {
    pub account_id: String,
    pub action: PlanAction,
    pub affected: Vec<ResourceVersion>,
    pub reason: String,
    pub preview: PlanPreview,
    pub expires_in_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanState {
    PendingApproval,
    Approved,
    Rejected,
    Executed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionPlan {
    pub plan_id: String,
    pub account_id: String,
    pub action: PlanAction,
    pub permission: PermissionLevel,
    pub affected: Vec<ResourceVersion>,
    pub reason: String,
    pub preview: PlanPreview,
    pub is_bulk: bool,
    pub is_rule_change: bool,
    pub requires_confirmation: bool,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub integrity_hash: String,
    pub state: PlanState,
    pub approved_at_ms: Option<u64>,
    pub explicitly_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanApproval {
    pub plan_id: String,
    pub integrity_hash: String,
    /// Must be true for send, delete, bulk, and rule-change plans.
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub plan_id: String,
    pub integrity_hash: String,
    pub current_versions: Vec<ResourceVersion>,
}

/// Returned only after all authorization checks pass. Provider code should
/// accept this value rather than a raw UI request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionAuthorization {
    pub plan: ActionPlan,
    pub authorized_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentError {
    InvalidInput(&'static str),
    PermissionDenied(PermissionLevel),
    PlanNotFound,
    DuplicatePlan,
    PlanExpired,
    PlanNotPending,
    PlanNotApproved,
    ConfirmationRequired,
    IntegrityMismatch,
    VersionDrift { resource_id: String },
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(f, "invalid plan: {message}"),
            Self::PermissionDenied(permission) => {
                write!(f, "agent does not have {permission:?} permission")
            }
            Self::PlanNotFound => f.write_str("plan was not found"),
            Self::DuplicatePlan => f.write_str("plan already exists"),
            Self::PlanExpired => f.write_str("plan has expired"),
            Self::PlanNotPending => f.write_str("plan is not pending approval"),
            Self::PlanNotApproved => f.write_str("plan has not been approved"),
            Self::ConfirmationRequired => f.write_str("explicit confirmation is required"),
            Self::IntegrityMismatch => f.write_str("plan integrity check failed"),
            Self::VersionDrift { resource_id } => {
                write!(f, "resource version changed: {resource_id}")
            }
        }
    }
}

impl std::error::Error for AgentError {}

/// In-memory authorization state. Its persistence owner should serialize the
/// returned plans and approvals in the encrypted database.
pub struct AgentPolicy {
    allowed: BTreeSet<PermissionLevel>,
    max_ttl_ms: u64,
    plans: HashMap<String, ActionPlan>,
}

impl AgentPolicy {
    pub fn new(
        allowed: impl IntoIterator<Item = PermissionLevel>,
        max_ttl_ms: u64,
    ) -> Result<Self, AgentError> {
        if max_ttl_ms == 0 || max_ttl_ms > DEFAULT_MAX_TTL_MS {
            return Err(AgentError::InvalidInput(
                "maximum expiration is out of range",
            ));
        }
        Ok(Self {
            allowed: allowed.into_iter().collect(),
            max_ttl_ms,
            plans: HashMap::new(),
        })
    }

    pub fn read_only() -> Self {
        Self::new([PermissionLevel::Read], DEFAULT_MAX_TTL_MS)
            .expect("the built-in policy expiration is valid")
    }

    pub fn permits(&self, permission: PermissionLevel) -> bool {
        self.allowed.contains(&permission)
    }

    /// Restores a canonical plan from encrypted persistence. Derived security
    /// fields and the integrity digest are revalidated before it becomes
    /// executable.
    pub fn restore_plan(&mut self, plan: ActionPlan) -> Result<(), AgentError> {
        validate_restored_plan(&plan, self.max_ttl_ms)?;
        if self.plans.contains_key(&plan.plan_id) {
            return Err(AgentError::DuplicatePlan);
        }
        self.plans.insert(plan.plan_id.clone(), plan);
        Ok(())
    }

    pub fn plans(&self) -> Vec<ActionPlan> {
        let mut plans = self.plans.values().cloned().collect::<Vec<_>>();
        plans.sort_by(|left, right| {
            left.created_at_ms
                .cmp(&right.created_at_ms)
                .then_with(|| left.plan_id.cmp(&right.plan_id))
        });
        plans
    }

    pub fn create_plan(
        &mut self,
        request: PlanRequest,
        now_ms: u64,
    ) -> Result<ActionPlan, AgentError> {
        validate_request(&request, self.max_ttl_ms)?;
        let permission = request.action.required_permission();
        if !self.permits(permission) {
            return Err(AgentError::PermissionDenied(permission));
        }

        let expires_at_ms = now_ms
            .checked_add(request.expires_in_ms)
            .ok_or(AgentError::InvalidInput("expiration overflows"))?;
        let is_bulk = request.affected.len() > 1;
        let is_rule_change = request.action.is_rule_change();
        let requires_confirmation =
            matches!(permission, PermissionLevel::Send | PermissionLevel::Delete)
                || is_bulk
                || is_rule_change;
        let nonce = PLAN_NONCE.fetch_add(1, Ordering::Relaxed);
        let id_material = serde_json::to_vec(&(
            &request.account_id,
            request.action,
            &request.affected,
            now_ms,
            nonce,
        ))
        .map_err(|_| AgentError::InvalidInput("plan cannot be encoded"))?;
        let plan_id = sha256_hex(&id_material);

        let mut plan = ActionPlan {
            plan_id: plan_id.clone(),
            account_id: request.account_id,
            action: request.action,
            permission,
            affected: request.affected,
            reason: request.reason,
            preview: request.preview,
            is_bulk,
            is_rule_change,
            requires_confirmation,
            created_at_ms: now_ms,
            expires_at_ms,
            integrity_hash: String::new(),
            state: PlanState::PendingApproval,
            approved_at_ms: None,
            explicitly_confirmed: false,
        };
        plan.integrity_hash = plan_integrity_hash(&plan)?;
        self.plans.insert(plan_id, plan.clone());
        Ok(plan)
    }

    pub fn plan(&self, plan_id: &str) -> Option<ActionPlan> {
        self.plans.get(plan_id).cloned()
    }

    pub fn approve_plan(
        &mut self,
        approval: PlanApproval,
        now_ms: u64,
    ) -> Result<ActionPlan, AgentError> {
        validate_opaque_id(&approval.plan_id)?;
        let permission = self
            .plans
            .get(&approval.plan_id)
            .ok_or(AgentError::PlanNotFound)?
            .permission;
        if !self.permits(permission) {
            return Err(AgentError::PermissionDenied(permission));
        }
        let plan = self
            .plans
            .get_mut(&approval.plan_id)
            .ok_or(AgentError::PlanNotFound)?;
        verify_stored_integrity(plan, &approval.integrity_hash)?;
        if now_ms >= plan.expires_at_ms {
            return Err(AgentError::PlanExpired);
        }
        if plan.state != PlanState::PendingApproval {
            return Err(AgentError::PlanNotPending);
        }
        if plan.requires_confirmation && !approval.confirmed {
            return Err(AgentError::ConfirmationRequired);
        }
        plan.state = PlanState::Approved;
        plan.approved_at_ms = Some(now_ms);
        plan.explicitly_confirmed = approval.confirmed;
        Ok(plan.clone())
    }

    pub fn reject_plan(&mut self, plan_id: &str, now_ms: u64) -> Result<ActionPlan, AgentError> {
        validate_opaque_id(plan_id)?;
        let plan = self
            .plans
            .get_mut(plan_id)
            .ok_or(AgentError::PlanNotFound)?;
        if now_ms >= plan.expires_at_ms {
            return Err(AgentError::PlanExpired);
        }
        if plan.state != PlanState::PendingApproval {
            return Err(AgentError::PlanNotPending);
        }
        plan.state = PlanState::Rejected;
        Ok(plan.clone())
    }

    /// Atomically validates and consumes an approved plan. A successful call
    /// marks the stored plan executed so an approval cannot be replayed.
    pub fn authorize_execution(
        &mut self,
        request: ExecutionRequest,
        now_ms: u64,
    ) -> Result<ExecutionAuthorization, AgentError> {
        validate_opaque_id(&request.plan_id)?;
        let permission = self
            .plans
            .get(&request.plan_id)
            .ok_or(AgentError::PlanNotFound)?
            .permission;
        if !self.permits(permission) {
            return Err(AgentError::PermissionDenied(permission));
        }
        let plan = self
            .plans
            .get_mut(&request.plan_id)
            .ok_or(AgentError::PlanNotFound)?;
        verify_stored_integrity(plan, &request.integrity_hash)?;
        if now_ms >= plan.expires_at_ms {
            return Err(AgentError::PlanExpired);
        }
        if plan.state != PlanState::Approved {
            return Err(AgentError::PlanNotApproved);
        }
        if plan.requires_confirmation && !plan.explicitly_confirmed {
            return Err(AgentError::ConfirmationRequired);
        }
        verify_versions(&plan.affected, &request.current_versions)?;
        plan.state = PlanState::Executed;
        Ok(ExecutionAuthorization {
            plan: plan.clone(),
            authorized_at_ms: now_ms,
        })
    }
}

fn validate_restored_plan(plan: &ActionPlan, max_ttl_ms: u64) -> Result<(), AgentError> {
    validate_opaque_id(&plan.plan_id)?;
    let expires_in_ms = plan
        .expires_at_ms
        .checked_sub(plan.created_at_ms)
        .ok_or(AgentError::InvalidInput("expiration precedes creation"))?;
    validate_request(
        &PlanRequest {
            account_id: plan.account_id.clone(),
            action: plan.action,
            affected: plan.affected.clone(),
            reason: plan.reason.clone(),
            preview: plan.preview.clone(),
            expires_in_ms,
        },
        max_ttl_ms,
    )?;
    let permission = plan.action.required_permission();
    let is_bulk = plan.affected.len() > 1;
    let is_rule_change = plan.action.is_rule_change();
    let requires_confirmation =
        matches!(permission, PermissionLevel::Send | PermissionLevel::Delete)
            || is_bulk
            || is_rule_change;
    if plan.permission != permission
        || plan.is_bulk != is_bulk
        || plan.is_rule_change != is_rule_change
        || plan.requires_confirmation != requires_confirmation
    {
        return Err(AgentError::IntegrityMismatch);
    }
    match (plan.state, plan.approved_at_ms, plan.explicitly_confirmed) {
        (PlanState::PendingApproval | PlanState::Rejected, None, false) => {}
        (PlanState::Approved | PlanState::Executed, Some(approved_at_ms), explicitly_confirmed)
            if approved_at_ms >= plan.created_at_ms
                && approved_at_ms < plan.expires_at_ms
                && (!plan.requires_confirmation || explicitly_confirmed) => {}
        _ => return Err(AgentError::IntegrityMismatch),
    }
    verify_stored_integrity(plan, &plan.integrity_hash)
}

fn validate_request(request: &PlanRequest, max_ttl_ms: u64) -> Result<(), AgentError> {
    validate_opaque_id(&request.account_id)?;
    if request.affected.is_empty() {
        return Err(AgentError::InvalidInput(
            "at least one affected resource is required",
        ));
    }
    if request.affected.len() > MAX_AFFECTED_RESOURCES {
        return Err(AgentError::InvalidInput("too many affected resources"));
    }
    if request.expires_in_ms == 0 || request.expires_in_ms > max_ttl_ms {
        return Err(AgentError::InvalidInput("expiration is out of range"));
    }
    validate_text(&request.reason, MAX_REASON_BYTES, "reason is out of range")?;
    validate_text(
        &request.preview.summary,
        MAX_PREVIEW_BYTES,
        "preview summary is out of range",
    )?;
    if request.preview.changes.len() > MAX_PREVIEW_CHANGES {
        return Err(AgentError::InvalidInput("too many preview changes"));
    }
    if request.preview.affected_count as usize != request.affected.len() {
        return Err(AgentError::InvalidInput(
            "preview affected count does not match plan",
        ));
    }

    let mut ids = BTreeSet::new();
    for resource in &request.affected {
        validate_opaque_id(&resource.resource_id)?;
        validate_version(&resource.version)?;
        if !ids.insert(resource.resource_id.as_str()) {
            return Err(AgentError::InvalidInput(
                "affected resource IDs must be unique",
            ));
        }
    }
    for change in &request.preview.changes {
        validate_opaque_id(&change.resource_id)?;
        if !ids.contains(change.resource_id.as_str()) {
            return Err(AgentError::InvalidInput(
                "preview references a resource outside the plan",
            ));
        }
        validate_text(
            &change.description,
            MAX_PREVIEW_BYTES,
            "preview change is out of range",
        )?;
    }
    Ok(())
}

fn verify_versions(
    expected: &[ResourceVersion],
    current: &[ResourceVersion],
) -> Result<(), AgentError> {
    if expected.len() != current.len() {
        return Err(AgentError::VersionDrift {
            resource_id: "resource_set".to_owned(),
        });
    }
    let mut current_by_id = HashMap::with_capacity(current.len());
    for resource in current {
        validate_opaque_id(&resource.resource_id)?;
        validate_version(&resource.version)?;
        if current_by_id
            .insert(resource.resource_id.as_str(), resource.version.as_str())
            .is_some()
        {
            return Err(AgentError::InvalidInput(
                "current resource IDs must be unique",
            ));
        }
    }
    for resource in expected {
        if current_by_id.get(resource.resource_id.as_str()).copied()
            != Some(resource.version.as_str())
        {
            return Err(AgentError::VersionDrift {
                resource_id: resource.resource_id.clone(),
            });
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct IntegrityMaterial<'a> {
    plan_id: &'a str,
    account_id: &'a str,
    action: PlanAction,
    permission: PermissionLevel,
    affected: &'a [ResourceVersion],
    reason: &'a str,
    preview: &'a PlanPreview,
    is_bulk: bool,
    is_rule_change: bool,
    requires_confirmation: bool,
    created_at_ms: u64,
    expires_at_ms: u64,
}

fn plan_integrity_hash(plan: &ActionPlan) -> Result<String, AgentError> {
    let material = IntegrityMaterial {
        plan_id: &plan.plan_id,
        account_id: &plan.account_id,
        action: plan.action,
        permission: plan.permission,
        affected: &plan.affected,
        reason: &plan.reason,
        preview: &plan.preview,
        is_bulk: plan.is_bulk,
        is_rule_change: plan.is_rule_change,
        requires_confirmation: plan.requires_confirmation,
        created_at_ms: plan.created_at_ms,
        expires_at_ms: plan.expires_at_ms,
    };
    serde_json::to_vec(&material)
        .map(|encoded| sha256_hex(&encoded))
        .map_err(|_| AgentError::InvalidInput("plan cannot be encoded"))
}

fn verify_stored_integrity(plan: &ActionPlan, presented_hash: &str) -> Result<(), AgentError> {
    let current = plan_integrity_hash(plan)?;
    if !constant_time_eq(current.as_bytes(), plan.integrity_hash.as_bytes())
        || !constant_time_eq(current.as_bytes(), presented_hash.as_bytes())
    {
        return Err(AgentError::IntegrityMismatch);
    }
    Ok(())
}

pub(crate) fn validate_opaque_id(value: &str) -> Result<(), AgentError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(AgentError::InvalidInput("opaque ID is invalid"));
    }
    Ok(())
}

fn validate_version(value: &str) -> Result<(), AgentError> {
    if value.is_empty() || value.len() > 128 || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(AgentError::InvalidInput("resource version is invalid"));
    }
    Ok(())
}

fn validate_text(value: &str, max_bytes: usize, message: &'static str) -> Result<(), AgentError> {
    if value.trim().is_empty() || value.len() > max_bytes || value.contains('\0') {
        return Err(AgentError::InvalidInput(message));
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

/// SHA-256 is used for tamper evidence, not as a password KDF or MAC.
pub(crate) fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(action: PlanAction, affected: usize) -> PlanRequest {
        let resources = (0..affected)
            .map(|index| ResourceVersion {
                resource_id: format!("message-{index}"),
                version: "v1".to_owned(),
            })
            .collect::<Vec<_>>();
        PlanRequest {
            account_id: "account-1".to_owned(),
            action,
            affected: resources.clone(),
            reason: "Requested by the user".to_owned(),
            preview: PlanPreview {
                summary: "Apply the requested change".to_owned(),
                affected_count: affected as u32,
                changes: resources
                    .iter()
                    .map(|item| PreviewChange {
                        resource_id: item.resource_id.clone(),
                        description: "Inbox -> Archive".to_owned(),
                    })
                    .collect(),
            },
            expires_in_ms: 10_000,
        }
    }

    fn policy() -> AgentPolicy {
        AgentPolicy::new(
            [
                PermissionLevel::Read,
                PermissionLevel::Organize,
                PermissionLevel::Draft,
                PermissionLevel::Send,
                PermissionLevel::Move,
                PermissionLevel::Delete,
            ],
            DEFAULT_MAX_TTL_MS,
        )
        .unwrap()
    }

    #[test]
    fn sha256_matches_standard_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn risky_plans_require_explicit_confirmation() {
        for action in [PlanAction::Send, PlanAction::Delete, PlanAction::CreateRule] {
            let mut policy = policy();
            let plan = policy.create_plan(request(action, 1), 100).unwrap();
            assert!(plan.requires_confirmation);
            assert_eq!(
                policy.approve_plan(
                    PlanApproval {
                        plan_id: plan.plan_id,
                        integrity_hash: plan.integrity_hash,
                        confirmed: false,
                    },
                    101,
                ),
                Err(AgentError::ConfirmationRequired)
            );
        }
        let mut policy = policy();
        let plan = policy
            .create_plan(request(PlanAction::Move, 2), 100)
            .unwrap();
        assert!(plan.is_bulk && plan.requires_confirmation);
    }

    #[test]
    fn restore_revalidates_confirmation_and_derived_security_fields() {
        let mut original = policy();
        let proposed = original
            .create_plan(request(PlanAction::Send, 1), 100)
            .unwrap();
        let approved = original
            .approve_plan(
                PlanApproval {
                    plan_id: proposed.plan_id,
                    integrity_hash: proposed.integrity_hash,
                    confirmed: true,
                },
                101,
            )
            .unwrap();

        let mut restored = policy();
        restored.restore_plan(approved.clone()).unwrap();
        assert_eq!(restored.plans(), vec![approved.clone()]);

        let mut missing_confirmation = approved;
        missing_confirmation.explicitly_confirmed = false;
        assert_eq!(
            policy().restore_plan(missing_confirmation),
            Err(AgentError::IntegrityMismatch)
        );
    }

    #[test]
    fn execution_rejects_unapproved_expired_tampered_and_drifted_plans() {
        let mut unapproved = policy();
        let plan = unapproved
            .create_plan(request(PlanAction::Move, 1), 100)
            .unwrap();
        let execution = ExecutionRequest {
            plan_id: plan.plan_id.clone(),
            integrity_hash: plan.integrity_hash.clone(),
            current_versions: plan.affected.clone(),
        };
        assert_eq!(
            unapproved.authorize_execution(execution.clone(), 101),
            Err(AgentError::PlanNotApproved)
        );

        let mut expired = policy();
        let mut expiring_request = request(PlanAction::Move, 1);
        expiring_request.expires_in_ms = 1;
        let expiring = expired.create_plan(expiring_request, 100).unwrap();
        assert_eq!(
            expired.approve_plan(
                PlanApproval {
                    plan_id: expiring.plan_id,
                    integrity_hash: expiring.integrity_hash,
                    confirmed: false,
                },
                101,
            ),
            Err(AgentError::PlanExpired)
        );

        let mut drifted = policy();
        let plan = drifted
            .create_plan(request(PlanAction::Move, 1), 100)
            .unwrap();
        drifted
            .approve_plan(
                PlanApproval {
                    plan_id: plan.plan_id.clone(),
                    integrity_hash: plan.integrity_hash.clone(),
                    confirmed: false,
                },
                101,
            )
            .unwrap();
        let mut changed = plan.affected.clone();
        changed[0].version = "v2".to_owned();
        assert!(matches!(
            drifted.authorize_execution(
                ExecutionRequest {
                    plan_id: plan.plan_id.clone(),
                    integrity_hash: plan.integrity_hash.clone(),
                    current_versions: changed,
                },
                102,
            ),
            Err(AgentError::VersionDrift { .. })
        ));
        assert_eq!(
            drifted.authorize_execution(
                ExecutionRequest {
                    plan_id: plan.plan_id,
                    integrity_hash: "0".repeat(64),
                    current_versions: plan.affected,
                },
                102,
            ),
            Err(AgentError::IntegrityMismatch)
        );
    }
}
