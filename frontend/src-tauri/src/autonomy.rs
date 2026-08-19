//! Bounded local autonomy models and scheduler. Content is data only; callers
//! provide typed findings and this module never executes mail or filesystem I/O.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const MAX_TEXT: usize = 2_000;
const MAX_LIST: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Citation {
    pub source_kind: SourceKind,
    pub record_id: String,
    pub title: String,
    pub excerpt: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Email,
    File,
    Case,
    Report,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    AlwaysAsk,
    AskBelowConfidence,
    AutoReversible,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleStatus {
    Active,
    Paused,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LearnedRule {
    pub id: String,
    pub name: String,
    pub conditions: Vec<String>,
    pub actions: Vec<String>,
    pub reason: String,
    pub status: RuleStatus,
    pub error_count: u32,
    pub confidence_threshold: f32,
    pub approval_mode: ApprovalMode,
    pub schedule: Schedule,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Schedule {
    Manual,
    Hourly,
    Daily,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewQueueKind {
    NeedsDecision,
    SuggestedAction,
    Duplicate,
    Case,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    Suggested,
    Approved,
    Rejected,
    Executed,
    Undone,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReviewRecord {
    pub id: String,
    pub queue: ReviewQueueKind,
    pub title: String,
    pub reason: String,
    pub status: ReviewStatus,
    pub confidence: f32,
    pub affected_records: Vec<Citation>,
    pub reversible: bool,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DailyReport {
    pub generated_at_ms: u64,
    pub anomalies: Vec<ReviewRecord>,
    pub duplicates: Vec<ReviewRecord>,
    pub deadlines: Vec<ReviewRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveCase {
    pub id: String,
    pub kind: ArchiveKind,
    pub title: String,
    pub summary: String,
    pub citations: Vec<Citation>,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveKind {
    Employee,
    Vendor,
    Case,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Approve,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutonomyError {
    InvalidInput(&'static str),
    NotFound,
    InvalidState,
    NotReversible,
    ConfirmationRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RuleChangePreview {
    pub rule: LearnedRule,
    pub operation: RuleOperation,
    pub summary: String,
    pub affected_count: u32,
    pub required_confirmation: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleOperation {
    Create,
    Update,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct AutonomySnapshot {
    pub rules: Vec<LearnedRule>,
    pub reviews: Vec<ReviewRecord>,
    pub archives: Vec<ArchiveCase>,
    pub last_daily_report: Option<DailyReport>,
}

/// State is intentionally storage-agnostic. The command layer persists snapshots
/// in SQLCipher and feeds scheduler ticks only while the desktop process is live.
#[derive(Default)]
pub struct AutonomyCore {
    rules: BTreeMap<String, LearnedRule>,
    reviews: BTreeMap<String, ReviewRecord>,
    archives: BTreeMap<String, ArchiveCase>,
    last_daily_report: Option<DailyReport>,
    pending_rule_previews: BTreeMap<String, RuleChangePreview>,
}

impl AutonomyCore {
    pub fn restore(snapshot: AutonomySnapshot) -> Result<Self, AutonomyError> {
        let mut core = Self::default();
        for rule in snapshot.rules {
            core.restore_rule(rule)?;
        }
        for review in snapshot.reviews {
            core.add_review(review)?;
        }
        for archive in snapshot.archives {
            core.add_archive(archive)?;
        }
        core.last_daily_report = snapshot.last_daily_report;
        Ok(core)
    }

    pub fn snapshot(&self) -> AutonomySnapshot {
        AutonomySnapshot {
            rules: self.rules(),
            reviews: self.reviews(None),
            archives: self.archives(),
            last_daily_report: self.last_daily_report.clone(),
        }
    }

    pub fn latest_daily_report(&self) -> Option<DailyReport> {
        self.last_daily_report.clone()
    }

    pub fn restore_rule(&mut self, rule: LearnedRule) -> Result<(), AutonomyError> {
        validate_rule(&rule)?;
        self.rules.insert(rule.id.clone(), rule);
        Ok(())
    }

    pub fn rules(&self) -> Vec<LearnedRule> {
        self.rules.values().cloned().collect()
    }
    pub fn reviews(&self, queue: Option<ReviewQueueKind>) -> Vec<ReviewRecord> {
        self.reviews
            .values()
            .filter(|item| queue.is_none() || Some(item.queue) == queue)
            .cloned()
            .collect()
    }

    pub fn archives(&self) -> Vec<ArchiveCase> {
        self.archives.values().cloned().collect()
    }

    pub fn add_archive(&mut self, archive: ArchiveCase) -> Result<(), AutonomyError> {
        validate_text(&archive.id)?;
        validate_text(&archive.title)?;
        validate_text(&archive.summary)?;
        if archive.citations.len() > MAX_LIST {
            return Err(AutonomyError::InvalidInput("archive bounds"));
        }
        self.archives.insert(archive.id.clone(), archive);
        Ok(())
    }

    pub fn add_review(&mut self, review: ReviewRecord) -> Result<(), AutonomyError> {
        validate_review(&review)?;
        self.reviews.insert(review.id.clone(), review);
        Ok(())
    }

    pub fn preview_rule_change(
        &mut self,
        rule: LearnedRule,
        operation: RuleOperation,
    ) -> Result<RuleChangePreview, AutonomyError> {
        validate_rule(&rule)?;
        if operation != RuleOperation::Create && !self.rules.contains_key(&rule.id) {
            return Err(AutonomyError::NotFound);
        }
        let verb = match operation {
            RuleOperation::Create => "Create",
            RuleOperation::Update => "Update",
            RuleOperation::Delete => "Delete",
        };
        let preview = RuleChangePreview {
            summary: format!("{verb} rule “{}”", rule.name),
            affected_count: 1,
            required_confirmation: format!("{verb} rule"),
            rule,
            operation,
        };
        self.pending_rule_previews
            .insert(preview.rule.id.clone(), preview.clone());
        Ok(preview)
    }

    pub fn confirm_rule_change(
        &mut self,
        preview: RuleChangePreview,
        confirmation: &str,
    ) -> Result<(), AutonomyError> {
        let canonical = self
            .pending_rule_previews
            .remove(&preview.rule.id)
            .ok_or(AutonomyError::InvalidState)?;
        if canonical != preview {
            return Err(AutonomyError::InvalidState);
        }
        if confirmation != canonical.required_confirmation {
            return Err(AutonomyError::ConfirmationRequired);
        }
        validate_rule(&canonical.rule)?;
        match canonical.operation {
            RuleOperation::Create if self.rules.contains_key(&canonical.rule.id) => {
                return Err(AutonomyError::InvalidState)
            }
            RuleOperation::Create | RuleOperation::Update => {
                self.rules.insert(canonical.rule.id.clone(), canonical.rule);
            }
            RuleOperation::Delete => {
                self.rules
                    .remove(&canonical.rule.id)
                    .ok_or(AutonomyError::NotFound)?;
            }
        }
        Ok(())
    }

    /// Approval authorizes a later typed execution; it does not execute here.
    pub fn decide(&mut self, id: &str, decision: Decision) -> Result<ReviewRecord, AutonomyError> {
        let item = self.reviews.get_mut(id).ok_or(AutonomyError::NotFound)?;
        if item.status != ReviewStatus::Suggested {
            return Err(AutonomyError::InvalidState);
        }
        item.status = match decision {
            Decision::Approve => ReviewStatus::Approved,
            Decision::Reject => ReviewStatus::Rejected,
        };
        Ok(item.clone())
    }

    pub fn mark_executed(&mut self, id: &str) -> Result<ReviewRecord, AutonomyError> {
        let item = self.reviews.get_mut(id).ok_or(AutonomyError::NotFound)?;
        if item.status != ReviewStatus::Approved {
            return Err(AutonomyError::InvalidState);
        }
        item.status = ReviewStatus::Executed;
        Ok(item.clone())
    }

    pub fn undo(&mut self, id: &str) -> Result<ReviewRecord, AutonomyError> {
        let item = self.reviews.get_mut(id).ok_or(AutonomyError::NotFound)?;
        if item.status != ReviewStatus::Executed {
            return Err(AutonomyError::InvalidState);
        }
        if !item.reversible {
            return Err(AutonomyError::NotReversible);
        }
        item.status = ReviewStatus::Undone;
        Ok(item.clone())
    }

    /// Produces report queues at most once per local day. Detection is supplied
    /// as bounded typed findings, never inferred from untrusted instructions.
    pub fn daily_report(&mut self, now_ms: u64) -> Option<DailyReport> {
        let day = now_ms / 86_400_000;
        if self
            .last_daily_report
            .as_ref()
            .is_some_and(|last| last.generated_at_ms / 86_400_000 == day)
        {
            return None;
        }
        let all = self.reviews.values().cloned().collect::<Vec<_>>();
        let report = DailyReport {
            generated_at_ms: now_ms,
            anomalies: all
                .iter()
                .filter(|item| item.queue == ReviewQueueKind::NeedsDecision)
                .cloned()
                .collect(),
            duplicates: all
                .iter()
                .filter(|item| item.queue == ReviewQueueKind::Duplicate)
                .cloned()
                .collect(),
            deadlines: all
                .into_iter()
                .filter(|item| item.queue == ReviewQueueKind::Case)
                .collect(),
        };
        self.last_daily_report = Some(report.clone());
        Some(report)
    }

    /// Automatic execution is limited to reversible non-mail/non-delete actions.
    pub fn may_auto_execute(
        rule: &LearnedRule,
        confidence: f32,
        action: &str,
        reversible: bool,
    ) -> bool {
        rule.status == RuleStatus::Active
            && rule.approval_mode == ApprovalMode::AutoReversible
            && confidence >= rule.confidence_threshold
            && reversible
            && !matches!(action, "send" | "permanent_delete" | "delete_rule")
    }
}

fn validate_rule(rule: &LearnedRule) -> Result<(), AutonomyError> {
    validate_text(&rule.id)?;
    validate_text(&rule.name)?;
    validate_text(&rule.reason)?;
    if rule.conditions.is_empty()
        || rule.actions.is_empty()
        || rule.conditions.len() > MAX_LIST
        || rule.actions.len() > MAX_LIST
    {
        return Err(AutonomyError::InvalidInput("rule bounds"));
    }
    if !(0.0..=1.0).contains(&rule.confidence_threshold) {
        return Err(AutonomyError::InvalidInput("confidence"));
    }
    for value in rule.conditions.iter().chain(rule.actions.iter()) {
        validate_text(value)?;
    }
    Ok(())
}

fn validate_review(item: &ReviewRecord) -> Result<(), AutonomyError> {
    validate_text(&item.id)?;
    validate_text(&item.title)?;
    validate_text(&item.reason)?;
    if !(0.0..=1.0).contains(&item.confidence) || item.affected_records.len() > MAX_LIST {
        return Err(AutonomyError::InvalidInput("review bounds"));
    }
    for citation in &item.affected_records {
        validate_text(&citation.record_id)?;
        validate_text(&citation.title)?;
        validate_text(&citation.excerpt)?;
    }
    Ok(())
}

fn validate_text(value: &str) -> Result<(), AutonomyError> {
    if value.trim().is_empty() || value.len() > MAX_TEXT || value.chars().any(char::is_control) {
        Err(AutonomyError::InvalidInput("text"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str) -> LearnedRule {
        LearnedRule {
            id: id.into(),
            name: "File invoices".into(),
            conditions: vec!["sender is Fred".into()],
            actions: vec!["move to Invoices".into()],
            reason: "Keep vendor records together".into(),
            status: RuleStatus::Active,
            error_count: 0,
            confidence_threshold: 0.9,
            approval_mode: ApprovalMode::AlwaysAsk,
            schedule: Schedule::Manual,
            updated_at_ms: 1,
        }
    }

    #[test]
    fn rule_preview_is_single_use_and_tamper_evident() {
        let mut core = AutonomyCore::default();
        let preview = core
            .preview_rule_change(rule("rule-1"), RuleOperation::Create)
            .unwrap();
        let mut tampered = preview.clone();
        tampered.rule.actions = vec!["permanent_delete".into()];
        assert_eq!(
            core.confirm_rule_change(tampered, "Create rule"),
            Err(AutonomyError::InvalidState)
        );
        assert_eq!(
            core.confirm_rule_change(preview, "Create rule"),
            Err(AutonomyError::InvalidState)
        );
    }

    #[test]
    fn snapshot_round_trip_preserves_rules_and_daily_report() {
        let mut core = AutonomyCore::default();
        let preview = core
            .preview_rule_change(rule("rule-2"), RuleOperation::Create)
            .unwrap();
        core.confirm_rule_change(preview, "Create rule").unwrap();
        assert!(core.daily_report(86_400_000).is_some());

        let restored = AutonomyCore::restore(core.snapshot()).unwrap();
        assert_eq!(restored.rules().len(), 1);
        assert_eq!(
            restored.latest_daily_report().unwrap().generated_at_ms,
            86_400_000
        );
    }
}
