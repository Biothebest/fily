use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::State;
use walkdir::WalkDir;

use crate::{
    commands::{AppState, CommandError},
    storage::{Storage, StorageError},
};

const MAX_EXTRACT_BYTES: u64 = 10 * 1024 * 1024;
const MAX_HASH_BYTES: u64 = 100 * 1024 * 1024;
const MAX_EXTRACTED_TEXT: usize = 1024 * 1024;
const MAX_SCAN_FILES: usize = 20_000;
const MAX_SEARCH_RESULTS: u32 = 100;
const MAX_SCAN_BYTES: u64 = 256 * 1024 * 1024;
const PLAN_TTL_MS: i64 = 15 * 60 * 1000;
const MAX_OCR_TIME: Duration = Duration::from_secs(20);
const MAX_SCAN_TIME: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum LocalFileError {
    #[error("invalid local file request")]
    Invalid,
    #[error("the path is outside an approved root")]
    OutsideApprovedRoot,
    #[error("symbolic links are not allowed")]
    Symlink,
    #[error("the local file item was not found")]
    NotFound,
    #[error("the local file changed")]
    VersionConflict,
    #[error("the action is not approved")]
    NotApproved,
    #[error("the action plan expired")]
    Expired,
    #[error("the destination already exists")]
    DestinationExists,
    #[error("local file storage failed")]
    Storage(#[from] StorageError),
    #[error("local file access failed")]
    Io(#[from] std::io::Error),
    #[error("local file watcher failed")]
    Watch(#[from] notify::Error),
}

impl From<LocalFileError> for CommandError {
    fn from(error: LocalFileError) -> Self {
        let (code, message) = match error {
            LocalFileError::Invalid => ("invalid_request", "The local file request is invalid."),
            LocalFileError::OutsideApprovedRoot | LocalFileError::Symlink => (
                "not_authorized",
                "The path is not safely contained in an approved folder.",
            ),
            LocalFileError::NotFound => ("not_found", "The local file item was not found."),
            LocalFileError::VersionConflict => (
                "version_conflict",
                "The file changed after the action was previewed.",
            ),
            LocalFileError::NotApproved => (
                "confirmation_required",
                "The immutable file action plan has not been approved.",
            ),
            LocalFileError::Expired => ("plan_expired", "The file action plan expired."),
            LocalFileError::DestinationExists => (
                "destination_exists",
                "The file action destination already exists.",
            ),
            LocalFileError::Storage(_) | LocalFileError::Io(_) | LocalFileError::Watch(_) => (
                "local_files_unavailable",
                "Local file stewardship is temporarily unavailable.",
            ),
        };
        Self { code, message }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FolderGrant {
    pub id: String,
    pub canonical_path: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FileRecord {
    pub id: String,
    pub root_id: String,
    pub relative_path: String,
    pub title: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub modified_at: i64,
    pub content_hash: String,
    pub duplicate_group: Option<String>,
    pub version_group: String,
    pub extraction_status: String,
    pub excerpt: String,
    pub indexed_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileSearchHit {
    pub record_id: String,
    pub root_id: String,
    pub title: String,
    pub relative_path: String,
    pub excerpt: String,
    pub extraction_status: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileRelations {
    pub duplicates: Vec<FileRecord>,
    pub versions: Vec<FileRecord>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileActionKind {
    Rename,
    Move,
    Archive,
    ManagedTrash,
}

impl FileActionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Rename => "rename",
            Self::Move => "move",
            Self::Archive => "archive",
            Self::ManagedTrash => "managed_trash",
        }
    }

    fn parse(value: &str) -> Result<Self, LocalFileError> {
        match value {
            "rename" => Ok(Self::Rename),
            "move" => Ok(Self::Move),
            "archive" => Ok(Self::Archive),
            "managed_trash" => Ok(Self::ManagedTrash),
            _ => Err(LocalFileError::Invalid),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateFileActionRequest {
    pub record_id: String,
    pub action: FileActionKind,
    pub destination: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileActionPlan {
    pub id: String,
    pub root_id: String,
    pub record_id: String,
    pub action: FileActionKind,
    pub source_relative: String,
    pub destination_relative: String,
    pub expected_hash: String,
    pub preview: String,
    pub confirmation_phrase: String,
    pub status: String,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApproveFileActionRequest {
    pub plan_id: String,
    pub confirmation: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilePlanRequest {
    pub plan_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileActionResult {
    pub plan_id: String,
    pub recovery_id: String,
    pub record: FileRecord,
}

#[derive(Debug, Clone)]
struct StoredRoot {
    grant: FolderGrant,
    identity: String,
}

#[derive(Debug, Clone)]
struct StoredFile {
    view: FileRecord,
    content: String,
}

#[derive(Debug, Clone)]
struct StoredRecovery {
    id: String,
    plan_id: String,
    root_id: String,
    record_id: String,
    action: String,
    before_relative: String,
    after_relative: String,
    expected_hash: String,
    status: String,
    created_at: i64,
}

pub struct LocalFileService {
    storage: Arc<Storage>,
    watchers: Mutex<HashMap<String, RecommendedWatcher>>,
    file_ops: Mutex<()>,
}

impl LocalFileService {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self {
            storage,
            watchers: Mutex::new(HashMap::new()),
            file_ops: Mutex::new(()),
        }
    }

    pub fn start_persisted_watchers(self: &Arc<Self>) -> Result<(), LocalFileError> {
        for root in self.stored_roots()? {
            if self.validate_root(&root).is_ok() {
                self.start_watch(&root)?;
                self.scan_root(&root)?;
            }
        }
        Ok(())
    }

    pub fn grant_root(self: &Arc<Self>, selected: &Path) -> Result<FolderGrant, LocalFileError> {
        let canonical = selected.canonicalize()?;
        let metadata = fs::metadata(&canonical)?;
        if !metadata.is_dir() || fs::symlink_metadata(selected)?.file_type().is_symlink() {
            return Err(LocalFileError::Invalid);
        }
        let canonical_path = canonical
            .to_str()
            .ok_or(LocalFileError::Invalid)?
            .to_owned();
        if let Some(mut existing) = self.root_by_path(&canonical_path)? {
            existing.identity = file_identity(&metadata);
            existing.grant.updated_at = now_ms();
            self.storage.with_connection(|connection| {
                connection.execute(
                    "UPDATE approved_file_roots SET identity=?2,updated_at=?3 WHERE id=?1",
                    params![
                        existing.grant.id,
                        existing.identity,
                        existing.grant.updated_at
                    ],
                )?;
                Ok(())
            })?;
            self.watchers
                .lock()
                .map_err(|_| LocalFileError::Invalid)?
                .remove(&existing.grant.id);
            self.start_watch(&existing)?;
            self.scan_root(&existing)?;
            return Ok(existing.grant);
        }
        let now = now_ms();
        let root = StoredRoot {
            grant: FolderGrant {
                id: random_id("root"),
                canonical_path,
                created_at: now,
                updated_at: now,
            },
            identity: file_identity(&metadata),
        };
        self.storage.with_connection(|connection| {
            connection.execute(
                "INSERT INTO approved_file_roots(id,canonical_path,identity,created_at,updated_at) VALUES(?1,?2,?3,?4,?5)",
                params![root.grant.id, root.grant.canonical_path, root.identity, now, now],
            )?;
            Ok(())
        })?;
        if let Err(error) = self.start_watch(&root) {
            let _ = self.delete_root(&root.grant.id);
            return Err(error);
        }
        self.scan_root(&root)?;
        Ok(root.grant)
    }

    pub fn list_roots(&self) -> Result<Vec<FolderGrant>, LocalFileError> {
        Ok(self
            .stored_roots()?
            .into_iter()
            .map(|root| root.grant)
            .collect())
    }

    pub(crate) fn get_extracted_text(&self, record_id: &str) -> Result<String, LocalFileError> {
        let file = self.stored_file(record_id)?;
        if file.view.extraction_status != "extracted" {
            return Err(LocalFileError::Invalid);
        }
        let root = self.root(&file.view.root_id)?;
        let root_path = self.validate_root(&root)?;
        let source = secure_existing(&root_path, Path::new(&file.view.relative_path))?;
        if hash_file(&source)?.as_deref() != Some(file.view.content_hash.as_str()) {
            return Err(LocalFileError::VersionConflict);
        }
        Ok(file.content)
    }

    pub fn revoke_root(&self, root_id: &str) -> Result<bool, LocalFileError> {
        validate_token(root_id)?;
        if let Ok(mut watchers) = self.watchers.lock() {
            watchers.remove(root_id);
        }
        self.delete_root(root_id)
    }

    pub fn scan_grant(&self, root_id: &str) -> Result<Vec<FileRecord>, LocalFileError> {
        let root = self.root(root_id)?;
        self.scan_root(&root)
    }

    pub fn get_file(&self, record_id: &str) -> Result<FileRecord, LocalFileError> {
        Ok(self.stored_file(record_id)?.view)
    }

    pub fn search(&self, query: &str, limit: u32) -> Result<Vec<FileSearchHit>, LocalFileError> {
        let terms = search_terms(query)?;
        let limit = limit.clamp(1, MAX_SEARCH_RESULTS);
        self.storage.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT r.id,r.root_id,r.title,r.relative_path,r.excerpt,r.extraction_status
                 FROM file_search s JOIN file_records r ON r.id=s.record_id
                 WHERE file_search MATCH ?1 AND r.extraction_status NOT IN ('missing','managed_trash')
                 ORDER BY bm25(file_search),r.indexed_at DESC LIMIT ?2",
            )?;
            let rows = statement.query_map(params![terms, limit], |row| Ok(FileSearchHit {
                record_id: row.get(0)?, root_id: row.get(1)?, title: row.get(2)?,
                relative_path: row.get(3)?, excerpt: row.get(4)?, extraction_status: row.get(5)?,
            }))?;
            rows.collect::<Result<Vec<_>, _>>().map_err(StorageError::from)
        }).map_err(LocalFileError::from)
    }

    pub fn relations(&self, record_id: &str) -> Result<FileRelations, LocalFileError> {
        let file = self.stored_file(record_id)?;
        let duplicates = if file.view.content_hash.is_empty() {
            Vec::new()
        } else {
            self.files_matching(
                "content_hash=?1 AND id!=?2 AND extraction_status NOT IN ('missing','managed_trash')",
                &file.view.content_hash,
                record_id,
            )?
        };
        let versions = self.files_matching(
            "version_group=?1 AND id!=?2 AND extraction_status NOT IN ('missing','managed_trash')",
            &file.view.version_group,
            record_id,
        )?;
        Ok(FileRelations {
            duplicates,
            versions,
        })
    }

    pub fn create_plan(
        &self,
        request: CreateFileActionRequest,
    ) -> Result<FileActionPlan, LocalFileError> {
        validate_token(&request.record_id)?;
        let file = self.stored_file(&request.record_id)?;
        if file.view.extraction_status == "missing" || file.view.content_hash.is_empty() {
            return Err(LocalFileError::Invalid);
        }
        let root = self.root(&file.view.root_id)?;
        let root_path = self.validate_root(&root)?;
        let source = secure_existing(&root_path, Path::new(&file.view.relative_path))?;
        if hash_file(&source)?.as_deref() != Some(file.view.content_hash.as_str()) {
            return Err(LocalFileError::VersionConflict);
        }
        let id = random_id("file-plan");
        let destination = action_destination(
            &root_path,
            &file.view,
            request.action,
            request.destination.as_deref(),
            &id,
        )?;
        let destination_relative = relative_string(&root_path, &destination)?;
        if destination.exists() {
            return Err(LocalFileError::DestinationExists);
        }
        let confirmation_phrase = confirmation_phrase();
        let now = now_ms();
        let preview = format!(
            "{} {} → {} (sha256 {})",
            request.action.as_str(),
            file.view.relative_path,
            destination_relative,
            file.view.content_hash
        );
        let plan = FileActionPlan {
            id,
            root_id: file.view.root_id.clone(),
            record_id: file.view.id.clone(),
            action: request.action,
            source_relative: file.view.relative_path.clone(),
            destination_relative,
            expected_hash: file.view.content_hash.clone(),
            preview,
            confirmation_phrase,
            status: "pending".to_owned(),
            created_at: now,
            expires_at: now + PLAN_TTL_MS,
        };
        self.insert_plan(&plan)?;
        Ok(plan)
    }

    pub fn approve_plan(
        &self,
        request: ApproveFileActionRequest,
    ) -> Result<FileActionPlan, LocalFileError> {
        validate_token(&request.plan_id)?;
        if request.confirmation.len() > 64 {
            return Err(LocalFileError::Invalid);
        }
        let mut plan = self.plan(&request.plan_id)?;
        if plan.status != "pending" || request.confirmation != plan.confirmation_phrase {
            return Err(LocalFileError::NotApproved);
        }
        if now_ms() > plan.expires_at {
            self.set_plan_status(&plan.id, "expired", None)?;
            return Err(LocalFileError::Expired);
        }
        self.set_plan_status(&plan.id, "approved", Some(now_ms()))?;
        plan.status = "approved".to_owned();
        Ok(plan)
    }

    pub fn execute_plan(&self, plan_id: &str) -> Result<FileActionResult, LocalFileError> {
        validate_token(plan_id)?;
        let _guard = self.file_ops.lock().map_err(|_| LocalFileError::Invalid)?;
        let plan = self.plan(plan_id)?;
        if plan.status != "approved" {
            return Err(LocalFileError::NotApproved);
        }
        if now_ms() > plan.expires_at {
            self.set_plan_status(&plan.id, "expired", None)?;
            return Err(LocalFileError::Expired);
        }
        let root = self.root(&plan.root_id)?;
        let root_path = self.validate_root(&root)?;
        let file = self.stored_file(&plan.record_id)?;
        if file.view.relative_path != plan.source_relative
            || file.view.content_hash != plan.expected_hash
        {
            return Err(LocalFileError::VersionConflict);
        }
        let source = secure_existing(&root_path, Path::new(&plan.source_relative))?;
        if hash_file(&source)?.as_deref() != Some(plan.expected_hash.as_str()) {
            return Err(LocalFileError::VersionConflict);
        }
        let destination = prepare_planned_destination(&root_path, &plan)?;
        if destination.exists() {
            return Err(LocalFileError::DestinationExists);
        }
        move_noreplace(&source, &destination)?;
        let recovery = StoredRecovery {
            id: random_id("file-recovery"),
            plan_id: plan.id.clone(),
            root_id: plan.root_id.clone(),
            record_id: plan.record_id.clone(),
            action: plan.action.as_str().to_owned(),
            before_relative: plan.source_relative.clone(),
            after_relative: plan.destination_relative.clone(),
            expected_hash: plan.expected_hash.clone(),
            status: "ready".to_owned(),
            created_at: now_ms(),
        };
        if let Err(error) = self.finish_execution(&plan, &recovery) {
            let _ = move_noreplace(&destination, &source);
            return Err(error);
        }
        let record = if plan.action == FileActionKind::ManagedTrash {
            self.stored_file(&plan.record_id)?.view
        } else {
            self.ingest_path_inner(&root, &destination)?
        };
        Ok(FileActionResult {
            plan_id: plan.id,
            recovery_id: recovery.id,
            record,
        })
    }

    pub fn undo(&self, recovery_id: &str) -> Result<FileActionResult, LocalFileError> {
        validate_token(recovery_id)?;
        let _guard = self.file_ops.lock().map_err(|_| LocalFileError::Invalid)?;
        let recovery = self.recovery(recovery_id)?;
        if recovery.status != "ready" {
            return Err(LocalFileError::NotApproved);
        }
        let root = self.root(&recovery.root_id)?;
        let root_path = self.validate_root(&root)?;
        let current = secure_existing(&root_path, Path::new(&recovery.after_relative))?;
        if hash_file(&current)?.as_deref() != Some(recovery.expected_hash.as_str()) {
            return Err(LocalFileError::VersionConflict);
        }
        let original = secure_destination(&root_path, Path::new(&recovery.before_relative), false)?;
        if original.exists() {
            return Err(LocalFileError::DestinationExists);
        }
        move_noreplace(&current, &original)?;
        if let Err(error) = self.mark_recovery_undone(&recovery) {
            let _ = move_noreplace(&original, &current);
            return Err(error);
        }
        let record = self.ingest_path_inner(&root, &original)?;
        Ok(FileActionResult {
            plan_id: recovery.plan_id,
            recovery_id: recovery.id,
            record,
        })
    }

    fn start_watch(self: &Arc<Self>, root: &StoredRoot) -> Result<(), LocalFileError> {
        let mut watchers = self.watchers.lock().map_err(|_| LocalFileError::Invalid)?;
        if watchers.contains_key(&root.grant.id) {
            return Ok(());
        }
        let root_id = root.grant.id.clone();
        let weak: Weak<Self> = Arc::downgrade(self);
        let mut watcher =
            notify::recommended_watcher(move |event: Result<Event, notify::Error>| {
                if let (Some(service), Ok(event)) = (weak.upgrade(), event) {
                    service.handle_event(&root_id, event);
                }
            })?;
        watcher.watch(
            Path::new(&root.grant.canonical_path),
            RecursiveMode::Recursive,
        )?;
        watchers.insert(root.grant.id.clone(), watcher);
        Ok(())
    }

    fn handle_event(&self, root_id: &str, event: Event) {
        if !matches!(
            event.kind,
            EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
        ) {
            return;
        }
        let Ok(root) = self.root(root_id) else {
            return;
        };
        let Ok(root_path) = self.validate_root(&root) else {
            return;
        };
        let Ok(_guard) = self.file_ops.lock() else {
            return;
        };
        let deadline = Instant::now() + MAX_SCAN_TIME;
        for path in event.paths.into_iter().take(128) {
            if Instant::now() >= deadline {
                break;
            }
            if path.is_file() {
                let _ = self.ingest_path_inner(&root, &path);
            } else if !path.exists() {
                if let Ok(relative) = relative_string_lexical(&root_path, &path) {
                    let _ = self.mark_missing(&root.grant.id, &relative);
                }
            }
        }
    }

    fn scan_root(&self, root: &StoredRoot) -> Result<Vec<FileRecord>, LocalFileError> {
        let root_path = self.validate_root(root)?;
        let _guard = self.file_ops.lock().map_err(|_| LocalFileError::Invalid)?;
        let mut records = Vec::new();
        let mut seen = HashSet::new();
        let mut scanned_bytes = 0_u64;
        let deadline = Instant::now() + MAX_SCAN_TIME;
        let mut complete = true;
        for (visited, entry) in WalkDir::new(&root_path)
            .follow_links(false)
            .into_iter()
            .enumerate()
        {
            if Instant::now() >= deadline {
                complete = false;
                break;
            }
            if visited >= MAX_SCAN_FILES * 4 {
                complete = false;
                break;
            }
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    complete = false;
                    continue;
                }
            };
            if entry.depth() == 0 {
                continue;
            }
            if is_managed_internal(entry.path(), &root_path) {
                continue;
            }
            if entry.file_type().is_symlink() || !entry.file_type().is_file() {
                continue;
            }
            if records.len() >= MAX_SCAN_FILES {
                complete = false;
                break;
            }
            let entry_size = match entry.metadata() {
                Ok(metadata) => metadata.len(),
                Err(_) => {
                    complete = false;
                    continue;
                }
            };
            scanned_bytes = scanned_bytes.saturating_add(entry_size.min(MAX_HASH_BYTES));
            if scanned_bytes > MAX_SCAN_BYTES {
                complete = false;
                break;
            }
            match self.ingest_path_inner(root, entry.path()) {
                Ok(record) => {
                    seen.insert(record.relative_path.clone());
                    records.push(record);
                }
                Err(_) => {
                    complete = false;
                }
            }
        }
        if complete {
            self.mark_unseen_missing(&root.grant.id, &seen)?;
        }
        Ok(records)
    }

    fn ingest_path_inner(
        &self,
        root: &StoredRoot,
        path: &Path,
    ) -> Result<FileRecord, LocalFileError> {
        let root_path = self.validate_root(root)?;
        let canonical = path.canonicalize()?;
        if !canonical.starts_with(&root_path)
            || fs::symlink_metadata(path)?.file_type().is_symlink()
        {
            return Err(LocalFileError::OutsideApprovedRoot);
        }
        reject_symlink_components(&root_path, &canonical)?;
        if is_managed_trash(&canonical, &root_path) {
            return Err(LocalFileError::Invalid);
        }
        let metadata = fs::metadata(&canonical)?;
        if !metadata.is_file() {
            return Err(LocalFileError::Invalid);
        }
        let relative_path = relative_string(&root_path, &canonical)?;
        let title = canonical
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or(LocalFileError::Invalid)?
            .to_owned();
        let modified_at = modified_ms(&metadata)?;
        let content_hash = hash_file(&canonical)?.unwrap_or_default();
        let extraction = extract_bounded(&canonical, metadata.len());
        let indexed_at = now_ms();
        let existing_id = self.record_id_by_path(&root.grant.id, &relative_path)?;
        let id = existing_id.unwrap_or_else(|| random_id("file"));
        let record = StoredFile {
            view: FileRecord {
                id,
                root_id: root.grant.id.clone(),
                relative_path,
                title: title.clone(),
                media_type: media_type(&canonical).to_owned(),
                size_bytes: metadata.len(),
                modified_at,
                content_hash: content_hash.clone(),
                duplicate_group: (!content_hash.is_empty()).then_some(content_hash),
                version_group: version_group(&title),
                extraction_status: extraction.status,
                excerpt: excerpt(&extraction.text),
                indexed_at,
            },
            content: extraction.text,
        };
        self.upsert_file(&record)?;
        Ok(record.view)
    }

    fn stored_roots(&self) -> Result<Vec<StoredRoot>, LocalFileError> {
        self.storage.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT id,canonical_path,identity,created_at,updated_at FROM approved_file_roots ORDER BY created_at,id"
            )?;
            let rows = statement.query_map([], map_root)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(StorageError::from)
        }).map_err(LocalFileError::from)
    }

    fn root(&self, id: &str) -> Result<StoredRoot, LocalFileError> {
        validate_token(id)?;
        self.storage.with_connection(|connection| {
            connection.query_row(
                "SELECT id,canonical_path,identity,created_at,updated_at FROM approved_file_roots WHERE id=?1",
                [id], map_root,
            ).optional().map_err(StorageError::from)
        })?.ok_or(LocalFileError::NotFound)
    }

    fn root_by_path(&self, path: &str) -> Result<Option<StoredRoot>, LocalFileError> {
        self.storage.with_connection(|connection| {
            connection.query_row(
                "SELECT id,canonical_path,identity,created_at,updated_at FROM approved_file_roots WHERE canonical_path=?1",
                [path], map_root,
            ).optional().map_err(StorageError::from)
        }).map_err(LocalFileError::from)
    }

    fn validate_root(&self, root: &StoredRoot) -> Result<PathBuf, LocalFileError> {
        let stored = PathBuf::from(&root.grant.canonical_path);
        let canonical = stored.canonicalize()?;
        let metadata = fs::metadata(&canonical)?;
        if canonical != stored || !metadata.is_dir() || file_identity(&metadata) != root.identity {
            return Err(LocalFileError::OutsideApprovedRoot);
        }
        Ok(canonical)
    }

    fn delete_root(&self, id: &str) -> Result<bool, LocalFileError> {
        Ok(self.storage.with_connection(|connection| {
            Ok(connection.execute("DELETE FROM approved_file_roots WHERE id=?1", [id])? == 1)
        })?)
    }

    fn record_id_by_path(
        &self,
        root_id: &str,
        relative: &str,
    ) -> Result<Option<String>, LocalFileError> {
        self.storage
            .with_connection(|connection| {
                connection
                    .query_row(
                        "SELECT id FROM file_records WHERE root_id=?1 AND relative_path=?2",
                        params![root_id, relative],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(StorageError::from)
            })
            .map_err(LocalFileError::from)
    }

    fn upsert_file(&self, file: &StoredFile) -> Result<(), LocalFileError> {
        self.storage.with_connection(|connection| {
            connection.execute(
                "INSERT INTO file_records(id,root_id,relative_path,title,media_type,size_bytes,modified_at,content_hash,duplicate_group,version_group,extraction_status,content,excerpt,indexed_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)
                 ON CONFLICT(id) DO UPDATE SET root_id=excluded.root_id,relative_path=excluded.relative_path,
                 title=excluded.title,media_type=excluded.media_type,size_bytes=excluded.size_bytes,
                 modified_at=excluded.modified_at,content_hash=excluded.content_hash,
                 duplicate_group=excluded.duplicate_group,version_group=excluded.version_group,
                 extraction_status=excluded.extraction_status,content=excluded.content,
                 excerpt=excluded.excerpt,indexed_at=excluded.indexed_at",
                params![file.view.id,file.view.root_id,file.view.relative_path,file.view.title,file.view.media_type,
                    file.view.size_bytes,file.view.modified_at,file.view.content_hash,file.view.duplicate_group,
                    file.view.version_group,file.view.extraction_status,file.content,file.view.excerpt,file.view.indexed_at],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    fn stored_file(&self, id: &str) -> Result<StoredFile, LocalFileError> {
        validate_token(id)?;
        self.storage.with_connection(|connection| {
            connection.query_row(
                "SELECT id,root_id,relative_path,title,media_type,size_bytes,modified_at,content_hash,
                        duplicate_group,version_group,extraction_status,content,excerpt,indexed_at
                 FROM file_records WHERE id=?1",
                [id], map_file,
            ).optional().map_err(StorageError::from)
        })?.ok_or(LocalFileError::NotFound)
    }

    fn files_matching(
        &self,
        predicate: &str,
        value: &str,
        id: &str,
    ) -> Result<Vec<FileRecord>, LocalFileError> {
        let sql = format!(
            "SELECT id,root_id,relative_path,title,media_type,size_bytes,modified_at,content_hash,
                    duplicate_group,version_group,extraction_status,content,excerpt,indexed_at
             FROM file_records WHERE {predicate} ORDER BY modified_at DESC,id LIMIT 200"
        );
        self.storage
            .with_connection(|connection| {
                let mut statement = connection.prepare(&sql)?;
                let rows = statement.query_map(params![value, id], map_file)?;
                Ok(rows
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .map(|file| file.view)
                    .collect())
            })
            .map_err(LocalFileError::from)
    }

    fn mark_missing(&self, root_id: &str, relative: &str) -> Result<(), LocalFileError> {
        self.storage.with_connection(|connection| {
            connection.execute(
                "UPDATE file_records SET extraction_status='missing',content='',excerpt='',indexed_at=?3 WHERE root_id=?1 AND relative_path=?2",
                params![root_id, relative, now_ms()],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    fn mark_unseen_missing(
        &self,
        root_id: &str,
        seen: &HashSet<String>,
    ) -> Result<(), LocalFileError> {
        let existing = self.storage.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT relative_path FROM file_records
                 WHERE root_id=?1 AND extraction_status!='missing'
                   AND relative_path NOT LIKE '.fily-archive/%'
                   AND relative_path NOT LIKE '.fily-trash/%'",
            )?;
            let rows = statement.query_map([root_id], |row| row.get::<_, String>(0))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(StorageError::from)
        })?;
        for relative in existing {
            if !seen.contains(&relative) {
                self.mark_missing(root_id, &relative)?;
            }
        }
        Ok(())
    }

    fn insert_plan(&self, plan: &FileActionPlan) -> Result<(), LocalFileError> {
        self.storage.with_connection(|connection| {
            connection.execute(
                "INSERT INTO file_action_plans(id,root_id,record_id,action,source_relative,destination_relative,
                 expected_hash,preview,confirmation_phrase,status,created_at,expires_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                params![plan.id,plan.root_id,plan.record_id,plan.action.as_str(),plan.source_relative,
                    plan.destination_relative,plan.expected_hash,plan.preview,plan.confirmation_phrase,
                    plan.status,plan.created_at,plan.expires_at],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    fn plan(&self, id: &str) -> Result<FileActionPlan, LocalFileError> {
        let value = self.storage.with_connection(|connection| {
            connection.query_row(
                "SELECT id,root_id,record_id,action,source_relative,destination_relative,expected_hash,
                        preview,confirmation_phrase,status,created_at,expires_at FROM file_action_plans WHERE id=?1",
                [id], |row| {
                    let action: String = row.get(3)?;
                    Ok((row.get::<_, String>(0)?,row.get::<_, String>(1)?,row.get::<_, String>(2)?,action,
                        row.get::<_, String>(4)?,row.get::<_, String>(5)?,row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,row.get::<_, String>(8)?,row.get::<_, String>(9)?,
                        row.get::<_, i64>(10)?,row.get::<_, i64>(11)?))
                },
            ).optional().map_err(StorageError::from)
        })?.ok_or(LocalFileError::NotFound)?;
        Ok(FileActionPlan {
            id: value.0,
            root_id: value.1,
            record_id: value.2,
            action: FileActionKind::parse(&value.3)?,
            source_relative: value.4,
            destination_relative: value.5,
            expected_hash: value.6,
            preview: value.7,
            confirmation_phrase: value.8,
            status: value.9,
            created_at: value.10,
            expires_at: value.11,
        })
    }

    fn set_plan_status(
        &self,
        id: &str,
        status: &str,
        approved_at: Option<i64>,
    ) -> Result<(), LocalFileError> {
        self.storage.with_connection(|connection| {
            let changed = connection.execute(
                "UPDATE file_action_plans SET status=?2,approved_at=COALESCE(?3,approved_at) WHERE id=?1 AND status IN ('pending','approved')",
                params![id,status,approved_at],
            )?;
            if changed != 1 { return Err(StorageError::InvalidInput("file plan state")); }
            Ok(())
        })?;
        Ok(())
    }

    fn finish_execution(
        &self,
        plan: &FileActionPlan,
        recovery: &StoredRecovery,
    ) -> Result<(), LocalFileError> {
        self.storage.with_connection(|connection| {
            let transaction = connection.unchecked_transaction()?;
            let changed = transaction.execute(
                "UPDATE file_action_plans SET status='executed',executed_at=?2 WHERE id=?1 AND status='approved'",
                params![plan.id, now_ms()],
            )?;
            if changed != 1 { return Err(StorageError::InvalidInput("file plan state")); }
            transaction.execute(
                "INSERT INTO file_action_recovery(id,plan_id,root_id,record_id,action,before_relative,after_relative,expected_hash,status,created_at,updated_at)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)",
                params![recovery.id,recovery.plan_id,recovery.root_id,recovery.record_id,recovery.action,
                    recovery.before_relative,recovery.after_relative,recovery.expected_hash,recovery.status,recovery.created_at],
            )?;
            let moved = transaction.execute(
                "UPDATE file_records SET relative_path=?2,title=?3,
                 extraction_status=CASE WHEN ?7='managed_trash' THEN 'managed_trash' ELSE extraction_status END,
                 indexed_at=?4 WHERE id=?1 AND relative_path=?5 AND content_hash=?6",
                params![plan.record_id,plan.destination_relative,
                    Path::new(&plan.destination_relative).file_name().and_then(OsStr::to_str).ok_or(StorageError::InvalidInput("file title"))?,
                    now_ms(),plan.source_relative,plan.expected_hash,plan.action.as_str()],
            )?;
            if moved != 1 { return Err(StorageError::InvalidInput("file plan version")); }
            transaction.commit()?;
            Ok(())
        })?;
        Ok(())
    }

    fn recovery(&self, id: &str) -> Result<StoredRecovery, LocalFileError> {
        self.storage.with_connection(|connection| {
            connection.query_row(
                "SELECT id,plan_id,root_id,record_id,action,before_relative,after_relative,expected_hash,status,created_at
                 FROM file_action_recovery WHERE id=?1",
                [id], |row| Ok(StoredRecovery { id:row.get(0)?,plan_id:row.get(1)?,root_id:row.get(2)?,
                    record_id:row.get(3)?,action:row.get(4)?,before_relative:row.get(5)?,after_relative:row.get(6)?,
                    expected_hash:row.get(7)?,status:row.get(8)?,created_at:row.get(9)? }),
            ).optional().map_err(StorageError::from)
        })?.ok_or(LocalFileError::NotFound)
    }

    fn mark_recovery_undone(&self, recovery: &StoredRecovery) -> Result<(), LocalFileError> {
        self.storage.with_connection(|connection| {
            let transaction = connection.unchecked_transaction()?;
            let changed = transaction.execute(
                "UPDATE file_action_recovery SET status='undone',updated_at=?2 WHERE id=?1 AND status='ready'",
                params![recovery.id,now_ms()],
            )?;
            if changed != 1 { return Err(StorageError::InvalidInput("file recovery state")); }
            let moved = transaction.execute(
                "UPDATE file_records SET relative_path=?2,title=?3,indexed_at=?4
                 WHERE id=?1 AND relative_path=?5 AND content_hash=?6",
                params![recovery.record_id,recovery.before_relative,
                    Path::new(&recovery.before_relative).file_name().and_then(OsStr::to_str)
                        .ok_or(StorageError::InvalidInput("file title"))?,
                    now_ms(),recovery.after_relative,recovery.expected_hash],
            )?;
            if moved != 1 { return Err(StorageError::InvalidInput("file recovery version")); }
            transaction.commit()?;
            Ok(())
        })?;
        Ok(())
    }
}

fn map_root(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredRoot> {
    Ok(StoredRoot {
        grant: FolderGrant {
            id: row.get(0)?,
            canonical_path: row.get(1)?,
            created_at: row.get(3)?,
            updated_at: row.get(4)?,
        },
        identity: row.get(2)?,
    })
}

fn map_file(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredFile> {
    Ok(StoredFile {
        view: FileRecord {
            id: row.get(0)?,
            root_id: row.get(1)?,
            relative_path: row.get(2)?,
            title: row.get(3)?,
            media_type: row.get(4)?,
            size_bytes: row.get(5)?,
            modified_at: row.get(6)?,
            content_hash: row.get(7)?,
            duplicate_group: row.get(8)?,
            version_group: row.get(9)?,
            extraction_status: row.get(10)?,
            excerpt: row.get(12)?,
            indexed_at: row.get(13)?,
        },
        content: row.get(11)?,
    })
}

struct Extraction {
    status: String,
    text: String,
}

fn extract_bounded(path: &Path, size: u64) -> Extraction {
    if size > MAX_EXTRACT_BYTES {
        return Extraction {
            status: "too_large".to_owned(),
            text: String::new(),
        };
    }
    let bytes = match read_bounded(path, MAX_EXTRACT_BYTES) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Extraction {
                status: "extraction_failed".to_owned(),
                text: String::new(),
            }
        }
    };
    let extension = path
        .extension()
        .and_then(OsStr::to_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let result: Result<String, ()> = match extension.as_str() {
        "txt" | "md" | "log" | "rtf" => String::from_utf8(bytes).map_err(|_| ()),
        "html" | "htm" => String::from_utf8(bytes)
            .map(|html| strip_html(&ammonia::clean(&html)))
            .map_err(|_| ()),
        "json" => serde_json::from_slice::<serde_json::Value>(&bytes)
            .and_then(|value| serde_json::to_string_pretty(&value))
            .map_err(|_| ()),
        "csv" => extract_csv(&bytes),
        "eml" => mailparse::parse_mail(&bytes)
            .and_then(|mail| mail.get_body())
            .map_err(|_| ()),
        "pdf" => pdf_extract::extract_text_from_mem(&bytes).map_err(|_| ()),
        "png" | "jpg" | "jpeg" | "tif" | "tiff" | "bmp" | "gif" | "webp" | "heic" => {
            return match local_ocr(path) {
                Ok(Some(text)) => Extraction {
                    status: "extracted".to_owned(),
                    text: truncate_text(text),
                },
                Ok(None) => Extraction {
                    status: "ocr_unavailable".to_owned(),
                    text: String::new(),
                },
                Err(_) => Extraction {
                    status: "extraction_failed".to_owned(),
                    text: String::new(),
                },
            };
        }
        _ => {
            return Extraction {
                status: "unsupported".to_owned(),
                text: String::new(),
            }
        }
    };
    match result {
        Ok(text) => Extraction {
            status: "extracted".to_owned(),
            text: truncate_text(text),
        },
        Err(()) => Extraction {
            status: "malformed".to_owned(),
            text: String::new(),
        },
    }
}

fn extract_csv(bytes: &[u8]) -> Result<String, ()> {
    let input = std::str::from_utf8(bytes).map_err(|_| ())?;
    let mut output = String::with_capacity(input.len().min(MAX_EXTRACTED_TEXT));
    let mut characters = input.chars().peekable();
    let mut quoted = false;
    let mut field_start = true;
    let mut rows = 0_usize;
    while let Some(character) = characters.next() {
        if quoted {
            if character == '"' {
                if characters.peek() == Some(&'"') {
                    characters.next();
                    if output.len() < MAX_EXTRACTED_TEXT {
                        output.push('"');
                    }
                } else {
                    quoted = false;
                }
            } else if output.len() < MAX_EXTRACTED_TEXT && rows < 10_000 {
                output.push(character);
            }
            continue;
        }
        match character {
            '"' if field_start => {
                quoted = true;
                field_start = false;
            }
            '"' => return Err(()),
            ',' => {
                if output.len() < MAX_EXTRACTED_TEXT && rows < 10_000 {
                    output.push('\t');
                }
                field_start = true;
            }
            '\n' => {
                if output.len() < MAX_EXTRACTED_TEXT && rows < 10_000 {
                    output.push('\n');
                }
                rows += 1;
                field_start = true;
            }
            '\r' if characters.peek() == Some(&'\n') => {}
            _ => {
                if output.len() < MAX_EXTRACTED_TEXT && rows < 10_000 {
                    output.push(character);
                }
                field_start = false;
            }
        }
    }
    if quoted {
        return Err(());
    }
    Ok(truncate_text(output))
}

fn local_ocr(path: &Path) -> Result<Option<String>, std::io::Error> {
    let executable = [
        "/opt/homebrew/bin/tesseract",
        "/usr/local/bin/tesseract",
        "/usr/bin/tesseract",
    ]
    .into_iter()
    .map(Path::new)
    .find(|candidate| candidate.is_file());
    let Some(executable) = executable else {
        return Ok(None);
    };
    let mut captured = tempfile::tempfile()?;
    let stdout = captured.try_clone()?;
    let mut child = Command::new(executable)
        .arg(path)
        .arg("stdout")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + MAX_OCR_TIME;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "OCR timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    if !status.success() {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, "OCR failed"));
    }
    captured.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    captured
        .take(MAX_EXTRACTED_TEXT as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_EXTRACTED_TEXT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "OCR output too large",
        ));
    }
    String::from_utf8(bytes).map(Some).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "OCR output is not UTF-8")
    })
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, std::io::Error> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::with_capacity(fs::metadata(path)?.len().min(limit) as usize);
    file.by_ref().take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file too large",
        ));
    }
    Ok(bytes)
}

fn hash_file(path: &Path) -> Result<Option<String>, std::io::Error> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_HASH_BYTES {
        return Ok(None);
    }
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(Some(hex(&hash.finalize())))
}

fn action_destination(
    root: &Path,
    file: &FileRecord,
    action: FileActionKind,
    requested: Option<&str>,
    plan_id: &str,
) -> Result<PathBuf, LocalFileError> {
    let source_relative = Path::new(&file.relative_path);
    let destination_relative = match action {
        FileActionKind::Rename => {
            let name = requested.ok_or(LocalFileError::Invalid)?;
            validate_filename(name)?;
            source_relative
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .join(name)
        }
        FileActionKind::Move => validate_relative(requested.ok_or(LocalFileError::Invalid)?)?,
        FileActionKind::Archive => {
            PathBuf::from(".fily-archive").join(format!("{}-{}", plan_id, file.title))
        }
        FileActionKind::ManagedTrash => {
            PathBuf::from(".fily-trash").join(format!("{}-{}", plan_id, file.title))
        }
    };
    secure_destination(
        root,
        &destination_relative,
        matches!(
            action,
            FileActionKind::Archive | FileActionKind::ManagedTrash
        ),
    )
}

fn prepare_planned_destination(
    root: &Path,
    plan: &FileActionPlan,
) -> Result<PathBuf, LocalFileError> {
    let managed = matches!(
        plan.action,
        FileActionKind::Archive | FileActionKind::ManagedTrash
    );
    let expected = action_destination(
        root,
        &FileRecord {
            id: plan.record_id.clone(),
            root_id: plan.root_id.clone(),
            relative_path: plan.source_relative.clone(),
            title: Path::new(&plan.source_relative)
                .file_name()
                .and_then(OsStr::to_str)
                .ok_or(LocalFileError::Invalid)?
                .to_owned(),
            media_type: String::new(),
            size_bytes: 0,
            modified_at: 0,
            content_hash: plan.expected_hash.clone(),
            duplicate_group: None,
            version_group: String::new(),
            extraction_status: String::new(),
            excerpt: String::new(),
            indexed_at: 0,
        },
        plan.action,
        match plan.action {
            FileActionKind::Rename => Path::new(&plan.destination_relative)
                .file_name()
                .and_then(OsStr::to_str),
            FileActionKind::Move => Some(&plan.destination_relative),
            _ => None,
        },
        &plan.id,
    )?;
    if relative_string(root, &expected)? != plan.destination_relative {
        return Err(LocalFileError::Invalid);
    }
    if managed {
        let parent = expected.parent().ok_or(LocalFileError::Invalid)?;
        if !parent.exists() {
            fs::create_dir(parent)?;
        }
    }
    secure_destination(root, Path::new(&plan.destination_relative), false)
}
fn move_noreplace(source: &Path, destination: &Path) -> Result<(), std::io::Error> {
    fs::hard_link(source, destination)?;
    if let Err(error) = fs::remove_file(source) {
        let _ = fs::remove_file(destination);
        return Err(error);
    }
    Ok(())
}

fn secure_existing(root: &Path, relative: &Path) -> Result<PathBuf, LocalFileError> {
    validate_relative_path(relative)?;
    let joined = root.join(relative);
    if fs::symlink_metadata(&joined)?.file_type().is_symlink() {
        return Err(LocalFileError::Symlink);
    }
    reject_symlink_components(root, &joined)?;
    let canonical = joined.canonicalize()?;
    if !canonical.starts_with(root) {
        return Err(LocalFileError::OutsideApprovedRoot);
    }
    Ok(canonical)
}

fn secure_destination(
    root: &Path,
    relative: &Path,
    allow_managed_missing_parent: bool,
) -> Result<PathBuf, LocalFileError> {
    validate_relative_path(relative)?;
    let joined = root.join(relative);
    if joined.exists() && fs::symlink_metadata(&joined)?.file_type().is_symlink() {
        return Err(LocalFileError::Symlink);
    }
    let parent = joined.parent().ok_or(LocalFileError::Invalid)?;
    if parent.exists() {
        reject_symlink_components(root, parent)?;
        let canonical_parent = parent.canonicalize()?;
        if !canonical_parent.starts_with(root) {
            return Err(LocalFileError::OutsideApprovedRoot);
        }
        Ok(canonical_parent.join(joined.file_name().ok_or(LocalFileError::Invalid)?))
    } else if allow_managed_missing_parent && parent.parent() == Some(root) {
        Ok(joined)
    } else {
        Err(LocalFileError::Invalid)
    }
}

fn reject_symlink_components(root: &Path, path: &Path) -> Result<(), LocalFileError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| LocalFileError::OutsideApprovedRoot)?;
    let mut cursor = root.to_path_buf();
    for component in relative.components() {
        cursor.push(component.as_os_str());
        if let Ok(metadata) = fs::symlink_metadata(&cursor) {
            if metadata.file_type().is_symlink() {
                return Err(LocalFileError::Symlink);
            }
        }
    }
    Ok(())
}

fn validate_relative(value: &str) -> Result<PathBuf, LocalFileError> {
    if value.is_empty() || value.len() > 4096 {
        return Err(LocalFileError::Invalid);
    }
    let path = PathBuf::from(value);
    validate_relative_path(&path)?;
    Ok(path)
}

fn validate_relative_path(path: &Path) -> Result<(), LocalFileError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(LocalFileError::Invalid);
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(LocalFileError::OutsideApprovedRoot);
    }
    Ok(())
}

fn validate_filename(value: &str) -> Result<(), LocalFileError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 255
        || path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        return Err(LocalFileError::Invalid);
    }
    Ok(())
}

fn relative_string(root: &Path, path: &Path) -> Result<String, LocalFileError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| LocalFileError::OutsideApprovedRoot)?;
    relative
        .to_str()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(LocalFileError::Invalid)
}

fn relative_string_lexical(root: &Path, path: &Path) -> Result<String, LocalFileError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| LocalFileError::OutsideApprovedRoot)?;
    validate_relative_path(relative)?;
    relative
        .to_str()
        .map(str::to_owned)
        .ok_or(LocalFileError::Invalid)
}

fn validate_token(value: &str) -> Result<(), LocalFileError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(LocalFileError::Invalid);
    }
    Ok(())
}

fn search_terms(query: &str) -> Result<String, LocalFileError> {
    if query.len() > 1000 {
        return Err(LocalFileError::Invalid);
    }
    let terms: Vec<String> = query
        .split_whitespace()
        .filter_map(|term| {
            let clean: String = term
                .chars()
                .filter(|character| {
                    character.is_alphanumeric() || *character == '_' || *character == '-'
                })
                .take(64)
                .collect();
            (!clean.is_empty()).then(|| format!("\"{}\"*", clean.replace('"', "")))
        })
        .take(12)
        .collect();
    if terms.is_empty() {
        return Err(LocalFileError::Invalid);
    }
    Ok(terms.join(" AND "))
}

fn version_group(title: &str) -> String {
    let stem = Path::new(title)
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or(title)
        .trim()
        .to_ascii_lowercase();
    let mut words: Vec<&str> = stem
        .split(|character: char| character == ' ' || character == '_' || character == '-')
        .filter(|word| !word.is_empty())
        .collect();
    while let Some(last) = words.last().copied() {
        let normalized = last.trim_matches(|character| character == '(' || character == ')');
        let version = normalized == "copy"
            || normalized.parse::<u32>().is_ok()
            || normalized.strip_prefix('v').is_some_and(|tail| {
                !tail.is_empty() && tail.chars().all(|character| character.is_ascii_digit())
            })
            || normalized.strip_prefix("version").is_some_and(|tail| {
                !tail.is_empty() && tail.chars().all(|character| character.is_ascii_digit())
            });
        if version {
            words.pop();
        } else {
            break;
        }
    }
    if matches!(words.last(), Some(word) if *word == "version") {
        words.pop();
    }
    let group = words.join(" ");
    if group.is_empty() {
        stem
    } else {
        group
    }
}

fn strip_html(html: &str) -> String {
    let mut text = String::with_capacity(html.len());
    let mut in_tag = false;
    for character in html.chars() {
        match character {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                text.push(' ');
            }
            _ if !in_tag => text.push(character),
            _ => {}
        }
    }
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_text(mut text: String) -> String {
    if text.len() <= MAX_EXTRACTED_TEXT {
        return text;
    }
    let mut boundary = MAX_EXTRACTED_TEXT;
    while !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    text.truncate(boundary);
    text
}

fn excerpt(text: &str) -> String {
    let mut end = text.len().min(500);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

fn media_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(OsStr::to_str)
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "txt" | "md" | "log" => "text/plain",
        "rtf" => "application/rtf",
        "html" | "htm" => "text/html",
        "json" => "application/json",
        "csv" => "text/csv",
        "eml" => "message/rfc822",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "tif" | "tiff" => "image/tiff",
        "gif" => "image/gif",
        "bmp" => "image/bmp",
        "webp" => "image/webp",
        "heic" => "image/heic",
        _ => "application/octet-stream",
    }
}

fn is_managed_internal(path: &Path, root: &Path) -> bool {
    path.strip_prefix(root).ok().and_then(|relative| relative.components().next()).is_some_and(|component| {
        matches!(component, Component::Normal(name) if name == OsStr::new(".fily-trash") || name == OsStr::new(".fily-archive"))
    })
}

fn is_managed_trash(path: &Path, root: &Path) -> bool {
    path.strip_prefix(root).ok().and_then(|relative| relative.components().next()).is_some_and(
        |component| matches!(component, Component::Normal(name) if name == OsStr::new(".fily-trash")),
    )
}

fn modified_ms(metadata: &fs::Metadata) -> Result<i64, LocalFileError> {
    Ok(metadata
        .modified()?
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn random_id(prefix: &str) -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("{prefix}-{}", hex(&bytes))
}

fn confirmation_phrase() -> String {
    let mut bytes = [0_u8; 4];
    OsRng.fill_bytes(&mut bytes);
    format!("FILE-{}", hex(&bytes).to_ascii_uppercase())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    format!("{}:{}", metadata.dev(), metadata.ino())
}

#[cfg(not(unix))]
fn file_identity(metadata: &fs::Metadata) -> String {
    format!(
        "{}:{}",
        metadata.len(),
        metadata
            .created()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|value| value.as_nanos())
            .unwrap_or_default()
    )
}

#[tauri::command]
pub async fn pick_folder_grant(
    state: State<'_, AppState>,
) -> Result<Option<FolderGrant>, CommandError> {
    let Some(folder) = rfd::AsyncFileDialog::new()
        .set_title("Approve a folder for Fily")
        .pick_folder()
        .await
    else {
        return Ok(None);
    };
    state
        .local_files()
        .grant_root(folder.path())
        .map(Some)
        .map_err(Into::into)
}

#[tauri::command]
pub fn list_folder_grants(state: State<'_, AppState>) -> Result<Vec<FolderGrant>, CommandError> {
    state.local_files().list_roots().map_err(Into::into)
}

#[tauri::command]
pub fn revoke_folder_grant(
    root_id: String,
    state: State<'_, AppState>,
) -> Result<bool, CommandError> {
    state
        .local_files()
        .revoke_root(&root_id)
        .map_err(Into::into)
}

#[tauri::command]
pub fn rescan_folder_grant(
    root_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<FileRecord>, CommandError> {
    state.local_files().scan_grant(&root_id).map_err(Into::into)
}

#[tauri::command]
pub fn get_file_record(
    record_id: String,
    state: State<'_, AppState>,
) -> Result<FileRecord, CommandError> {
    state.local_files().get_file(&record_id).map_err(Into::into)
}

#[tauri::command]
pub fn search_files(
    query: String,
    limit: u32,
    state: State<'_, AppState>,
) -> Result<Vec<FileSearchHit>, CommandError> {
    state
        .local_files()
        .search(&query, limit)
        .map_err(Into::into)
}

#[tauri::command]
pub fn list_file_relations(
    record_id: String,
    state: State<'_, AppState>,
) -> Result<FileRelations, CommandError> {
    state
        .local_files()
        .relations(&record_id)
        .map_err(Into::into)
}

#[tauri::command]
pub fn create_file_action_plan(
    request: CreateFileActionRequest,
    state: State<'_, AppState>,
) -> Result<FileActionPlan, CommandError> {
    state.local_files().create_plan(request).map_err(Into::into)
}

#[tauri::command]
pub fn approve_file_action_plan(
    request: ApproveFileActionRequest,
    state: State<'_, AppState>,
) -> Result<FileActionPlan, CommandError> {
    state
        .local_files()
        .approve_plan(request)
        .map_err(Into::into)
}

#[tauri::command]
pub fn execute_file_action_plan(
    request: FilePlanRequest,
    state: State<'_, AppState>,
) -> Result<FileActionResult, CommandError> {
    state
        .local_files()
        .execute_plan(&request.plan_id)
        .map_err(Into::into)
}

#[tauri::command]
pub fn undo_file_action(
    recovery_id: String,
    state: State<'_, AppState>,
) -> Result<FileActionResult, CommandError> {
    state.local_files().undo(&recovery_id).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    fn service() -> (tempfile::TempDir, PathBuf, Arc<LocalFileService>) {
        let workspace = tempdir().expect("temporary workspace");
        let root = workspace.path().join("approved");
        fs::create_dir(&root).expect("approved root");
        let storage = Storage::open(
            workspace.path().join("records.db"),
            Zeroizing::new([17_u8; 32]),
        )
        .expect("encrypted store");
        (
            workspace,
            root,
            Arc::new(LocalFileService::new(Arc::new(storage))),
        )
    }

    #[test]
    fn ingestion_relations_actions_and_undo_stay_inside_grant() {
        let (_workspace, root, service) = service();
        fs::write(
            root.join("Quarterly Report.txt"),
            "bounded searchable content",
        )
        .expect("first file");
        fs::write(
            root.join("Quarterly Report copy.txt"),
            "bounded searchable content",
        )
        .expect("duplicate file");
        let grant = service.grant_root(&root).expect("folder grant");
        let records = service.scan_grant(&grant.id).expect("rescan");
        assert_eq!(records.len(), 2);
        let primary = records
            .iter()
            .find(|record| record.title == "Quarterly Report.txt")
            .expect("primary record");
        let relations = service.relations(&primary.id).expect("relations");
        assert_eq!(relations.duplicates.len(), 1);
        assert_eq!(relations.versions.len(), 1);
        assert_eq!(service.search("searchable", 10).expect("search").len(), 2);

        let plan = service
            .create_plan(CreateFileActionRequest {
                record_id: primary.id.clone(),
                action: FileActionKind::Rename,
                destination: Some("Renamed Report.txt".to_owned()),
            })
            .expect("action preview");
        assert!(matches!(
            service.execute_plan(&plan.id),
            Err(LocalFileError::NotApproved)
        ));
        service
            .approve_plan(ApproveFileActionRequest {
                plan_id: plan.id.clone(),
                confirmation: plan.confirmation_phrase,
            })
            .expect("explicit approval");
        let executed = service.execute_plan(&plan.id).expect("safe execution");
        assert!(root.join("Renamed Report.txt").is_file());
        assert!(!root.join("Quarterly Report.txt").exists());
        service
            .undo(&executed.recovery_id)
            .expect("version-checked undo");
        assert!(root.join("Quarterly Report.txt").is_file());
        assert!(!root.join("Renamed Report.txt").exists());

        assert!(matches!(
            service.create_plan(CreateFileActionRequest {
                record_id: primary.id.clone(),
                action: FileActionKind::Move,
                destination: Some("../escape.txt".to_owned()),
            }),
            Err(LocalFileError::OutsideApprovedRoot)
        ));
    }

    #[test]
    fn malformed_and_large_files_are_recorded_without_unbounded_extraction() {
        let (_workspace, root, service) = service();
        fs::write(root.join("broken.json"), b"{not json").expect("malformed json");
        let oversized = File::create(root.join("large.txt")).expect("large file");
        oversized
            .set_len(MAX_EXTRACT_BYTES + 1)
            .expect("sparse oversized file");
        let grant = service.grant_root(&root).expect("folder grant");
        let records = service.scan_grant(&grant.id).expect("rescan");
        assert_eq!(
            records
                .iter()
                .find(|record| record.title == "broken.json")
                .expect("json record")
                .extraction_status,
            "malformed"
        );
        assert_eq!(
            records
                .iter()
                .find(|record| record.title == "large.txt")
                .expect("large record")
                .extraction_status,
            "too_large"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_never_ingested() {
        use std::os::unix::fs::symlink;

        let (workspace, root, service) = service();
        let outside = workspace.path().join("outside.txt");
        fs::write(&outside, "private").expect("outside file");
        symlink(&outside, root.join("escape.txt")).expect("escape symlink");
        let grant = service.grant_root(&root).expect("folder grant");
        assert!(service.scan_grant(&grant.id).expect("rescan").is_empty());
        assert!(matches!(
            secure_existing(
                &root.canonicalize().expect("canonical root"),
                Path::new("escape.txt")
            ),
            Err(LocalFileError::Symlink)
        ));
    }
}
