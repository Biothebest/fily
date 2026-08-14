"""SQLite persistence and safe, approval-first filesystem actions."""

import datetime as _dt
import hashlib
import hmac
import json
import math
import mimetypes
import os
import shutil
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .models import Action, Document


_ACTION_TYPES = {"move", "rename", "delete"}
_STATUSES = {"pending", "approved", "rejected", "executed", "failed"}


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _json(value: Any, default: Any) -> str:
    if value is None:
        value = default
    if isinstance(value, str):
        # Validate strings here so malformed data cannot enter action rows.
        json.loads(value)
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _row_dict(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    return dict(row) if row is not None else None


class Store:
    """Own the library's SQLite database and its approval-controlled actions."""

    def __init__(self, library_root: Any):
        self.library_root = Path(library_root).expanduser().resolve()
        self.db_path = self.library_root / ".fily" / "index.sqlite3"
        self._fts_available = False
        self.initialize()

    def _connect(self) -> sqlite3.Connection:
        metadata_dir = self.db_path.parent
        if metadata_dir.is_symlink():
            raise ValueError("library metadata directory must not be a symlink")
        metadata_dir.mkdir(parents=True, exist_ok=True)
        if self.db_path.is_symlink():
            raise ValueError("library database must not be a symlink")
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.execute("PRAGMA foreign_keys = ON")
        # WAL is persistent at the database level and is safe for independent
        # Store instances in separate processes.
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    def initialize(self) -> None:
        self.library_root.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL DEFAULT '',
                    mime_type TEXT NOT NULL DEFAULT '',
                    size INTEGER NOT NULL DEFAULT 0,
                    sha256 TEXT NOT NULL DEFAULT '',
                    text TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    modified_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_documents_sha256 ON documents(sha256);
                CREATE INDEX IF NOT EXISTS idx_documents_modified_at ON documents(modified_at);
                CREATE TABLE IF NOT EXISTS actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL CHECK(type IN ('move', 'rename', 'delete')),
                    document_ids_json TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected', 'executed', 'failed')),
                    created_at TEXT NOT NULL,
                    executed_at TEXT,
                    error TEXT,
                    approval_hash TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_actions_status ON actions(status);
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            action_columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(actions)").fetchall()
            }
            if "approval_hash" not in action_columns:
                conn.execute("ALTER TABLE actions ADD COLUMN approval_hash TEXT")
            try:
                existing_fts = conn.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name='documents_fts'"
                ).fetchone()
                if existing_fts and existing_fts["sql"] and "content=" in existing_fts["sql"]:
                    # Older versions used an external-content table, whose
                    # ordinary DELETE statements corrupt the index. Recreate
                    # it as a rowid-aligned standalone index.
                    conn.execute("DROP TABLE documents_fts")
                conn.execute(
                    """CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
                        name, path, text, metadata_json
                    )"""
                )
                conn.execute("DELETE FROM documents_fts")
                for fts_row in conn.execute(
                    "SELECT id, name, path, text, metadata_json FROM documents"
                ):
                    conn.execute(
                        "INSERT INTO documents_fts(rowid,name,path,text,metadata_json) VALUES (?,?,?,?,?)",
                        tuple(fts_row),
                    )
                self._fts_available = True
            except sqlite3.Error:
                self._fts_available = False

    @staticmethod
    def _normal_metadata(metadata: Any, metadata_json: Any) -> str:
        if metadata_json is not None:
            return _json(metadata_json, {})
        return _json(metadata, {})

    def _document_path(self, value: Any) -> Path:
        """Normalize an indexed path; indexed files may be outside the library."""
        if value is None:
            raise ValueError("path is required")
        raw = os.fspath(value)
        if not isinstance(raw, str) or not raw:
            raise ValueError("path is required")
        raw_path = Path(raw).expanduser()
        if ".." in raw_path.parts:
            raise ValueError("path traversal is not allowed")
        return raw_path.resolve(strict=False)

    def upsert_document(
        self,
        path: Any,
        name: Optional[str] = None,
        mime_type: Optional[str] = None,
        size: Optional[int] = None,
        sha256: Optional[str] = None,
        text: str = "",
        created_at: Optional[str] = None,
        modified_at: Optional[str] = None,
        metadata: Any = None,
        metadata_json: Any = None,
    ) -> Dict[str, Any]:
        """Insert or update a document, matching first by path and then hash."""
        normalized = self._document_path(path)
        path_text = str(normalized)
        name = str(name if name is not None else normalized.name)
        mime_type = str(mime_type if mime_type is not None else (mimetypes.guess_type(name)[0] or ""))
        size = int(size if size is not None else (normalized.stat().st_size if normalized.exists() else 0))
        sha256 = str(sha256 or "")
        text = str(text or "")
        metadata_text = self._normal_metadata(metadata, metadata_json)
        now = _utc_now()
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM documents WHERE path = ?", (path_text,)).fetchone()
            if row is None and sha256:
                duplicate = conn.execute(
                    "SELECT * FROM documents WHERE sha256 = ? ORDER BY id LIMIT 1", (sha256,)
                ).fetchone()
                if duplicate is not None:
                    return dict(duplicate)
            if row is None:
                created = created_at or now
                modified = modified_at or now
                cur = conn.execute(
                    """INSERT INTO documents
                    (path, name, mime_type, size, sha256, text, created_at, modified_at, metadata_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (path_text, name, mime_type, size, sha256, text, created, modified, metadata_text),
                )
                doc_id = int(cur.lastrowid)
            else:
                doc_id = int(row["id"])
                created = created_at or str(row["created_at"])
                modified = modified_at or now
                conn.execute(
                    """UPDATE documents SET path=?, name=?, mime_type=?, size=?, sha256=?, text=?,
                       created_at=?, modified_at=?, metadata_json=? WHERE id=?""",
                    (path_text, name, mime_type, size, sha256, text, created, modified, metadata_text, doc_id),
                )
            if self._fts_available:
                conn.execute("DELETE FROM documents_fts WHERE rowid = ?", (doc_id,))
                conn.execute(
                    "INSERT INTO documents_fts(rowid, name, path, text, metadata_json) VALUES (?, ?, ?, ?, ?)",
                    (doc_id, name, path_text, text, metadata_text),
                )
            result = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
        return dict(result)

    def get_document(self, document_id: Any) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            return _row_dict(conn.execute("SELECT * FROM documents WHERE id = ?", (int(document_id),)).fetchone())

    def list_documents(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM documents ORDER BY id")]

    def search(self, query: Any, limit: int = 20) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        query_text = str(query or "").strip()
        with self._connect() as conn:
            if not query_text:
                rows = conn.execute("SELECT * FROM documents ORDER BY modified_at DESC, id DESC LIMIT ?", (limit,))
                return [dict(row) for row in rows]
            if self._fts_available:
                try:
                    rows = conn.execute(
                        """SELECT d.* FROM documents_fts f JOIN documents d ON d.id = f.rowid
                           WHERE documents_fts MATCH ? ORDER BY bm25(documents_fts), d.id DESC LIMIT ?""",
                        (query_text, limit),
                    )
                    return [dict(row) for row in rows]
                except sqlite3.OperationalError:
                    # User-entered punctuation can be invalid FTS syntax.
                    # The LIKE path remains useful and does not interpret SQL.
                    pass
            needle = "%" + query_text.replace("%", "\\%").replace("_", "\\_") + "%"
            rows = conn.execute(
                """SELECT * FROM documents
                   WHERE name LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\'
                      OR text LIKE ? ESCAPE '\\' OR metadata_json LIKE ? ESCAPE '\\'
                   ORDER BY modified_at DESC, id DESC LIMIT ?""",
                (needle, needle, needle, needle, limit),
            )
            return [dict(row) for row in rows]

    @staticmethod
    def _document_ids(value: Any) -> List[int]:
        if isinstance(value, str):
            value = json.loads(value)
        if not isinstance(value, (list, tuple)):
            try:
                value = list(value)
            except TypeError as exc:
                raise ValueError("document_ids must be a non-empty list") from exc
        if not value:
            raise ValueError("document_ids must be a non-empty list")
        ids = []
        for item in value:
            try:
                number = int(item)
            except (TypeError, ValueError):
                raise ValueError("document_ids must contain integer IDs")
            if number <= 0 or number in ids:
                raise ValueError("document_ids must contain unique positive IDs")
            ids.append(number)
        return ids

    def _approval_digest(self, row: Mapping[str, Any], conn: Optional[sqlite3.Connection] = None) -> str:
        owns_connection = conn is None
        connection = conn or self._connect()
        try:
            ids = self._document_ids(row["document_ids_json"])
            documents = []
            for doc_id in ids:
                document = connection.execute(
                    "SELECT id, path, sha256, size, modified_at FROM documents WHERE id = ?",
                    (doc_id,),
                ).fetchone()
                if document is None:
                    raise ValueError("unknown document ID: " + str(doc_id))
                documents.append(dict(document))
            basis = {
                "type": str(row["type"]),
                "document_ids": ids,
                "payload": json.loads(row["payload_json"]),
                "reason": str(row["reason"]),
                "confidence": float(row["confidence"]),
                "created_at": str(row["created_at"]),
                "documents": documents,
            }
            encoded = json.dumps(basis, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        finally:
            if owns_connection:
                connection.close()

    def create_action(
        self,
        type: str,
        document_ids: Iterable[Any],
        payload: Any,
        reason: str,
        confidence: float,
    ) -> Dict[str, Any]:
        action_type = str(type or "").lower()
        if action_type not in _ACTION_TYPES:
            raise ValueError("action type must be move, rename, or delete")
        ids = self._document_ids(document_ids)
        try:
            payload_text = _json(payload, {})
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("payload must be valid JSON data") from exc
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("reason is required")
        try:
            confidence = float(confidence)
        except (TypeError, ValueError) as exc:
            raise ValueError("confidence must be numeric") from exc
        if not math.isfinite(confidence) or confidence < 0 or confidence > 1:
            raise ValueError("confidence must be between 0 and 1")
        with self._connect() as conn:
            missing = [
                doc_id
                for doc_id in ids
                if conn.execute("SELECT 1 FROM documents WHERE id = ?", (doc_id,)).fetchone() is None
            ]
            if missing:
                raise ValueError("unknown document ID(s): " + ", ".join(map(str, missing)))
            now = _utc_now()
            cur = conn.execute(
                """INSERT INTO actions
                   (type, document_ids_json, payload_json, reason, confidence, status, created_at)
                   VALUES (?, ?, ?, ?, ?, 'pending', ?)""",
                (action_type, json.dumps(ids), payload_text, reason.strip(), confidence, now),
            )
            action_id = int(cur.lastrowid)
            self._audit_conn(conn, "action.created", {"action_id": action_id, "type": action_type, "document_ids": ids})
            return dict(conn.execute("SELECT * FROM actions WHERE id = ?", (action_id,)).fetchone())

    def list_actions(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        if status is not None and status not in _STATUSES:
            raise ValueError("invalid action status")
        with self._connect() as conn:
            if status is None:
                rows = conn.execute("SELECT * FROM actions ORDER BY id DESC")
            else:
                rows = conn.execute("SELECT * FROM actions WHERE status = ? ORDER BY id DESC", (status,))
            return [dict(row) for row in rows]

    def approve_action(self, action_id: Any) -> Dict[str, Any]:
        return self._transition_action(action_id, "approved")

    def reject_action(self, action_id: Any) -> Dict[str, Any]:
        return self._transition_action(action_id, "rejected")

    def _transition_action(self, action_id: Any, target: str) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM actions WHERE id = ?", (int(action_id),)).fetchone()
            if row is None:
                raise ValueError("unknown action ID")
            if row["status"] != "pending":
                raise ValueError("only pending actions can be approved or rejected")
            approval_hash = self._approval_digest(row, conn) if target == "approved" else None
            conn.execute(
                "UPDATE actions SET status = ?, error = NULL, approval_hash = ? WHERE id = ?",
                (target, approval_hash, int(action_id)),
            )
            self._audit_conn(conn, "action." + target, {"action_id": int(action_id)})
            return dict(conn.execute("SELECT * FROM actions WHERE id = ?", (int(action_id),)).fetchone())

    def audit(self, event: str, details: Any) -> Dict[str, Any]:
        if not isinstance(event, str) or not event.strip():
            raise ValueError("audit event is required")
        with self._connect() as conn:
            return self._audit_conn(conn, event.strip(), details)

    def _audit_conn(self, conn: sqlite3.Connection, event: str, details: Any) -> Dict[str, Any]:
        details_text = _json(details, {})
        now = _utc_now()
        cur = conn.execute(
            "INSERT INTO audit(event, details_json, created_at) VALUES (?, ?, ?)",
            (event, details_text, now),
        )
        return {"id": int(cur.lastrowid), "event": event, "details_json": details_text, "created_at": now}

    def _safe_path(self, value: Any, allow_root: bool = False) -> Path:
        raw = os.fspath(value)
        if not isinstance(raw, str) or not raw:
            raise ValueError("path is required")
        raw_path = Path(raw)
        if ".." in raw_path.parts:
            raise ValueError("path traversal is not allowed")
        candidate = raw_path if raw_path.is_absolute() else self.library_root / raw_path
        resolved = candidate.resolve(strict=False)
        try:
            resolved.relative_to(self.library_root)
        except ValueError as exc:
            raise ValueError("path must be inside the library root") from exc
        if not allow_root and resolved == self.library_root:
            raise ValueError("path must name a file, not the library root")
        return resolved

    @staticmethod
    def _payload_target(payload: Mapping[str, Any], doc_id: int, source: Path) -> Any:
        for key in (str(doc_id), source.name, source.as_posix()):
            if isinstance(payload.get(key), (str, os.PathLike)):
                return payload[key]
        for key in ("destinations", "targets", "names"):
            mapping = payload.get(key)
            if isinstance(mapping, Mapping):
                for lookup in (str(doc_id), source.name, source.as_posix()):
                    if lookup in mapping:
                        return mapping[lookup]
        for key in ("destination", "dest", "path", "target_path", "name", "new_name"):
            if key in payload:
                return payload[key]
        return None
    @staticmethod
    def _file_sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _verify_source_identity(self, source: Path) -> None:
        if source.is_symlink():
            raise ValueError("refusing to operate on a symlink source: " + str(source))
        resolved_source = source.resolve(strict=True)
        if resolved_source != source:
            raise ValueError("source path resolves through a symlink: " + str(source))
        with self._connect() as conn:
            row = conn.execute("SELECT sha256 FROM documents WHERE path = ?", (str(source),)).fetchone()
        expected = str(row["sha256"] or "") if row is not None else ""
        if expected and self._file_sha256(source) != expected:
            raise RuntimeError("source content changed since ingestion: " + str(source))

    def _verify_runtime_destination(self, target: Path) -> None:
        parent = target.parent.resolve(strict=False)
        try:
            parent.relative_to(self.library_root)
        except ValueError as exc:
            raise ValueError("destination parent escaped the library root") from exc
        if target.exists() or target.is_symlink():
            raise RuntimeError("refusing to overwrite existing path: " + str(target))

    def execute_action(self, action_id: Any) -> Dict[str, Any]:
        try:
            action_number = int(action_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("action ID must be an integer") from exc
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM actions WHERE id = ?", (action_number,)).fetchone()
        if row is None:
            raise ValueError("unknown action ID")
        if row["status"] != "approved":
            raise ValueError("only approved actions can be executed")
        changed = []
        try:
            approval_hash = row["approval_hash"]
            if not approval_hash:
                raise RuntimeError("approved action has no integrity snapshot; recreate the action")
            current_hash = self._approval_digest(row)
            if not hmac.compare_digest(str(approval_hash), current_hash):
                raise RuntimeError("approved action changed after approval; recreate the action")
            ids = self._document_ids(row["document_ids_json"])
            payload = json.loads(row["payload_json"])
            if not isinstance(payload, Mapping):
                raise ValueError("action payload must be an object")
            operations = self._prepare_operations(str(row["type"]), ids, payload, action_number)
            for source, target in operations:
                if str(row["type"]) in {"delete", "move"}:
                    target.parent.mkdir(parents=True, exist_ok=True)
                self._verify_runtime_destination(target)
                self._verify_source_identity(source)
                if not source.exists():
                    raise RuntimeError("source path no longer exists: " + str(source))
                shutil.move(str(source), str(target))
                changed.append((source, target))
                self._update_document_path(action_number, source, target)
            now = _utc_now()
            with self._connect() as conn:
                conn.execute("UPDATE actions SET status='executed', executed_at=?, error=NULL WHERE id=?", (now, action_number))
                self._audit_conn(conn, "action.executed", {"action_id": action_number, "documents": ids, "changed": len(changed)})
                return dict(conn.execute("SELECT * FROM actions WHERE id=?", (action_number,)).fetchone())
        except Exception as exc:
            rollback_errors = []
            for source, target in reversed(changed):
                try:
                    if target.exists() and not source.exists():
                        source.parent.mkdir(parents=True, exist_ok=True)
                        shutil.move(str(target), str(source))
                        self._update_document_path(action_number, target, source)
                except Exception as rollback_exc:
                    rollback_errors.append(str(rollback_exc))
            message = str(exc) or exc.__class__.__name__
            now = _utc_now()
            with self._connect() as conn:
                conn.execute(
                    "UPDATE actions SET status='failed', executed_at=?, error=? WHERE id=?",
                    (now, message, action_number),
                )
                self._audit_conn(
                    conn,
                    "action.failed",
                    {
                        "action_id": action_number,
                        "error": message,
                        "changed": len(changed),
                        "rolled_back": len(changed) - len(rollback_errors),
                        "rollback_errors": rollback_errors,
                    },
                )
            if isinstance(exc, ValueError):
                raise
            raise RuntimeError(message) from exc

    def _prepare_operations(
        self, action_type: str, ids: Sequence[int], payload: Mapping[str, Any], action_id: int
    ) -> List[Tuple[Path, Path]]:
        operations: List[Tuple[Path, Path]] = []
        seen_targets = set()
        for doc_id in ids:
            doc = self.get_document(doc_id)
            if doc is None:
                raise ValueError("unknown document ID: " + str(doc_id))
            source = self._document_path(doc["path"])
            if not source.exists() and not source.is_symlink():
                raise RuntimeError("source path no longer exists: " + str(source))
            if action_type == "delete":
                target = self._safe_path(self.library_root / ".fily" / "trash" / str(action_id) / source.name)
            elif action_type == "rename":
                raw = self._payload_target(payload, doc_id, source)
                if raw is None or not isinstance(raw, (str, os.PathLike)):
                    raise ValueError("rename action requires a destination name")
                raw_name = os.fspath(raw)
                if Path(raw_name).name != raw_name or raw_name in ("", ".", "..") or os.sep in raw_name or (os.altsep and os.altsep in raw_name):
                    raise ValueError("rename destination must be a plain filename")
                target = source.parent / raw_name
                target = self._document_path(target)
                if target.parent != source.parent:
                    raise ValueError("rename destination must stay in the document's current parent")
            else:
                raw = self._payload_target(payload, doc_id, source)
                if raw is None or not isinstance(raw, (str, os.PathLike)):
                    raise ValueError("move action requires a destination path")
                target = self._safe_path(raw)
                if target.exists() and target.is_dir():
                    target = self._safe_path(target / source.name)
                if target == source:
                    raise ValueError("move destination is the current path")
            if target in seen_targets:
                raise ValueError("multiple documents resolve to the same destination")
            seen_targets.add(target)
            if target.exists():
                raise ValueError("refusing to overwrite existing path: " + str(target))
            operations.append((source, target))
        return operations

    def _update_document_path(self, action_id: int, source: Path, target: Path) -> None:
        with self._connect() as conn:
            row = conn.execute("SELECT id FROM documents WHERE path = ?", (str(source),)).fetchone()
            if row is None:
                return
            doc_id = int(row["id"])
            try:
                stat = target.stat()
                size = stat.st_size
            except OSError:
                size = 0
            conn.execute(
                "UPDATE documents SET path=?, name=?, size=?, modified_at=? WHERE id=?",
                (str(target), target.name, size, _utc_now(), doc_id),
            )
            if self._fts_available:
                current = conn.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
                conn.execute("DELETE FROM documents_fts WHERE rowid=?", (doc_id,))
                conn.execute(
                    "INSERT INTO documents_fts(rowid,name,path,text,metadata_json) VALUES (?,?,?,?,?)",
                    (doc_id, current["name"], current["path"], current["text"], current["metadata_json"]),
                )
