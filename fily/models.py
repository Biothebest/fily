"""Typed value objects used by the filing store.

The store deliberately returns ordinary dictionaries so callers can use the
same shape with the CLI and agent layers.  These dataclasses are convenient
for code that wants typed values without coupling itself to sqlite3.Row.
"""

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional


@dataclass(frozen=True)
class Document:
    id: int
    path: str
    name: str
    mime_type: str
    size: int
    sha256: str
    text: str
    created_at: str
    modified_at: str
    metadata_json: str

    @classmethod
    def from_mapping(cls, row: Mapping[str, Any]) -> "Document":
        return cls(
            id=int(row["id"]),
            path=str(row.get("path", "")),
            name=str(row.get("name", "")),
            mime_type=str(row.get("mime_type", "")),
            size=int(row.get("size", 0) or 0),
            sha256=str(row.get("sha256", "") or ""),
            text=str(row.get("text", "") or ""),
            created_at=str(row.get("created_at", "")),
            modified_at=str(row.get("modified_at", "")),
            metadata_json=str(row.get("metadata_json", "{}") or "{}"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "path": self.path,
            "name": self.name,
            "mime_type": self.mime_type,
            "size": self.size,
            "sha256": self.sha256,
            "text": self.text,
            "created_at": self.created_at,
            "modified_at": self.modified_at,
            "metadata_json": self.metadata_json,
        }


@dataclass(frozen=True)
class Action:
    id: int
    type: str
    document_ids_json: str
    payload_json: str
    reason: str
    confidence: float
    status: str
    created_at: str
    executed_at: Optional[str]
    error: Optional[str]

    @classmethod
    def from_mapping(cls, row: Mapping[str, Any]) -> "Action":
        return cls(
            id=int(row["id"]),
            type=str(row.get("type", "")),
            document_ids_json=str(row.get("document_ids_json", "[]") or "[]"),
            payload_json=str(row.get("payload_json", "{}") or "{}"),
            reason=str(row.get("reason", "") or ""),
            confidence=float(row.get("confidence", 0.0) or 0.0),
            status=str(row.get("status", "pending")),
            created_at=str(row.get("created_at", "")),
            executed_at=row.get("executed_at"),
            error=row.get("error"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "document_ids_json": self.document_ids_json,
            "payload_json": self.payload_json,
            "reason": self.reason,
            "confidence": self.confidence,
            "status": self.status,
            "created_at": self.created_at,
            "executed_at": self.executed_at,
            "error": self.error,
        }
