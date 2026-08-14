"""Local file ingestion for Fily.

The ingestion layer is intentionally filesystem-only.  It extracts useful text and
small pieces of metadata without requiring optional third-party parsers, then hands
records to :class:`fily.store.Store` for persistence.
"""

from __future__ import annotations

import csv
import hashlib
import html.parser
import io
import json
import mimetypes
import os
import re
import struct
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


_TEXT_EXTENSIONS = {
    ".c", ".cc", ".cfg", ".conf", ".cpp", ".css", ".csv", ".go", ".h",
    ".hpp", ".htm", ".html", ".ini", ".java", ".js", ".jsx", ".json",
    ".less", ".log", ".md", ".mjs", ".php", ".pl", ".py", ".r", ".rb",
    ".rs", ".scss", ".sh", ".sql", ".svg", ".tex", ".toml", ".ts",
    ".tsx", ".txt", ".vbs", ".vue", ".xml", ".yaml", ".yml", ".zsh",
}
_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp"}


class _HTMLTextParser(html.parser.HTMLParser):
    """Small HTML-to-text parser used instead of an optional HTML dependency."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []
        self.title: str = ""
        self._in_title = False
        self._ignored = 0

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
        if tag in {"script", "style", "noscript", "template"}:
            self._ignored += 1
        elif tag in {"br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        if tag in {"script", "style", "noscript", "template"} and self._ignored:
            self._ignored -= 1
        elif tag in {"p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._ignored:
            return
        if self._in_title:
            self.title += data
        self.parts.append(data)

    def text(self) -> str:
        return re.sub(r"[ \t]+", " ", "".join(self.parts)).strip()


def _iso_timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def _relative_path(path: Path, root: Path) -> str:
    """Return a portable relative path, even when roots are unrelated."""
    try:
        relative = path.resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        relative = Path(os.path.relpath(str(path), str(root)))
    return os.path.normpath(str(relative)).replace(os.sep, "/")


def _looks_binary(data: bytes) -> bool:
    if not data:
        return False
    if b"\x00" in data:
        return True
    # A high proportion of control bytes is a useful conservative binary signal.
    controls = sum(1 for byte in data[:8192] if byte < 9 or 13 < byte < 32)
    return controls > max(8, len(data[:8192]) // 20)


def _decode_text(data: bytes) -> str:
    # UTF-8 covers normal text and exported files; replacement keeps ingestion
    # useful for legacy files instead of failing the complete batch.
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def _pdf_text(data: bytes) -> str:
    """Best-effort PDF fallback: retain readable literal byte segments."""
    chunks = re.findall(rb"[ -~]{4,}", data)
    values: List[str] = []
    for chunk in chunks:
        value = chunk.decode("latin-1", errors="ignore")
        # PDF operators and object syntax are noise; retaining the rest still
        # gives search useful words when no PDF parser is installed.
        value = re.sub(r"\\[nrt()\\]", " ", value)
        value = re.sub(r"\s+", " ", value).strip()
        if value and not re.fullmatch(r"(?:obj|endobj|stream|endstream|xref|trailer|startxref|\d+)", value):
            values.append(value)
    return "\n".join(values)


def _image_metadata(data: bytes, suffix: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 24:
        result.update(format="png", width=struct.unpack(">I", data[16:20])[0], height=struct.unpack(">I", data[20:24])[0])
    elif data[:6] in (b"GIF87a", b"GIF89a") and len(data) >= 10:
        result.update(format="gif", width=struct.unpack("<H", data[6:8])[0], height=struct.unpack("<H", data[8:10])[0])
    elif data.startswith(b"\xff\xd8"):
        result["format"] = "jpeg"
        offset = 2
        while offset + 9 < len(data):
            if data[offset] != 0xFF:
                offset += 1
                continue
            marker = data[offset + 1]
            offset += 2
            if marker in (0xD8, 0xD9):
                continue
            if offset + 2 > len(data):
                break
            length = struct.unpack(">H", data[offset:offset + 2])[0]
            if marker in range(0xC0, 0xC4) and offset + 7 < len(data):
                result["height"], result["width"] = struct.unpack(">HH", data[offset + 3:offset + 7])
                break
            if length < 2:
                break
            offset += length
    elif data.startswith(b"BM") and len(data) >= 26:
        result.update(format="bmp", width=struct.unpack("<I", data[18:22])[0], height=abs(struct.unpack("<i", data[22:26])[0]))
    elif data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        result["format"] = "webp"
        if data[12:16] == b"VP8X" and len(data) >= 30:
            result["width"] = 1 + int.from_bytes(data[24:27], "little")
            result["height"] = 1 + int.from_bytes(data[27:30], "little")
    elif suffix:
        result["format"] = suffix.lstrip(".").lower()
    return result


def _extract_email(data: bytes) -> Tuple[str, Dict[str, Any], List[str]]:
    errors: List[str] = []
    message = BytesParser(policy=policy.default).parsebytes(data)
    metadata: Dict[str, Any] = {
        "format": "eml",
        "sender": message.get("From", ""),
        "recipients": [value for header in ("To", "Cc", "Bcc") for value in message.get_all(header, [])],
        "subject": message.get("Subject", ""),
    }
    if message.get("Date"):
        metadata["date"] = message.get("Date")
    attachments: List[Dict[str, Any]] = []
    body_parts: List[str] = []
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "name": filename or "attachment",
                "mime_type": part.get_content_type(),
                "size": len(payload),
            })
            continue
        if part.get_content_type() == "text/plain":
            try:
                content = part.get_content()
                if isinstance(content, bytes):
                    content = content.decode("utf-8", errors="replace")
                body_parts.append(str(content))
            except Exception as exc:
                errors.append("email body: %s" % exc)
        elif part.get_content_type() == "text/html" and not body_parts:
            try:
                parser = _HTMLTextParser()
                parser.feed(part.get_content())
                body_parts.append(parser.text())
            except Exception as exc:
                errors.append("email html body: %s" % exc)
    metadata["attachments"] = attachments
    text = "\n\n".join(part.strip() for part in body_parts if part and part.strip())
    return text, metadata, errors


def _extract(data: bytes, path: Path, mime_type: str) -> Tuple[str, Dict[str, Any], List[str]]:
    suffix = path.suffix.lower()
    metadata: Dict[str, Any] = {"extension": suffix, "mime_type": mime_type}
    errors: List[str] = []
    if not data:
        metadata["empty"] = True
        return "", metadata, ["empty file; no text extracted"]
    if suffix == ".eml" or mime_type == "message/rfc822":
        try:
            return _extract_email(data)
        except Exception as exc:
            return "", metadata, ["email: %s" % exc]
    if suffix == ".pdf" or mime_type == "application/pdf":
        try:
            text = _pdf_text(data)
            metadata["format"] = "pdf"
            return text, metadata, errors
        except Exception as exc:
            errors.append("pdf: %s" % exc)
            return "", metadata, errors
    is_image = (
        suffix in _IMAGE_EXTENSIONS
        or mime_type.startswith("image/")
        or data.startswith(b"\x89PNG\r\n\x1a\n")
        or data[:6] in (b"GIF87a", b"GIF89a")
        or data.startswith(b"\xff\xd8")
        or data.startswith(b"BM")
        or (data.startswith(b"RIFF") and data[8:12] == b"WEBP")
    )
    if is_image:
        try:
            metadata["image"] = _image_metadata(data, suffix)
        except Exception as exc:
            errors.append("image metadata: %s" % exc)
        return "", metadata, errors
    unknown_binary = suffix not in _TEXT_EXTENSIONS and not mime_type.startswith("text/")
    if unknown_binary and _looks_binary(data):
        metadata["binary"] = True
        return "", metadata, ["binary or non-text file; text extraction unavailable"]
    if unknown_binary:
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            metadata["binary"] = True
            return "", metadata, ["binary or non-text file; text extraction unavailable"]
    text = _decode_text(data)
    if suffix in {".html", ".htm"} or mime_type == "text/html":
        parser = _HTMLTextParser()
        try:
            parser.feed(text)
            text = parser.text()
            metadata["title"] = parser.title.strip()
            metadata["format"] = "html"
        except Exception as exc:
            errors.append("html: %s" % exc)
    elif suffix == ".json" or mime_type == "application/json":
        metadata["format"] = "json"
        try:
            value = json.loads(text)
            if isinstance(value, dict):
                metadata["json_keys"] = list(value.keys())[:100]
            elif isinstance(value, list):
                metadata["json_items"] = len(value)
        except (ValueError, TypeError) as exc:
            errors.append("json metadata: %s" % exc)
    elif suffix in {".csv", ".tsv"} or mime_type in {"text/csv", "text/tab-separated-values"}:
        metadata["format"] = "csv"
        try:
            dialect = "excel-tab" if suffix == ".tsv" else "excel"
            rows = list(csv.reader(io.StringIO(text), dialect=dialect))
            metadata["rows"] = len(rows)
            metadata["columns"] = max((len(row) for row in rows), default=0)
            if rows:
                metadata["headers"] = rows[0][:100]
        except (csv.Error, UnicodeError) as exc:
            errors.append("csv metadata: %s" % exc)
    return text, metadata, errors


def _candidate_files(source: Path, recursive: bool) -> Tuple[Path, List[Dict[str, str]]]:
    skipped: List[Dict[str, str]] = []
    if source.is_symlink():
        return source, [{"path": str(source), "reason": "symlink skipped"}]
    if source.is_file():
        if ".fily" in source.parts:
            return source, [{"path": str(source), "reason": "internal .fily path"}]
        return source, [source]
    if not source.is_dir():
        return source, []
    files: List[Path] = []
    iterator: Iterable[Path]
    iterator = source.rglob("*") if recursive else source.glob("*")
    for candidate in iterator:
        if ".fily" in candidate.parts:
            if candidate.is_file() and not candidate.is_symlink():
                skipped.append({"path": str(candidate), "reason": "internal .fily path"})
            continue
        try:
            if candidate.is_symlink():
                skipped.append({"path": str(candidate), "reason": "symlink skipped"})
            elif candidate.is_file():
                files.append(candidate)
        except OSError as exc:
            skipped.append({"path": str(candidate), "reason": str(exc)})
    return source, files + skipped


def ingest_path(store: Any, source_path: Any, recursive: bool = True) -> Dict[str, List[Dict[str, Any]]]:
    """Ingest regular files under *source_path* into ``store``.

    The returned lists contain small structured entries rather than database rows:
    ``ingested`` records successful upserts, ``skipped`` records intentionally
    ignored files, and ``errors`` records extraction or filesystem failures.
    Every readable file is upserted, including empty and binary files.
    """
    result: Dict[str, List[Dict[str, Any]]] = {"ingested": [], "skipped": [], "errors": []}
    try:
        source = Path(source_path).expanduser()
    except (TypeError, ValueError) as exc:
        result["errors"].append({"path": str(source_path), "error": "invalid source path: %s" % exc})
        return result
    try:
        root, candidates = _candidate_files(source, recursive)
    except OSError as exc:
        result["errors"].append({"path": str(source), "error": str(exc)})
        return result
    if not source.exists():
        result["errors"].append({"path": str(source), "error": "source path does not exist"})
        return result
    seen_hashes: Dict[str, str] = {}
    for candidate in candidates:
        if isinstance(candidate, dict):
            result["skipped"].append(candidate)
            continue
        relative = _relative_path(candidate, root if root.is_dir() else root.parent)
        try:
            stat = candidate.stat()
            size = stat.st_size
            created_at = _iso_timestamp(getattr(stat, "st_birthtime", stat.st_ctime))
            modified_at = _iso_timestamp(stat.st_mtime)
            mime_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
            try:
                with candidate.open("rb") as handle:
                    data = handle.read()
            except Exception as read_exc:
                # Keep an unreadable file visible in the index.  Its empty hash
                # is deliberately not treated as content and its error remains
                # searchable in metadata/audit output.
                read_error = "read: %s" % read_exc
                metadata = {
                    "source": "local",
                    "original_path": str(candidate),
                    "extraction_errors": [read_error],
                    "unreadable": True,
                }
                try:
                    document = store.upsert_document(
                        path=str(candidate.resolve()),
                        name=candidate.name,
                        mime_type=mime_type,
                        size=size,
                        sha256="",
                        text="",
                        created_at=created_at,
                        modified_at=modified_at,
                        metadata_json=json.dumps(metadata, ensure_ascii=False, sort_keys=True),
                    )
                    entry = {"path": relative, "sha256": ""}
                    if isinstance(document, dict) and "id" in document:
                        entry["id"] = document["id"]
                    result["ingested"].append(entry)
                except Exception as store_exc:
                    result["errors"].append({"path": relative, "error": "store upsert: %s" % store_exc})
                result["errors"].append({"path": relative, "error": read_error})
                continue
            digest = hashlib.sha256()
            digest.update(data)
            sha256 = digest.hexdigest()
            if sha256 in seen_hashes:
                result["skipped"].append({"path": relative, "reason": "duplicate content", "duplicate_of": seen_hashes[sha256]})
                continue
            seen_hashes[sha256] = relative
            text, metadata, extraction_errors = _extract(data, candidate, mime_type)
            metadata.update({"source": "local", "original_path": str(candidate), "extraction_errors": extraction_errors})
            metadata_json = json.dumps(metadata, ensure_ascii=False, sort_keys=True)
            try:
                document = store.upsert_document(
                    path=str(candidate.resolve()),
                    name=candidate.name,
                    mime_type=mime_type,
                    size=size,
                    sha256=sha256,
                    text=text,
                    created_at=created_at,
                    modified_at=modified_at,
                    metadata_json=metadata_json,
                )
                entry: Dict[str, Any] = {"path": relative, "sha256": sha256}
                if document is not None:
                    if isinstance(document, dict) and "id" in document:
                        entry["id"] = document["id"]
                    elif isinstance(document, (str, int)):
                        entry["id"] = document
                result["ingested"].append(entry)
                for extraction_error in extraction_errors:
                    result["errors"].append({"path": relative, "error": extraction_error})
            except Exception as exc:
                result["errors"].append({"path": relative, "error": "store upsert: %s" % exc})
        except Exception as exc:
            result["errors"].append({"path": relative, "error": str(exc)})
    return result


__all__ = ["ingest_path"]
