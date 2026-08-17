"""Read-only synchronization of Gmail messages into a :class:`Store`.

This module deliberately knows nothing about OAuth or the Gmail transport.  The
client is duck-typed so callers (and tests) can provide any object implementing
``list_messages`` and ``get_message``.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import re
from collections.abc import Mapping
from typing import Any, Dict, Iterable, List, Optional, Tuple


_DEFAULT_MAX_MESSAGES = 100
_MAX_MESSAGES = 10_000


_TAG_RE = re.compile(r"<[^>]*>")
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_SCRIPT_RE = re.compile(r"<(script|style)\b[^>]*>.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
_BLOCK_TAG_RE = re.compile(r"</?(?:br|p|div|li|tr|td|th|h[1-6]|blockquote|pre|ul|ol)\b[^>]*>", re.IGNORECASE)


def _bounded_max_messages(value: Any) -> int:
    """Return a positive, bounded message count for an untrusted CLI value."""
    try:
        count = int(value)
    except (TypeError, ValueError):
        count = _DEFAULT_MAX_MESSAGES
    return max(1, min(count, _MAX_MESSAGES))


def _decode_body(data: Any) -> str:
    """Decode Gmail's URL-safe base64 body representation."""
    if data is None:
        return ""
    if isinstance(data, bytes):
        raw = data
    else:
        raw = str(data).encode("ascii", "replace")
    raw += b"=" * ((4 - len(raw) % 4) % 4)
    decoded = base64.urlsafe_b64decode(raw)
    return decoded.decode("utf-8", "replace")


def _html_to_text(value: str) -> str:
    """Convert an HTML body to searchable text without external dependencies."""
    value = _SCRIPT_RE.sub("", value)
    value = _COMMENT_RE.sub("", value)
    value = _BLOCK_TAG_RE.sub("\n", value)
    value = _TAG_RE.sub("", value)
    value = html.unescape(value)
    # Keep meaningful line breaks, while avoiding a huge amount of formatting
    # whitespace from HTML source.
    lines = [re.sub(r"[ \t\r\f\v]+", " ", line).strip() for line in value.splitlines()]
    return "\n".join(line for line in lines if line)


def _parts(payload: Any) -> Tuple[List[str], List[str], List[str]]:
    """Return plain bodies, HTML bodies, and decoding errors recursively."""
    plain: List[str] = []
    markup: List[str] = []
    errors: List[str] = []

    def visit(part: Any) -> None:
        if not isinstance(part, Mapping):
            return
        mime_type = str(part.get("mimeType", "")).lower().split(";", 1)[0].strip()
        body = part.get("body")
        if isinstance(body, Mapping) and body.get("data") is not None:
            try:
                decoded = _decode_body(body.get("data"))
                if mime_type == "text/plain":
                    plain.append(decoded)
                elif mime_type == "text/html":
                    markup.append(decoded)
                elif not part.get("parts") and not mime_type:
                    plain.append(decoded)
            except (ValueError, TypeError, UnicodeError) as exc:
                errors.append("body decode: %s" % exc)
        children = part.get("parts")
        if isinstance(children, (list, tuple)):
            for child in children:
                visit(child)

    visit(payload)
    return plain, markup, errors


def _body_text(message: Mapping[str, Any]) -> Tuple[str, List[str]]:
    payload = message.get("payload")
    plain, markup, errors = _parts(payload)
    plain_text = "\n\n".join(value for value in plain if value).strip()
    if plain_text:
        return plain_text, errors
    html_text = "\n\n".join(_html_to_text(value) for value in markup if value).strip()
    if html_text:
        return html_text, errors
    snippet = message.get("snippet")
    return (str(snippet).strip() if snippet is not None else ""), errors


def _header_values(message: Mapping[str, Any]) -> Dict[str, str]:
    headers = message.get("payload", {}).get("headers", []) if isinstance(message.get("payload"), Mapping) else []
    result: Dict[str, str] = {}
    if not isinstance(headers, (list, tuple)):
        return result
    for header in headers:
        if not isinstance(header, Mapping):
            continue
        name = str(header.get("name", "")).strip().lower()
        if not name:
            continue
        value = str(header.get("value", ""))
        if name in result and value:
            result[name] = result[name] + ", " + value
        else:
            result[name] = value
    return result


def _message_listing(response: Any) -> Tuple[List[Any], Optional[str]]:
    """Accept Gmail-shaped responses and simple fake-client list responses."""
    if isinstance(response, Mapping):
        messages = response.get("messages", [])
        token = response.get("nextPageToken", response.get("next_page_token"))
        if not isinstance(messages, (list, tuple)):
            messages = []
        return list(messages), str(token) if token is not None else None
    if isinstance(response, (list, tuple)):
        return list(response), None
    return [], None


def _account_hint(client: Any) -> str:
    value = getattr(client, "account_hint", None)
    if value is None:
        value = getattr(client, "account", None)
    return str(value or "")


def _metadata_for(message: Mapping[str, Any], message_id: str, client: Any) -> Tuple[Dict[str, Any], str, List[str]]:
    headers = _header_values(message)
    text, extraction_errors = _body_text(message)
    sender = headers.get("from", "")
    to = headers.get("to", "")
    cc = headers.get("cc", "")
    bcc = headers.get("bcc", "")
    recipients = ", ".join(value for value in (to, cc, bcc) if value)
    account = _account_hint(client)
    labels = message.get("labelIds", message.get("labels", []))
    if not isinstance(labels, list):
        labels = list(labels) if isinstance(labels, (tuple, set)) else ([labels] if labels else [])
    metadata: Dict[str, Any] = {
        "source": "gmail",
        "account": account,
        "account_hint": account,
        "message_id": message_id,
        "thread_id": str(message.get("threadId", "") or ""),
        "labels": [str(label) for label in labels],
        "subject": headers.get("subject", ""),
        "sender": sender,
        "recipients": recipients,
        "to": to,
        "cc": cc,
        "bcc": bcc,
        "date": headers.get("date", ""),
        "snippet": str(message.get("snippet", "") or ""),
    }
    if message.get("internalDate") is not None:
        metadata["internal_date"] = str(message.get("internalDate"))
    if extraction_errors:
        metadata["extraction_errors"] = extraction_errors
    return metadata, text, extraction_errors


def sync_gmail(store: Any, client: Any, query: str = "", max_messages: int = 100) -> Dict[str, Any]:
    """Fetch Gmail messages and upsert searchable, read-only local records.

    The Gmail client is expected to perform only GET requests.  A failed fetch
    or upsert is recorded in ``errors`` and does not prevent later messages from
    being synchronized.
    """
    limit = _bounded_max_messages(max_messages)
    result: Dict[str, Any] = {"synced": [], "skipped": [], "errors": [], "next_page_token": None}
    try:
        listing_response = client.list_messages(query=query or "", max_messages=limit)
        listings, next_page_token = _message_listing(listing_response)
        result["next_page_token"] = next_page_token
    except Exception as exc:
        result["errors"].append({"message_id": None, "error": "list messages: %s" % exc})
        return result

    seen_ids = set()
    for item in listings[:limit]:
        if isinstance(item, Mapping):
            raw_id = item.get("id")
        else:
            raw_id = item
        message_id = str(raw_id or "").strip()
        if not message_id:
            result["skipped"].append({"message_id": None, "reason": "message has no id"})
            continue
        if message_id in seen_ids:
            result["skipped"].append({"message_id": message_id, "reason": "duplicate message id"})
            continue
        seen_ids.add(message_id)
        try:
            message = client.get_message(message_id, format="full")
            if not isinstance(message, Mapping):
                raise ValueError("message response is not an object")
            metadata, text, extraction_errors = _metadata_for(message, message_id, client)
            # Include the ID in the digest.  Store de-duplicates by hash before
            # path, so two different Gmail messages with identical bodies must
            # still receive one local record each.
            digest_input = (message_id + "\n" + text).encode("utf-8", "replace")
            sha256 = hashlib.sha256(digest_input).hexdigest()
            path = "gmail://" + message_id
            document = store.upsert_document(
                path=path,
                name=message_id + ".eml",
                mime_type="message/rfc822",
                size=len(text.encode("utf-8")),
                sha256=sha256,
                text=text,
                metadata_json=json.dumps(metadata, ensure_ascii=False, sort_keys=True),
            )
            entry: Dict[str, Any] = {"message_id": message_id, "path": path, "sha256": sha256}
            if isinstance(document, Mapping) and document.get("id") is not None:
                entry["id"] = document["id"]
            result["synced"].append(entry)
            for extraction_error in extraction_errors:
                result["errors"].append({"message_id": message_id, "error": extraction_error})
        except Exception as exc:
            result["errors"].append({"message_id": message_id, "error": "sync message: %s" % exc})
    return result


__all__ = ["sync_gmail"]
