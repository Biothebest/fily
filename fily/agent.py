"""Deterministic, approval-first filing assistant.

The agent deliberately uses only the indexed documents and the :class:`Store`
interface.  It does not move files itself: archive requests create pending
Store actions which a caller must explicitly approve and execute.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple



class FilyAgent:
    """Answer filing questions and propose safe, explainable file actions."""

    def __init__(self, store: Any, library_root: Optional[Path] = None) -> None:
        self.store = store
        configured_root = library_root
        if configured_root is None:
            configured_root = getattr(store, "library_root", None)
        self.library_root = Path(configured_root).expanduser() if configured_root else None

    def ask(self, text: str, limit: int = 20) -> Dict[str, Any]:
        """Answer a deterministic natural-language request.

        The returned mapping always has ``intent``, ``answer``, ``documents``,
        and ``actions`` keys.  ``documents`` and ``actions`` contain serializable
        dictionaries where possible, making the result suitable for a CLI or
        API without another model involved.
        """
        original = "" if text is None else str(text).strip()
        if not original:
            return {
                "intent": "unknown",
                "answer": "Please provide a search, invoice, or archive request.",
                "documents": [],
                "actions": [],
            }

        intent = self._classify(original)
        if intent == "archive":
            return self._archive(original, limit)
        if intent == "invoice":
            return self._invoice(original, limit)
        if intent == "search":
            return self._search(original, limit)
        return {
            "intent": "unknown",
            "answer": (
                "I can find documents, look up invoice or bill amounts, or "
                "propose archiving matching documents."
            ),
            "documents": [],
            "actions": [],
        }

    def approve(self, action_id: Any) -> Any:
        """Approve an action; execution remains a separate explicit operation."""
        return self.store.approve_action(action_id)

    def reject(self, action_id: Any) -> Any:
        """Reject an action without touching the filesystem."""
        return self.store.reject_action(action_id)

    def render(self, result: Mapping[str, Any]) -> str:
        """Render an ``ask`` result as concise human-readable text."""
        answer = str(result.get("answer", ""))
        lines = [answer] if answer else []
        documents = result.get("documents") or []
        for document in documents:
            if not isinstance(document, Mapping):
                continue
            label = document.get("name") or document.get("path") or document.get("id")
            if label is None:
                continue
            amounts = document.get("amounts") or []
            suffix = " — amounts: " + ", ".join(map(str, amounts)) if amounts else ""
            lines.append("- " + str(label) + suffix)
        actions = result.get("actions") or []
        for action in actions:
            if isinstance(action, Mapping):
                action_id = action.get("id", "?")
                status = action.get("status", "pending")
            else:
                action_id, status = action, "pending"
            lines.append("- pending action " + str(action_id) + " (" + str(status) + ")")
        return "\n".join(lines)

    # -- Intent handlers -------------------------------------------------

    def _classify(self, text: str) -> str:
        normalized = self._normalize(text)
        if re.search(r"\b(?:archive|archiving|file\s+away)\b", normalized):
            return "archive"
        # An invoice lookup remains an invoice intent even when phrased as
        # "find the invoice from ...".
        if re.search(r"\b(?:invoice|invoices|bill|bills)\b", normalized):
            return "invoice"
        if re.search(r"\b(?:find|search|query|look\s+for|show|list)\b", normalized):
            return "search"
        return "unknown"

    def _search(self, text: str, limit: int) -> Dict[str, Any]:
        query = self._query_text(text, "search")
        documents = self._search_documents(query, limit)
        if documents:
            answer = "Found {} matching document{}.".format(
                len(documents), "" if len(documents) == 1 else "s"
            )
        else:
            answer = "No documents matched {!r}.".format(query or text)
        return {"intent": "search", "answer": answer, "documents": documents, "actions": []}

    def _invoice(self, text: str, limit: int) -> Dict[str, Any]:
        query = self._query_text(text, "invoice")
        documents = self._search_documents(query, limit)
        enriched: List[Dict[str, Any]] = []
        evidenced: List[Tuple[str, str]] = []
        for document in documents:
            item = dict(document)
            amounts = self._extract_amounts(item.get("text", ""))
            item["amounts"] = amounts
            # Keep evidence explicit rather than calculating or choosing a
            # presumed total when a document contains several amounts.
            item["amount_evidence"] = list(amounts)
            label = str(item.get("name") or item.get("path") or item.get("id") or "document")
            for amount in amounts:
                evidenced.append((label, amount))
            enriched.append(item)

        if not enriched:
            answer = "No invoice or bill documents matched {!r}; amount unknown.".format(
                query or text
            )
        elif evidenced:
            details = "; ".join("{}: {}".format(label, amount) for label, amount in evidenced)
            answer = "Found {} invoice/bill document{}. Evidenced amount{}: {}.".format(
                len(enriched),
                "" if len(enriched) == 1 else "s",
                "" if len(evidenced) == 1 else "s",
                details,
            )
        else:
            answer = (
                "Found {} invoice/bill document{} but no monetary amount is evidenced; "
                "amount unknown."
            ).format(len(enriched), "" if len(enriched) == 1 else "s")
        return {"intent": "invoice", "answer": answer, "documents": enriched, "actions": []}

    def _archive(self, text: str, limit: int) -> Dict[str, Any]:
        subject = self._archive_subject(text)
        if not subject:
            return {
                "intent": "archive",
                "answer": "Tell me which person or phrase to archive; no action was proposed.",
                "documents": [],
                "actions": [],
            }

        documents = self._matching_documents(subject, limit)
        if not documents:
            return {
                "intent": "archive",
                "answer": "No documents matched {!r}; no action was proposed.".format(subject),
                "documents": [],
                "actions": [],
            }
        if self.library_root is None:
            return {
                "intent": "archive",
                "answer": (
                    "Found {} matching document{} for {!r}, but no library root is configured; "
                    "no action was proposed."
                ).format(len(documents), "" if len(documents) == 1 else "s", subject),
                "documents": documents,
                "actions": [],
            }

        archive_dir = self.library_root / "Archive" / self._safe_subject(subject)
        actions: List[Dict[str, Any]] = []
        used_destinations = set()
        for document in documents:
            source = document.get("path")
            raw_name = document.get("name") or (Path(str(source)).name if source else "document")
            # Names are persisted metadata, but treating them as untrusted
            # prevents a crafted ``../`` name from escaping Archive/<subject>.
            name = Path(str(raw_name)).name or "document"
            candidate = archive_dir / name
            if str(candidate) in used_destinations or candidate.exists():
                name_path = Path(name)
                stem = name_path.stem or "document"
                suffix = name_path.suffix
                document_id = str(document.get("id") or len(actions) + 1)
                name = "{}__{}{}".format(stem, document_id, suffix)
                candidate = archive_dir / name
                counter = 2
                while str(candidate) in used_destinations or candidate.exists():
                    name = "{}__{}-{}{}".format(stem, document_id, counter, suffix)
                    candidate = archive_dir / name
                    counter += 1
            used_destinations.add(str(candidate))
            destination = candidate
            payload = {
                "source": str(source) if source is not None else "",
                "destination": str(destination),
                "target_path": str(destination),
            }
            reason = "Document matches archive subject {!r} by name, path, or indexed text.".format(
                subject
            )
            created = self.store.create_action(
                "move", [document.get("id")], payload, reason, 0.9
            )
            action = self._action_result(created)
            actions.append(action)

        answer = (
            "Proposed {} pending archive action{} for {!r} into {}. "
            "Nothing was moved; explicit approval is required."
        ).format(
            len(actions),
            "" if len(actions) == 1 else "s",
            subject,
            str(archive_dir),
        )
        return {"intent": "archive", "answer": answer, "documents": documents, "actions": actions}

    # -- Search and extraction helpers ----------------------------------

    def _search_documents(self, query: str, limit: int) -> List[Dict[str, Any]]:
        limit = max(0, int(limit))
        if not query or limit == 0:
            return []
        variants = [query]
        normalized = self._normalize(query)
        if normalized and normalized not in variants:
            variants.append(normalized)
        tokens = self._tokens(query)
        if tokens:
            variants.append(" ".join(tokens))
        found: List[Dict[str, Any]] = []
        seen = set()
        for variant in variants:
            try:
                rows = self.store.search(variant, limit=limit)
            except TypeError:
                rows = self.store.search(variant, limit)
            except (ValueError, KeyError):
                rows = []
            for row in rows or []:
                item = self._document_dict(row)
                key = item.get("id") or item.get("path") or item.get("name")
                if key in seen:
                    continue
                seen.add(key)
                found.append(item)
                if len(found) >= limit:
                    return found
        if found:
            return found
        # Store.search is the primary index path.  The local fallback keeps
        # punctuation/case tolerance even for lightweight Store adapters and
        # makes a missing/empty index an ordinary no-match result.
        try:
            candidates = self.store.list_documents() or []
        except (AttributeError, ValueError, KeyError):
            candidates = []
        for candidate in candidates:
            item = self._document_dict(candidate)
            haystack = self._normalize(
                " ".join(str(item.get(field, "")) for field in ("name", "path", "text"))
            )
            if tokens and all(token in haystack for token in tokens):
                key = item.get("id") or item.get("path") or item.get("name")
                if key not in seen:
                    seen.add(key)
                    found.append(item)
                    if len(found) >= limit:
                        break
        return found

    def _matching_documents(self, subject: str, limit: int) -> List[Dict[str, Any]]:
        max_results = max(0, int(limit))
        tokens = self._tokens(subject)
        if not tokens or max_results == 0:
            return []
        candidates: Iterable[Any]
        try:
            candidates = self.store.list_documents() or []
        except (AttributeError, ValueError, KeyError):
            candidates = self._search_documents(subject, limit)
        matches: List[Dict[str, Any]] = []
        seen = set()
        for candidate in candidates:
            document = self._document_dict(candidate)
            haystack = self._normalize(
                " ".join(
                    str(document.get(field, ""))
                    for field in ("name", "path", "text")
                )
            )
            if all(token in haystack for token in tokens):
                key = document.get("id") or document.get("path") or document.get("name")
                if key not in seen:
                    seen.add(key)
                    matches.append(document)
                    if len(matches) >= max_results:
                        break
        return matches

    def _query_text(self, text: str, intent: str) -> str:
        query = re.sub(
            r"^\s*(?:please\s+)?(?:find|search|query|show|list|look\s+for)\b",
            "",
            text,
            flags=re.I,
        )
        if intent == "invoice":
            # Keep invoice/bill as a useful discriminator while removing only
            # conversational amount wording and filler words.
            query = re.sub(
                r"\b(?:how\s+much|what(?:'s| is)?|tell\s+me|the|a|an|from|for|of|was|were)\b",
                " ",
                query,
                flags=re.I,
            )
            query = re.sub(r"\b(?:amount|total)\b", " ", query, flags=re.I)
        query = re.sub(r"\s+", " ", query).strip(" \t\r\n,.;:!?-")
        return query or text.strip()

    @staticmethod
    def _archive_subject(text: str) -> str:
        subject = re.sub(
            r"^\s*(?:please\s+)?(?:archive|archiving|file\s+away)\b", "", text, flags=re.I
        )
        subject = re.sub(r"^\s*(?:the|a|an)\s+", "", subject, flags=re.I)
        subject = re.sub(r"\b(?:file|files|document|documents)\b", "", subject, flags=re.I)
        subject = re.sub(r"\b(?:for\s+me|please)\b", "", subject, flags=re.I)
        subject = re.sub(r"\s+", " ", subject).strip(" \t\r\n,.;:!?-")
        subject = re.sub(r"(?:'s|’s)$", "", subject, flags=re.I).strip()
        return subject

    @staticmethod
    def _normalize(value: Any) -> str:
        # Punctuation becomes spaces so "Fred's_invoice" and "Fred invoice"
        # have the same searchable tokens while preserving word boundaries.
        return re.sub(r"[^\w]+", " ", str(value or "").casefold(), flags=re.UNICODE).strip()

    @classmethod
    def _tokens(cls, value: Any) -> List[str]:
        return [token for token in cls._normalize(value).split() if token]

    @staticmethod
    def _extract_amounts(value: Any) -> List[str]:
        text = str(value or "")
        pattern = re.compile(
            r"(?<![\w])(?:[$€£]\s?\d+(?:,\d{3})*(?:\.\d{2})?|"
            r"\d+(?:,\d{3})*(?:\.\d{2})?\s?(?:USD|EUR|GBP|dollars?|euros?|pounds?))"
            r"(?![\w])",
            flags=re.I,
        )
        return [match.group(0).strip() for match in pattern.finditer(text)]
    @staticmethod
    def _document_dict(document: Any) -> Dict[str, Any]:
        if isinstance(document, Mapping):
            return dict(document)
        try:
            keys = document.keys()
        except AttributeError:
            keys = None
        if keys is not None:
            try:
                return {key: document[key] for key in keys}
            except (KeyError, TypeError):
                pass
        try:
            return dict(document)
        except (TypeError, ValueError):
            fields = (
                "id", "path", "name", "mime_type", "size", "sha256", "text",
                "created_at", "modified_at", "metadata_json",
            )
            return {field: getattr(document, field, None) for field in fields}

    @staticmethod
    def _safe_subject(subject: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", subject).strip("._-")
        return safe[:100] or "Unsorted"

    def _action_result(self, created: Any) -> Dict[str, Any]:
        if isinstance(created, Mapping):
            return dict(created)
        # Stores commonly return the inserted id.  Recover the persisted action
        # so callers can show its status and audit fields immediately.
        try:
            action_id = int(created)
        except (TypeError, ValueError):
            return {"id": created, "status": "pending"}
        try:
            actions = self.store.list_actions()
            for action in actions or []:
                item = self._document_dict(action)
                if str(item.get("id")) == str(action_id):
                    return item
        except (AttributeError, ValueError, KeyError):
            pass
        return {"id": action_id, "status": "pending"}


