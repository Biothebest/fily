"""Evidence-backed job application cases derived from indexed email."""
from __future__ import annotations

import html
import json
import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

_APPLICATION_MARKERS = (
    "thank you for applying",
    "thanks for applying",
    "application has been received",
    "received your application",
    "application was sent to",
    "confirmation of application receipt",
)

_STAGE_RULES = (
    ("Offer", ("pleased to offer", "offer letter", "employment offer")),
    ("Interview", ("schedule an interview", "interview invitation", "interview availability")),
    ("Assessment", ("complete the assessment", "technical assessment", "coding assessment")),
    ("Rejected", ("not moving forward", "decided to move forward with other", "will not be moving forward")),
    ("Applied", _APPLICATION_MARKERS),
)

_ROLE_PATTERNS = (
    r"applying to our (?P<role>.+?) at (?P<company>.+?)(?:[.!]|\r|\n)",
    r"application to the (?P<role>.+?) position",
    r"submission for the position of (?P<role>.+?)(?:\.|\r|\n)",
    r"application for the (?P<role>.+?) position",
    r"application for the (?P<role>.+?) role",
    r"applying for the (?P<role>.+?) role at (?P<company>.+?)(?:[.!]|\r|\n)",
)

_COMPANY_SUBJECT_PATTERNS = (
    r"(?:applying|application) to (?P<company>.+?)$",
    r"applying to (?P<company>.+?)[!]?\s*$",
)


def _metadata(document: Mapping[str, Any]) -> Dict[str, Any]:
    value = document.get("metadata_json") or "{}"
    if isinstance(value, Mapping):
        return dict(value)
    try:
        decoded = json.loads(str(value))
    except (TypeError, ValueError):
        return {}
    return dict(decoded) if isinstance(decoded, Mapping) else {}


def _clean(value: Any) -> str:
    text = html.unescape(str(value or ""))
    text = re.sub(r"\s+", " ", text).strip(" \t\r\n.,")
    return text


def _date(value: Any) -> Tuple[str, float]:
    raw = str(value or "")
    try:
        parsed = parsedate_to_datetime(raw)
        return parsed.isoformat(), parsed.timestamp()
    except (TypeError, ValueError, OverflowError):
        return raw, 0.0


def _stage(text: str) -> str:
    lowered = text.casefold()
    for stage, markers in _STAGE_RULES:
        if any(marker in lowered for marker in markers):
            return stage
    return "Unknown"


def _role_and_company(subject: str, text: str, sender: str) -> Tuple[str, str]:
    combined = _clean(text)
    for pattern in _ROLE_PATTERNS:
        match = re.search(pattern, combined, flags=re.I)
        if match:
            role = _clean(match.groupdict().get("role"))
            company = _clean(match.groupdict().get("company"))
            if not company:
                company = _company_from_subject(subject)
            if not company:
                company = _company_from_body(combined)
            if not company:
                company = _company_from_sender(sender)
            return role or "Unknown role", company or "Unknown company"
    return "Unknown role", _company_from_subject(subject) or _company_from_body(combined) or _company_from_sender(sender) or "Unknown company"


def _company_from_subject(subject: str) -> str:
    clean_subject = _clean(subject)
    for pattern in _COMPANY_SUBJECT_PATTERNS:
        match = re.search(pattern, clean_subject, flags=re.I)
        if match:
            return _clean(match.group("company"))
    return ""


def _company_from_body(text: str) -> str:
    match = re.search(r"application to join the (?P<company>.+?) team", text, flags=re.I)
    return _clean(match.group("company")) if match else ""


def _company_from_sender(sender: str) -> str:
    display = re.match(r"\s*([^<]+?)\s*<", sender)
    if display:
        value = _clean(display.group(1)).strip('"')
        value = re.sub(r"\s+(?:Hiring|Talent|Recruiting)\s+Team$", "", value, flags=re.I)
        if value and value.casefold() not in {"linkedin", "no-reply"}:
            return value
    address = re.search(r"@([A-Za-z0-9.-]+)", sender)
    if not address:
        return ""
    domain = address.group(1).split(".")[0]
    if domain in {"gmail", "greenhouse-mail", "hire", "ashbyhq", "talent"}:
        return ""
    return domain.replace("-", " ").title()


def extract_job_applications(documents: Iterable[Mapping[str, Any]], limit: int = 20) -> List[Dict[str, Any]]:
    """Return newest distinct application cases with explicit email evidence."""
    maximum = max(1, min(int(limit), 200))
    candidates: List[Tuple[int, float, Dict[str, Any]]] = []
    seen = set()
    for document in documents:
        metadata = _metadata(document)
        if metadata.get("source") != "gmail":
            continue
        subject = _clean(metadata.get("subject"))
        sender = _clean(metadata.get("sender"))
        body = _clean(document.get("text"))
        snippet = _clean(metadata.get("snippet"))
        evidence_source = body or snippet
        searchable = " ".join((subject, evidence_source)).casefold()
        if not any(marker in searchable for marker in _APPLICATION_MARKERS):
            continue
        role, company = _role_and_company(subject, evidence_source, sender)
        key = (company.casefold(), role.casefold())
        if key in seen:
            continue
        seen.add(key)
        date_text, timestamp = _date(metadata.get("date"))
        evidence = evidence_source[:280]
        stage = _stage(searchable)
        complete = role != "Unknown role" and company != "Unknown company"
        candidates.append(
            (
                1 if complete else 0,
                timestamp,
                {
                    "id": "job:%s" % metadata.get("message_id", document.get("id", "")),
                    "company": company,
                    "role": role,
                    "stage": stage,
                    "application_date": date_text,
                    "next_action": "Wait for employer response" if stage == "Applied" else "Review latest message",
                    "evidence": evidence,
                    "evidence_message_id": metadata.get("message_id"),
                    "account": metadata.get("account"),
                    "subject": subject,
                    "confidence": 0.95 if complete else 0.75,
                },
            )
        )
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [item[2] for item in candidates[:maximum]]


__all__ = ["extract_job_applications"]
