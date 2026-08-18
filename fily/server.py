"""Local-only JSON API for the Fily desktop application."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Mapping, Optional
from urllib.parse import parse_qs, unquote, urlparse

from .agent import FilyAgent
from .api_contract import openapi_document
from .jobs import extract_job_applications
from .store import Store

_API_VERSION = "v1"
_ALLOWED_ORIGIN_HOSTS = ("http://localhost", "http://127.0.0.1", "tauri://localhost")


def _accounts(store: Store) -> list:
    accounts: Dict[tuple, Dict[str, Any]] = {}
    for document in store.list_documents():
        try:
            metadata = json.loads(document.get("metadata_json") or "{}")
        except (TypeError, ValueError):
            continue
        if not isinstance(metadata, Mapping):
            continue
        provider = str(metadata.get("source") or "local")
        address = str(metadata.get("account") or "")
        key = (provider, address)
        current = accounts.setdefault(
            key,
            {
                "id": "%s:%s" % (provider, address or "local"),
                "provider": provider,
                "email": address or None,
                "status": "connected",
                "indexed_messages": 0,
            },
        )
        current["indexed_messages"] += 1
    return sorted(accounts.values(), key=lambda item: (item["provider"], item.get("email") or ""))

def _applications(store: Store, limit: int) -> list:
    return extract_job_applications(store.list_documents(), limit=limit)


def _bootstrap(store: Store, application_limit: int) -> Dict[str, Any]:
    accounts = _accounts(store)
    applications = _applications(store, application_limit)
    stage_counts: Dict[str, int] = {}
    for application in applications:
        stage = str(application.get("stage") or "Unknown")
        stage_counts[stage] = stage_counts.get(stage, 0) + 1
    return {
        "product": {"name": "Fily", "api_version": _API_VERSION, "mode": "local"},
        "accounts": accounts,
        "smart_views": [
            {
                "id": "job-applications",
                "label": "Job Applications",
                "count": len(applications),
                "stage_counts": stage_counts,
            }
        ],
        "job_applications": applications,
        "assistant": {
            "suggestions": [
                "Show my active job applications",
                "Find emails that need my response",
                "Find the invoice from Fred",
            ]
        },
        "capabilities": {
            "gmail_readonly": True,
            "provider_mutations": False,
            "multi_account": False,
        },
    }


def _handler(store: Store):
    agent = FilyAgent(store)

    class Handler(BaseHTTPRequestHandler):
        server_version = "FilyLocal/0.1"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return None

        def _origin(self) -> Optional[str]:
            origin = self.headers.get("Origin")
            if origin and origin.startswith(_ALLOWED_ORIGIN_HOSTS):
                return origin
            return None

        def _send(self, status: int, payload: Any) -> None:
            body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            origin = self._origin()
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self) -> None:  # noqa: N802
            origin = self._origin()
            if not origin:
                self._send(403, {"error": "origin not allowed"})
                return
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Max-Age", "600")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            try:
                if parsed.path == "/v1/health":
                    self._send(200, {"status": "ok", "api_version": _API_VERSION})
                    return
                if parsed.path == "/v1/openapi.json":
                    self._send(200, openapi_document())
                    return
                if parsed.path == "/v1/bootstrap":
                    query = parse_qs(parsed.query)
                    raw_limit = query.get("application_limit", ["5"])[0]
                    limit = max(1, min(int(raw_limit), 50))
                    self._send(200, _bootstrap(store, limit))
                    return
                if parsed.path == "/v1/accounts":
                    self._send(200, {"accounts": _accounts(store)})
                    return
                if parsed.path == "/v1/job-applications":
                    query = parse_qs(parsed.query)
                    raw_limit = query.get("limit", ["20"])[0]
                    limit = max(1, min(int(raw_limit), 200))
                    applications = _applications(store, limit)
                    self._send(200, {"applications": applications, "count": len(applications)})
                    return
                prefix = "/v1/job-applications/"
                if parsed.path.startswith(prefix):
                    application_id = unquote(parsed.path[len(prefix):])
                    if not application_id or "/" in application_id:
                        self._send(404, {"error": "application not found"})
                        return
                    application = next(
                        (item for item in _applications(store, 200) if item["id"] == application_id),
                        None,
                    )
                    if application is None:
                        self._send(404, {"error": "application not found"})
                    else:
                        self._send(200, {"application": application})
                    return
                self._send(404, {"error": "not found"})
            except (TypeError, ValueError) as exc:
                self._send(400, {"error": str(exc)})
            except Exception:
                self._send(500, {"error": "local API request failed"})

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path != "/v1/ask":
                self._send(404, {"error": "not found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 64 * 1024:
                    raise ValueError("request body must be between 1 byte and 64 KiB")
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(body, Mapping):
                    raise ValueError("request body must be a JSON object")
                question = str(body.get("question") or "").strip()
                if not question:
                    raise ValueError("question is required")
                limit = max(1, min(int(body.get("limit", 20)), 100))
                self._send(200, agent.ask(question, limit=limit))
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
                self._send(400, {"error": str(exc)})
            except Exception:
                self._send(500, {"error": "assistant request failed"})

    return Handler


def create_server(store: Store, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    """Create a local API server; non-loopback binding is intentionally rejected."""
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Fily local API may only bind to a loopback address")
    if not 0 <= int(port) <= 65535:
        raise ValueError("port must be between 0 and 65535")
    return ThreadingHTTPServer((host, int(port)), _handler(store))


def serve(store: Store, host: str = "127.0.0.1", port: int = 8765) -> None:
    server = create_server(store, host=host, port=port)
    print("Fily local API listening on http://%s:%s" % server.server_address, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


__all__ = ["create_server", "serve"]
