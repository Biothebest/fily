"""Small dependency-free Gmail REST client.

The client deliberately implements only the installed-application OAuth flow and
read-only Gmail endpoints needed by Fily.  OAuth token exchange/refresh uses
POST as required by Google's OAuth protocol; Gmail API requests are GET-only.
"""

from __future__ import annotations

import http.server
import json
import os
from pathlib import Path
import secrets
import tempfile
import threading
import time
from typing import Any, Dict, List, Mapping, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlencode, urlparse
from urllib.request import Request, urlopen
import webbrowser


GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
_GMAIL_API_ROOT = "https://gmail.googleapis.com/gmail/v1/users/me"
_DEFAULT_TOKEN_PATH = Path.home() / ".fily" / "gmail-token.json"


def load_client_secret(path: os.PathLike[str] | str) -> Dict[str, str]:
    """Load and validate a Google OAuth client JSON file.

    Google publishes both ``installed`` and ``web`` client files.  The
    selected inner object is returned as a plain mapping after validating the
    fields required by the OAuth flow.
    """

    if path is None or not str(path).strip():
        raise RuntimeError(
            "Gmail OAuth client JSON is required; provide client_secret_path "
            "from Google Cloud Console"
        )
    client_path = Path(path).expanduser()
    try:
        with client_path.open("r", encoding="utf-8") as handle:
            document = json.load(handle)
    except FileNotFoundError as exc:
        raise RuntimeError(
            "Gmail OAuth client JSON was not found; provide a valid client_secret_path"
        ) from exc
    except OSError as exc:
        raise RuntimeError("Unable to read Gmail OAuth client JSON") from exc
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("Gmail OAuth client JSON is not valid JSON") from exc

    if not isinstance(document, dict):
        raise RuntimeError("Gmail OAuth client JSON must contain an installed or web object")
    config: Any = document.get("installed") or document.get("web")
    if not isinstance(config, dict):
        raise RuntimeError("Gmail OAuth client JSON must contain an installed or web object")

    required = ("client_id", "client_secret", "auth_uri", "token_uri")
    missing = [key for key in required if not isinstance(config.get(key), str) or not config[key]]
    if missing:
        raise RuntimeError(
            "Gmail OAuth client JSON is missing required fields: " + ", ".join(missing)
        )
    return dict(config)


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    """Placeholder base used only to make callback handler construction clear."""

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        # Request paths can contain an authorization code.  Never log them.
        return None


class GmailClient:
    """Read-only Gmail REST client using standard-library HTTP and OAuth."""

    def __init__(
        self,
        client_secret_path: os.PathLike[str] | str,
        token_path: Optional[os.PathLike[str] | str] = None,
        account_hint: Optional[str] = None,
    ) -> None:
        self.client = load_client_secret(client_secret_path)
        self.token_path = Path(token_path).expanduser() if token_path is not None else _DEFAULT_TOKEN_PATH
        self.account_hint = account_hint
        self._token: Optional[Dict[str, Any]] = None
        self._request_timeout = 30.0

    def authorize(self, open_browser: bool = True) -> Dict[str, Any]:
        """Load, refresh, or obtain an OAuth token and return its token mapping."""

        token = self._load_token()
        if token is not None and self._token_is_valid(token):
            self._token = token
            return dict(token)

        if token is not None and token.get("refresh_token"):
            try:
                refreshed = self._refresh_token(str(token["refresh_token"]))
            except RuntimeError:
                # A revoked/invalid refresh token requires interactive consent.
                refreshed = None
            if refreshed is not None:
                if not refreshed.get("refresh_token"):
                    refreshed["refresh_token"] = token["refresh_token"]
                self._save_token(refreshed)
                self._token = refreshed
                return dict(refreshed)

        token = self._interactive_authorize(open_browser=open_browser)
        self._save_token(token)
        self._token = token
        return dict(token)

    def list_messages(self, query: str = "", max_messages: int = 100) -> Dict[str, Any]:
        """List at most ``max_messages`` message references across Gmail pages.

        The returned mapping uses ``messages`` and ``next_page_token`` keys.
        The token is non-null only when the requested bound stopped pagination.
        """

        if isinstance(max_messages, bool) or not isinstance(max_messages, int):
            raise ValueError("max_messages must be a non-negative integer")
        if max_messages < 0:
            raise ValueError("max_messages must be a non-negative integer")
        if not isinstance(query, str):
            raise ValueError("query must be a string")
        if max_messages == 0:
            return {"messages": [], "next_page_token": None}

        messages: List[Dict[str, Any]] = []
        page_token: Optional[str] = None
        seen_tokens = set()
        while len(messages) < max_messages:
            remaining = max_messages - len(messages)
            params: Dict[str, str] = {"maxResults": str(min(500, remaining))}
            if query:
                params["q"] = query
            if page_token:
                params["pageToken"] = page_token
            response = self._gmail_get("messages", params)
            page_messages = response.get("messages", [])
            if not isinstance(page_messages, list):
                raise RuntimeError("Gmail API returned an invalid messages list")
            for item in page_messages:
                if isinstance(item, dict):
                    messages.append(dict(item))
                    if len(messages) >= max_messages:
                        break

            next_token = response.get("nextPageToken", response.get("next_page_token"))
            if not isinstance(next_token, str) or not next_token:
                page_token = None
                break
            if next_token in seen_tokens or next_token == page_token:
                raise RuntimeError("Gmail API returned a repeating page token")
            seen_tokens.add(next_token)
            page_token = next_token
            # A malformed empty page with a next token is still safe to follow,
            # but a repeating-token guard above prevents an infinite loop.

        return {"messages": messages[:max_messages], "next_page_token": page_token}

    def get_message(self, message_id: str, format: str = "full") -> Dict[str, Any]:  # noqa: A002
        """Fetch one Gmail message using the read-only ``messages.get`` endpoint."""

        if not isinstance(message_id, str) or not message_id.strip():
            raise ValueError("message_id must be a non-empty string")
        if format not in {"full", "minimal", "metadata", "raw"}:
            raise ValueError("format must be one of: full, minimal, metadata, raw")
        response = self._gmail_get("messages/" + quote(message_id, safe=""), {"format": format})
        return response

    def _gmail_get(self, resource: str, params: Mapping[str, str]) -> Dict[str, Any]:
        """Perform one authenticated Gmail GET, retrying once after a 401."""

        token = self._ensure_access_token()
        try:
            return self._request_json(resource, params, token)
        except _UnauthorizedError:
            # An expiry race can happen after the local expiry check.  Refresh
            # once if possible, without ever attempting a Gmail mutation.
            refresh_token = token.get("refresh_token") if self._token else None
            if not refresh_token:
                raise RuntimeError("Gmail authorization expired; run authorize again")
            refreshed = self._refresh_token(str(refresh_token))
            refreshed.setdefault("refresh_token", refresh_token)
            self._save_token(refreshed)
            self._token = refreshed
            try:
                return self._request_json(resource, params, refreshed)
            except _UnauthorizedError as exc:
                raise RuntimeError("Gmail API rejected refreshed authorization (HTTP 401)") from exc

    def _ensure_access_token(self) -> Dict[str, Any]:
        if self._token is None:
            self.authorize(open_browser=True)
        if self._token is None or not self._token.get("access_token"):
            raise RuntimeError("Gmail authorization did not provide an access token")
        if self._token_is_valid(self._token):
            return self._token
        refresh_token = self._token.get("refresh_token")
        if refresh_token:
            refreshed = self._refresh_token(str(refresh_token))
            refreshed.setdefault("refresh_token", refresh_token)
            self._save_token(refreshed)
            self._token = refreshed
            return refreshed
        self.authorize(open_browser=True)
        if self._token is None or not self._token.get("access_token"):
            raise RuntimeError("Gmail authorization did not provide an access token")
        return self._token

    def _request_json(
        self, resource: str, params: Mapping[str, str], token: Mapping[str, Any]
    ) -> Dict[str, Any]:
        query = urlencode(dict(params))
        url = _GMAIL_API_ROOT + "/" + resource
        if query:
            url += "?" + query
        request = Request(
            url,
            headers={
                "Accept": "application/json",
                "Authorization": "Bearer " + str(token["access_token"]),
            },
            method="GET",
        )
        try:
            with urlopen(request, timeout=self._request_timeout) as response:
                body = response.read()
        except HTTPError as exc:
            if exc.code == 401:
                raise _UnauthorizedError() from exc
            error_body: Any = b""
            try:
                error_body = exc.read()
            except (OSError, ValueError):
                pass
            raise self._api_error(exc.code, error_body) from exc
        except URLError as exc:
            raise RuntimeError("Unable to reach Gmail API") from exc
        except OSError as exc:
            raise RuntimeError("Unable to read Gmail API response") from exc

        try:
            decoded = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("Gmail API returned invalid JSON") from exc
        if not isinstance(decoded, dict):
            raise RuntimeError("Gmail API returned an invalid JSON object")
        return decoded

    @staticmethod
    def _api_error(status: int, body: Any) -> RuntimeError:
        # Only include stable, non-secret error labels.  Never echo response
        # bodies because a proxy or test endpoint could place tokens in them.
        reason = ""
        try:
            if isinstance(body, bytes):
                payload = json.loads(body.decode("utf-8"))
            elif isinstance(body, str):
                payload = json.loads(body)
            else:
                payload = {}
            error = payload.get("error", {}) if isinstance(payload, dict) else {}
            if isinstance(error, dict):
                status_name = error.get("status")
                if isinstance(status_name, str) and status_name.isidentifier():
                    reason = status_name
                if not reason:
                    details = error.get("errors")
                    if isinstance(details, list) and details and isinstance(details[0], dict):
                        candidate = details[0].get("reason")
                        if isinstance(candidate, str) and candidate.isidentifier():
                            reason = candidate
        except (UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError):
            pass
        suffix = ": " + reason if reason else ""
        return RuntimeError("Gmail API request failed (HTTP %s)%s" % (status, suffix))

    def _load_token(self) -> Optional[Dict[str, Any]]:
        try:
            with self.token_path.open("r", encoding="utf-8") as handle:
                token = json.load(handle)
        except FileNotFoundError:
            return None
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("Gmail OAuth token file could not be read") from exc
        if not isinstance(token, dict):
            raise RuntimeError("Gmail OAuth token file must contain a JSON object")
        return token

    @staticmethod
    def _token_is_valid(token: Mapping[str, Any]) -> bool:
        access_token = token.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            return False
        expiry = token.get("expires_at")
        if expiry is None:
            expiry = token.get("expiry")
        if expiry is None:
            # Some manually provisioned token files omit expiry.  Let the API
            # decide; a 401 path still performs a refresh when available.
            return True
        try:
            return float(expiry) > time.time() + 60
        except (TypeError, ValueError):
            return False

    def _save_token(self, token: Mapping[str, Any]) -> None:
        data = dict(token)
        if "expires_at" not in data and data.get("expires_in") is not None:
            try:
                data["expires_at"] = time.time() + float(data["expires_in"])
            except (TypeError, ValueError):
                pass
        parent = self.token_path.parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(parent, 0o700)
            except OSError:
                pass
            fd, temporary = tempfile.mkstemp(prefix=".gmail-token-", dir=str(parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(data, handle)
                    handle.write("\n")
                try:
                    os.chmod(temporary, 0o600)
                except OSError:
                    pass
                os.replace(temporary, self.token_path)
            finally:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
        except OSError as exc:
            raise RuntimeError("Unable to securely save Gmail OAuth token") from exc

    def _refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        form = {
            "client_id": self.client["client_id"],
            "client_secret": self.client["client_secret"],
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }
        return self._oauth_post(form, "refresh")

    def _exchange_code(self, code: str, redirect_uri: str) -> Dict[str, Any]:
        form = {
            "client_id": self.client["client_id"],
            "client_secret": self.client["client_secret"],
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
        return self._oauth_post(form, "authorization")

    def _oauth_post(self, form: Mapping[str, str], operation: str) -> Dict[str, Any]:
        request = Request(
            self.client["token_uri"],
            data=urlencode(dict(form)).encode("ascii"),
            headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self._request_timeout) as response:
                body = response.read()
        except HTTPError as exc:
            # Deliberately avoid response text: OAuth responses can contain
            # values that must never appear in exception messages.
            raise RuntimeError("Gmail OAuth %s request failed (HTTP %s)" % (operation, exc.code)) from exc
        except (URLError, OSError) as exc:
            raise RuntimeError("Unable to reach Gmail OAuth endpoint") from exc
        try:
            decoded = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("Gmail OAuth endpoint returned invalid JSON") from exc
        if not isinstance(decoded, dict) or not isinstance(decoded.get("access_token"), str):
            raise RuntimeError("Gmail OAuth endpoint returned no access token")
        return decoded

    def _interactive_authorize(self, open_browser: bool) -> Dict[str, Any]:
        state = secrets.token_urlsafe(32)
        callback: Dict[str, Optional[str]] = {"code": None, "error": None, "state": None}
        event = threading.Event()

        class CallbackHandler(_CallbackHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib signature
                parsed = urlparse(self.path)
                if parsed.path != "/oauth2callback":
                    self.send_response(404)
                    self.end_headers()
                    return
                values = parse_qs(parsed.query, keep_blank_values=True)
                callback["code"] = values.get("code", [None])[0]
                callback["error"] = values.get("error", [None])[0]
                callback["state"] = values.get("state", [None])[0]
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"<html><body>Authorization received. You may close this window.</body></html>")
                event.set()

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CallbackHandler)
        redirect_uri = "http://127.0.0.1:%d/oauth2callback" % server.server_address[1]
        values = {
            "client_id": self.client["client_id"],
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": GMAIL_READONLY_SCOPE,
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
        }
        if self.account_hint:
            values["login_hint"] = self.account_hint
        authorization_url = self.client["auth_uri"] + "?" + urlencode(values)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            print("Gmail authorization URL (open manually if needed): " + authorization_url, flush=True)
            if open_browser:
                try:
                    opened = webbrowser.open(authorization_url)
                    if not opened:
                        print("The browser could not be opened; use the URL above.", flush=True)
                except Exception:
                    print("The browser could not be opened; use the URL above.", flush=True)
            if not event.wait(timeout=300):
                raise RuntimeError("Timed out waiting for Gmail OAuth callback")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        if callback["error"]:
            raise RuntimeError("Gmail OAuth authorization was denied or failed")
        if callback["state"] != state or not callback["code"]:
            raise RuntimeError("Gmail OAuth callback was invalid")
        return self._exchange_code(callback["code"], redirect_uri)


class _UnauthorizedError(Exception):
    """Internal marker for a Gmail 401 response."""
