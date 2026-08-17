"""Command-line interface for the local-first filing system.

The CLI deliberately keeps destructive operations behind the explicit
``approve`` then ``execute`` commands.  It is a thin composition layer over
:mod:`fily.store`, :mod:`fily.ingest`, and :mod:`fily.agent`.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

from .agent import FilyAgent
from .ingest import ingest_path
from .store import Store
from .gmail import GmailClient
from .gmail_sync import sync_gmail

DEFAULT_LIBRARY = Path("~/FilyLibrary")
DEFAULT_GMAIL_ACCOUNT = "matthew.benitez23@gmail.com"


def _library(value: Optional[str]) -> Path:
    """Resolve a library argument, including the default location."""
    return Path(value).expanduser() if value else DEFAULT_LIBRARY.expanduser()


def _jsonable(value: Any) -> Any:
    """Convert common result objects to values accepted by ``json.dumps``."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except (AttributeError, TypeError, ValueError):
            pass
    if hasattr(value, "__dict__"):
        return _jsonable(vars(value))
    return str(value)


def _print_json(value: Any) -> None:
    print(json.dumps(_jsonable(value), indent=2, sort_keys=True))


def _display_name(document: Any) -> str:
    if isinstance(document, dict):
        return str(document.get("name") or document.get("path") or document.get("id", "document"))
    return str(document)


def _document_text(document: Any) -> str:
    if not isinstance(document, dict):
        return ""
    text = document.get("text")
    return str(text) if text else ""


def _extract_invoice_details(result: Any, documents: Iterable[Any]) -> Any:
    """Return agent-provided invoice information, with a useful fallback.

    Agent implementations may use ``invoices``, ``invoice_amounts``, or an
    ``evidence`` field.  Preserve those fields unchanged; when absent, scan
    returned document metadata/text so ``ask`` remains useful with a minimal
    agent implementation.
    """
    if isinstance(result, dict):
        for key in ("invoices", "invoice_amounts", "amounts", "invoice_evidence"):
            if result.get(key):
                return result[key]
        if result.get("evidence"):
            return result["evidence"]
    fallback = []
    for document in documents:
        if not isinstance(document, dict):
            continue
        # FilyAgent attaches both parsed amounts and their exact textual
        # evidence to invoice documents.  Keep those values visible instead
        # of reducing the answer to a filename.
        amounts = document.get("amounts")
        evidence = document.get("amount_evidence")
        if amounts or evidence:
            fallback.append({
                "document": _display_name(document),
                "amounts": amounts or [],
                "evidence": evidence or [],
            })
            continue
        metadata = document.get("metadata_json")
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except (TypeError, ValueError):
                metadata = {}
        if not isinstance(metadata, dict):
            metadata = {}
        values = {k: v for k, v in metadata.items() if "invoice" in k.lower() or "amount" in k.lower() or "total" in k.lower()}
        text = _document_text(document)
        if values or ("invoice" in text.lower() and any(ch.isdigit() for ch in text)):
            fallback.append({"document": _display_name(document), "values": values, "evidence": text[:500] if text else None})
    return fallback


def _pending_actions(store: Store) -> list:
    try:
        return list(store.list_actions(status="pending"))
    except TypeError:
        # Compatibility with stores whose optional argument is positional.
        return list(store.list_actions("pending"))


def _agent_answer(store: Store, question: str) -> Any:
    agent = FilyAgent(store)
    ask = getattr(agent, "ask", None)
    if not callable(ask):
        raise RuntimeError("FilyAgent does not provide ask(question)")
    return ask(question)


def _ask(store: Store, question: str, as_json: bool) -> int:
    result = _agent_answer(store, question)
    if isinstance(result, dict):
        documents = result.get("documents") or result.get("matches") or result.get("results") or []
    elif isinstance(result, list):
        documents = result
    else:
        documents = []
    # A response may be prose-only; search independently so matching files and
    # pending actions are still visible in the CLI contract.
    if not documents:
        try:
            documents = list(store.search(question, limit=20))
        except TypeError:
            documents = list(store.search(question))
    pending = _pending_actions(store)
    if not pending and isinstance(result, dict):
        pending = list(result.get("actions") or [])
    invoice_details = _extract_invoice_details(result, documents)
    payload = {
        "question": question,
        "answer": result,
        "documents": documents,
        "invoice_amounts_and_evidence": invoice_details,
        "pending_actions": pending,
    }
    if as_json:
        _print_json(payload)
        return 0

    print("Answer:")
    if isinstance(result, str):
        print(result)
    elif isinstance(result, dict):
        answer = result.get("answer") or result.get("response") or result.get("summary")
        print(answer if answer is not None else json.dumps(_jsonable(result), sort_keys=True))
    else:
        print(json.dumps(_jsonable(result), sort_keys=True))
    print("Documents:")
    if documents:
        for document in documents:
            if isinstance(document, dict):
                detail = document.get("path") or document.get("name") or document.get("id")
                print("- {}".format(detail))
            else:
                print("- {}".format(document))
    else:
        print("- none")
    print("Invoice amounts/evidence:")
    if invoice_details:
        print(json.dumps(_jsonable(invoice_details), sort_keys=True))
    else:
        print("- none found")
    print("Pending archive actions:")
    if pending:
        for action in pending:
            if isinstance(action, dict):
                print("- #{id} {type}: {reason} (confidence {confidence})".format(
                    id=action.get("id", "?"), type=action.get("type", "action"),
                    reason=action.get("reason", "no reason"), confidence=action.get("confidence", "?")))
            else:
                print("- {}".format(action))
    else:
        print("- none")
    return 0


def _ingest(store: Store, sources: Sequence[str]) -> int:
    if not sources:
        raise ValueError("ingest requires at least one source path")
    summary = {"ingested": [], "skipped": [], "errors": []}
    for source in sources:
        value = ingest_path(store, Path(source).expanduser(), recursive=True)
        if isinstance(value, dict):
            for key in summary:
                item = value.get(key, [])
                if isinstance(item, list):
                    summary[key].extend(item)
                elif item:
                    summary[key].append(item)
        elif value is not None:
            summary["ingested"].append(value)
    print("Ingested {} file(s); skipped {}; errors {}.".format(
        len(summary["ingested"]), len(summary["skipped"]), len(summary["errors"])))
    if summary["errors"]:
        for error in summary["errors"]:
            print("error: {}".format(error), file=sys.stderr)
    return 1 if summary["errors"] and not summary["ingested"] else 0


def _print_documents(documents: Sequence[Any], as_json: bool) -> int:
    if as_json:
        _print_json(list(documents))
    elif documents:
        for document in documents:
            if isinstance(document, dict):
                print("{id}: {name} ({path})".format(
                    id=document.get("id", "?"), name=document.get("name") or "(unnamed)", path=document.get("path", "")))
            else:
                print(document)
    else:
        print("No documents found.")
    return 0


def _print_actions(actions: Sequence[Any], as_json: bool) -> int:
    if as_json:
        _print_json(list(actions))
    elif actions:
        for action in actions:
            if isinstance(action, dict):
                print("#{id} [{status}] {type} confidence={confidence}: {reason}".format(
                    id=action.get("id", "?"), status=str(action.get("status", "unknown")).upper(),
                    type=action.get("type", "action"), confidence=action.get("confidence", "?"),
                    reason=action.get("reason", "")))
            else:
                print(action)
    else:
        print("No actions found.")
    return 0


def _looks_like_library(value: str) -> bool:
    path = Path(value).expanduser()
    return (
        path.exists() and path.is_dir()
    ) or value.startswith(("~", "/", "./", "../")) or os.sep in value


def _items_library(items: Sequence[str], rest_required: bool, command: str) -> tuple:
    """Split optional library from positional command items.

    The grammar intentionally permits a default library.  For commands with
    free-form questions, a path-like first item is therefore the explicit
    library while ordinary words remain part of the question.
    """
    if not items:
        return None, []
    if command == "ingest":
        if len(items) == 1:
            return None, list(items)
        # Multiple existing files are naturally multiple default-library
        # sources; a directory/path-like first item denotes an explicit root.
        first = Path(items[0]).expanduser()
        if first.is_file() or all(Path(item).expanduser().is_file() for item in items):
            return None, list(items)
        return items[0], list(items[1:])
    if rest_required and len(items) == 1:
        return None, list(items)
    if rest_required and command == "ask" and not _looks_like_library(items[0]):
        return None, list(items)
    if rest_required:
        return items[0], list(items[1:])
    return items[0], []


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fily", description="Local-first, approval-first filing system")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create a filing library")
    p.add_argument("library", nargs="?", help="library directory (default: ~/FilyLibrary)")

    p = sub.add_parser("ingest", help="ingest local files or exported email files")
    p.add_argument("items", nargs="+", metavar="PATH")

    p = sub.add_parser("ask", help="search and ask a natural-language question")
    p.add_argument("items", nargs="+", metavar="TEXT")
    p.add_argument("--json", action="store_true", dest="as_json")

    p = sub.add_parser("list", help="list ingested documents")
    p.add_argument("library", nargs="?")
    p.add_argument("--json", action="store_true", dest="as_json")

    p = sub.add_parser("actions", help="list proposed archive actions")
    p.add_argument("library", nargs="?")
    p.add_argument("--status")
    p.add_argument("--json", action="store_true", dest="as_json")

    p = sub.add_parser("gmail-auth", help="authorize read-only access to Gmail")
    p.add_argument("--client-secret", required=True, help="Google OAuth client JSON")
    p.add_argument("--token-path", help="token file (default: ~/.fily/gmail-token.json)")
    p.add_argument("--account", default=DEFAULT_GMAIL_ACCOUNT)
    p.add_argument("--no-browser", action="store_true", help="print the consent URL instead of opening a browser")

    p = sub.add_parser("gmail-sync", help="sync Gmail messages into the local read-only index")
    p.add_argument("library", nargs="?", help="library directory (default: ~/FilyLibrary)")
    p.add_argument("--client-secret", required=True, help="Google OAuth client JSON")
    p.add_argument("--token-path", help="token file (default: ~/.fily/gmail-token.json)")
    p.add_argument("--account", default=DEFAULT_GMAIL_ACCOUNT)
    p.add_argument("--query", default="", help="Gmail search query, e.g. from:fred invoice")
    p.add_argument("--max-messages", type=int, default=100)
    p.add_argument("--page-token", help="resume from a prior JSON result's next_page_token")
    p.add_argument("--no-browser", action="store_true", help="do not open a browser during first authorization")
    p.add_argument("--json", action="store_true", dest="as_json")

    for name in ("approve", "reject", "execute"):
        p = sub.add_parser(name, help="{} an archive action".format(name))
        p.add_argument("items", nargs="+", metavar="ID")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        command = args.command
        if command == "gmail-auth":
            client = GmailClient(args.client_secret, args.token_path, args.account)
            token = client.authorize(open_browser=not args.no_browser)
            if isinstance(token, dict):
                _print_json(
                    {
                        "account": args.account,
                        "token_path": str(client.token_path),
                        "scope": token.get("scope") or token.get("scopes"),
                    }
                )
            else:
                print("Gmail authorization complete for {}.".format(args.account))
            return 0

        if command == "gmail-sync":
            root = _library(args.library)
            store = Store(root)
            client = GmailClient(args.client_secret, args.token_path, args.account)
            client.authorize(open_browser=not args.no_browser)
            result = sync_gmail(
                store,
                client,
                query=args.query,
                max_messages=args.max_messages,
                page_token=args.page_token,
            )
            if args.as_json:
                _print_json(result)
            else:
                print(
                    "Synced {} Gmail message(s); skipped {}; errors {}.".format(
                        len(result.get("synced", [])),
                        len(result.get("skipped", [])),
                        len(result.get("errors", [])),
                    )
                )
                for error in result.get("errors", []):
                    print("error: {}".format(error), file=sys.stderr)
            return 1 if result.get("errors") and not result.get("synced") else 0

        if command == "init":
            root = _library(args.library)
            root.mkdir(parents=True, exist_ok=True)
            store = Store(root)
            store.initialize()
            print("Initialized Fily library at {}".format(root))
            return 0

        if command == "ingest":
            library_name, sources = _items_library(args.items, True, command)
            store = Store(_library(library_name))
            store.initialize()
            return _ingest(store, sources)

        if command == "ask":
            library_name, question_items = _items_library(args.items, True, command)
            if not question_items:
                raise ValueError("ask requires a question")
            store = Store(_library(library_name))
            store.initialize()
            return _ask(store, " ".join(question_items), args.as_json)

        if command == "list":
            store = Store(_library(args.library))
            store.initialize()
            return _print_documents(list(store.list_documents()), args.as_json)

        if command == "actions":
            store = Store(_library(args.library))
            store.initialize()
            actions = store.list_actions(status=args.status) if args.status else store.list_actions()
            return _print_actions(list(actions), args.as_json)

        library_name, ids = _items_library(args.items, True, command)
        if not ids:
            raise ValueError("{} requires an action id".format(command))
        if len(ids) > 1:
            raise ValueError("{} accepts one action id".format(command))
        store = Store(_library(library_name))
        store.initialize()
        action_id = ids[0]
        if command == "approve":
            action = store.approve_action(action_id)
            print("Approved action #{}; execute explicitly to apply it.".format(action_id))
        elif command == "reject":
            action = store.reject_action(action_id)
            print("Rejected action #{}; no filesystem change was made.".format(action_id))
        else:
            action = store.execute_action(action_id)
            print("Executed action #{}.".format(action_id))
        if action is not None:
            _print_json(action)
        return 0
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        # Keep command-line failures concise while still returning a failure
        # status; unexpected exceptions remain visible to callers in tests.
        print("error: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
