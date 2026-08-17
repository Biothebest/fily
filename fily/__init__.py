"""Explainable, approval-first local filing system."""

from .agent import FilyAgent
from .cli import main
from .ingest import ingest_path
from .store import Store
from .gmail import GmailClient
from .gmail_sync import sync_gmail

__all__ = ["FilyAgent", "GmailClient", "Store", "ingest_path", "main", "sync_gmail"]
__version__ = "0.1.0"
