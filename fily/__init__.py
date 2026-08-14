"""Explainable, approval-first local filing system."""

from .agent import FilyAgent
from .cli import main
from .ingest import ingest_path
from .store import Store

__all__ = ["FilyAgent", "Store", "ingest_path", "main"]
__version__ = "0.1.0"
