"""Seed vendors, policies, emails (via POST /ingest) into a backend. CONTRACTS.md §1, §4.1 #21.

Owner: WS-E.
"""
from __future__ import annotations

from typing import Any


def seed(*, settings: Any = None, data_dir: str = 'data') -> None:
    """Load data/*.json and emails into the store."""
    raise NotImplementedError("TODO WS-E")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    raise NotImplementedError("TODO WS-E")


if __name__ == "__main__":
    raise SystemExit(main())
