"""Offline audit verifier (`python -m tools.verify_audit export.json`). CONTRACTS.md §7.3 last paragraph.

Owner: WS-A.
"""
from __future__ import annotations

from typing import Any


def verify(export: dict[str, Any]) -> list[str]:
    """List of problems (empty = OK): leaf hashes, seq gaps, roots vs STH, sigs, anchors, consistency, ledger<->execution, decision replay."""
    raise NotImplementedError("TODO WS-A")


def main(argv: list[str] | None = None) -> int:
    """CLI; exit 1 on any problem."""
    raise NotImplementedError("TODO WS-A")


if __name__ == "__main__":
    raise SystemExit(main())
