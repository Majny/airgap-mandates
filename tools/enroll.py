"""Enroll bank signers from data/enrollment.json into enrolled_signers (+ enroll leaves). CONTRACTS.md §6.

Owner: WS-A.
"""
from __future__ import annotations

from typing import Any


def enroll(path: str = 'data/enrollment.json', *, settings: Any = None) -> int:
    """Number of signers enrolled."""
    raise NotImplementedError("TODO WS-A")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    raise NotImplementedError("TODO WS-A")


if __name__ == "__main__":
    raise SystemExit(main())
