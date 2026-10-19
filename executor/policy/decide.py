"""Pure decision function (replayed offline by tools/verify_audit.py). CONTRACTS.md §2.2. No I/O, no LLM.

Owner: WS-E.
"""
from __future__ import annotations

from typing import Any


def decide(invoice: dict[str, Any], vendor: dict[str, Any] | None, facts: list[dict[str, Any]], mandate: dict[str, Any] | None, history: list[dict[str, Any]], *, now: Any, policy_hash: str) -> dict[str, Any]:
    """Return Decision object without 'challenge' (caller attaches it). H facts never change the outcome (S3)."""
    raise NotImplementedError("TODO WS-E")
