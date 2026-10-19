"""Helpers that compute the Cedar context from snapshots/ledger (pure). CONTRACTS.md v2 §8.1.

The rules themselves are Cedar policies (executor/policy/cedar/). Owner: WS-A.
"""
from __future__ import annotations

from typing import Any


def cedar_context(subject: dict[str, Any], facts: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """Context for action `pay` per cedar schema: amount_minor, vop, reg_hit, warn_hit, block_hit, warn_count,
    anom, dup, split_sum, z_hit, now (epoch s), attest_count. [F] only."""
    raise NotImplementedError("TODO WS-A")


def is_duplicate(invoice: dict[str, Any], history: list[dict[str, Any]]) -> bool:
    """I-DUP: normalized invoice no, or (vendor, amount +-50 bp, issue_date +-3 d) EXECUTED/PENDING_SIG."""
    raise NotImplementedError("TODO WS-A")


def split_sum(invoice: dict[str, Any], history: list[dict[str, Any]], *, now: Any) -> int:
    """I-SPLIT: executed sum for the vendor in the last 24 h (minor units)."""
    raise NotImplementedError("TODO WS-A")


def z_hit(invoice: dict[str, Any], history: list[dict[str, Any]]) -> bool:
    """I-Z: robust z-score (median/MAD) > 3.5."""
    raise NotImplementedError("TODO WS-A")


def normalize_invoice_no(invoice_no: str) -> str:
    """Uppercase, strip non-alphanumerics, strip leading zeros of numeric runs."""
    raise NotImplementedError("TODO WS-A")
