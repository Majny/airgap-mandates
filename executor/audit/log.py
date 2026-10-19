"""Audit event append (seq allocation, canonical JSON, leaf hash), log-before-execute (S6). CONTRACTS.md §7.2, §3.2.

Owner: WS-A.
"""
from __future__ import annotations

from typing import Any


def append(event_type: str, data: dict[str, Any], *, subject_id: str | None, actor: str, log_id: str = 'audit', store: Any, settings: Any) -> int:
    """Append one leaf; returns seq. Triggers STH every N leaves."""
    raise NotImplementedError("TODO WS-A")


def export(log_id: str, from_seq: int, *, store: Any, settings: Any) -> dict[str, Any]:
    """audit_export.response body."""
    raise NotImplementedError("TODO WS-A")
