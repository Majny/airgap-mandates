"""Audit leaves v2: seq allocation (head-conditioned Put), canonical JSON, leaf hash. CONTRACTS.md v2 §7.2, §3.2.

Owner: WS-B.
"""
from __future__ import annotations

from typing import Any


def make_event(event_type: str, data: dict[str, Any], *, subject_id: str | None, actor: str, log_id: str = "audit",
               policy_hash: str | None = None, inputs_digest: str | None = None, facts_digest: str | None = None,
               hints_digest: str | None = None, ts: str | None = None) -> dict[str, Any]:
    """Build a v2 event without seq (digests required for models.DECISION_RELEVANT_EVENTS)."""
    raise NotImplementedError("TODO WS-B")


def append(event: dict[str, Any], *, store: Any, settings: Any) -> int:
    """Append one leaf (sets seq); returns seq. Triggers a checkpoint every N leaves / max seconds."""
    raise NotImplementedError("TODO WS-B")


def leaf_hash(event: dict[str, Any]) -> str:
    """sha256(0x00 || canonical_json(event)) hex."""
    raise NotImplementedError("TODO WS-B")


def export(log_id: str, from_seq: int = 0, *, redact: bool = False, store: Any, settings: Any) -> dict[str, Any]:
    """audit_export.response body (CONTRACTS §7.4)."""
    raise NotImplementedError("TODO WS-B")
