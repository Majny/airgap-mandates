"""Audit leaves v2: seq allocation (head-conditioned Put), canonical JSON, leaf hash. CONTRACTS.md v2 §7.2, §3.2.

Owner: WS-B.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from executor import config
from executor.audit import merkle
from executor.canonical import canonical_json
from executor.models import DECISION_RELEVANT_EVENTS, AuditEventType
from executor import store as storemod
from executor.store import TxConflict

DIGESTS = ("policy_hash", "inputs_digest", "facts_digest", "hints_digest")
_DECISION_RELEVANT = {e.value for e in DECISION_RELEVANT_EVENTS}
_EVENT_TYPES = {e.value for e in AuditEventType}


# Natural store keys (CONTRACTS §3.3: the backend builds physical pk/sk). Kept in one place.
def leaf_key(log_id: str, seq: int) -> dict[str, Any]:
    return {"log_id": log_id, "seq": seq}


head_key = storemod.head_key


def checkpoint_pk(log_id: str) -> tuple[str, str]:
    return ("log_id", log_id)


def checkpoint_key(log_id: str, size: int) -> dict[str, Any]:
    return {"log_id": log_id, "sk": f"{size:012d}"}


def now_iso(settings: Any) -> str:
    """UTC ISO 8601 with milliseconds and 'Z' (honours AIRGAP_FAKE_NOW off AWS)."""
    return config.now(settings).astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def make_event(event_type: str, data: dict[str, Any], *, subject_id: str | None, actor: str, log_id: str = "audit",
               policy_hash: str | None = None, inputs_digest: str | None = None, facts_digest: str | None = None,
               hints_digest: str | None = None, ts: str | None = None) -> dict[str, Any]:
    """Build a v2 event without seq. Digests belong on models.DECISION_RELEVANT_EVENTS and are null elsewhere; a
    missing digest is recorded as null, never refused (the log must not drop events): verify_audit flags it."""
    if event_type not in _EVENT_TYPES:
        raise ValueError(f"unknown event type {event_type!r}")
    digests: dict[str, str | None] = {"policy_hash": policy_hash, "inputs_digest": inputs_digest, "facts_digest": facts_digest,
               "hints_digest": hints_digest}
    if event_type not in _DECISION_RELEVANT:
        digests = dict.fromkeys(DIGESTS)
    return {"v": 2, "log_id": log_id, "ts": ts, "type": event_type, "actor": actor, "subject_id": subject_id,
            "data": data, **digests}


def leaf_hash(event: dict[str, Any]) -> str:
    """sha256(0x00 || canonical_json(event)) hex."""
    return merkle.leaf_hash(canonical_json(event)).hex()


def _next_seq(log_id: str, store: Any) -> int:
    storemod.ensure_head(store, log_id)
    return storemod.next_seq(store, log_id)


def append(event: dict[str, Any], *, store: Any, settings: Any, checkpoint: bool = True) -> int:
    """Append one leaf (sets seq); returns seq. Triggers a checkpoint every N leaves / max seconds."""
    event = dict(event)
    event.pop("seq", None)
    if event.get("ts") is None:
        event["ts"] = now_iso(settings)
    log_id = event["log_id"]
    for _ in range(50):
        seq = _next_seq(log_id, store)
        try:
            if store.transact(storemod.leaf_ops(event, seq)):
                break
        except TxConflict:
            pass
    else:
        raise TxConflict(f"could not append to {log_id} after 50 attempts")
    if checkpoint:
        from executor.audit import checkpoint as cp

        cp.maybe_checkpoint(log_id, store=store, settings=settings)
    return seq


def checkpoint_due(log_id: str, size: int, *, store: Any, settings: Any) -> bool:
    """N leaves since the last checkpoint, or max_seconds elapsed with uncovered leaves (or no checkpoint yet)."""
    from executor.audit import checkpoint as cp

    prev = cp.latest(log_id, store=store)
    covered = int(prev["size"]) if prev else 0
    if size <= covered:
        return False
    if size - covered >= settings.checkpoint_every_n_leaves:
        return True
    if prev is not None:
        since = prev["created_at"]
    else:  # fresh log: age of the oldest uncovered leaf
        first = store.get("audit", leaf_key(log_id, 0))
        if first is None:
            return False
        since = first["ts"]
    age = config.now(settings) - datetime.fromisoformat(since.replace("Z", "+00:00"))
    return age.total_seconds() >= settings.checkpoint_max_seconds


def next_size(log_id: str = "audit", *, store: Any) -> int:
    """Current tree size (= next seq)."""
    return storemod.next_seq(store, log_id)


def tick(log_id: str = "audit", *, store: Any, settings: Any) -> str | None:
    """Scheduler entry: checkpoint if leaves exist that no checkpoint covers. Returns the new note or None."""
    from executor.audit import checkpoint as cp

    size = next_size(log_id, store=store)
    prev = cp.latest(log_id, store=store)
    if size == 0 or (prev is not None and int(prev["size"]) >= size):
        return None
    return cp.make_checkpoint(log_id, store=store, settings=settings)


def anchor(log_id: str = "audit", *, store: Any, settings: Any) -> dict[str, Any] | None:
    """Scheduler entry (every AIRGAP_ANCHOR_INTERVAL_SECONDS): S3 Object Lock copy of the latest checkpoint."""
    from executor.audit import anchor as anchor_mod

    return anchor_mod.anchor(log_id, store=store, settings=settings)


def leaves(log_id: str, from_seq: int = 0, *, store: Any) -> list[dict[str, Any]]:
    """Stored leaf items (sorted by seq), excluding the head item."""
    rows = store.query("audit", ("log_id", log_id))
    return sorted((r for r in rows if int(r["seq"]) >= from_seq), key=lambda r: int(r["seq"]))


def leaf_hashes(log_id: str, *, store: Any) -> list[bytes]:
    """All leaf hashes in seq order; raises if the stored sequence has a gap."""
    rows = leaves(log_id, store=store)
    for i, r in enumerate(rows):
        if int(r["seq"]) != i:
            raise ValueError(f"{log_id}: seq gap at {i}")
    return [bytes.fromhex(r["leaf_hash"]) for r in rows]


def export(log_id: str, from_seq: int = 0, *, redact: bool = False, store: Any, settings: Any) -> dict[str, Any]:
    """audit_export.response body (CONTRACTS §7.4)."""
    from executor.audit import checkpoint as cp
    from executor.policy import rules

    if redact:
        raise NotImplementedError("TODO WS-B: redacted export (IBAN -> salted commitment)")
    out_leaves = [{"seq": int(r["seq"]), "event": json.loads(r["event"]), "leaf_hash": r["leaf_hash"]}
                  for r in leaves(log_id, from_seq, store=store)]
    notes = [r["note"] for r in sorted(store.query("checkpoints", checkpoint_pk(log_id)), key=lambda r: int(r["size"]))]
    vk = cp.vkeys(settings)
    approvers = [{"address": e["data"]["address"], "role": e["data"]["role"], "device": e["data"]["device"],
                  "enroll_seq": le["seq"]} for le in out_leaves if (e := le["event"])["type"] == "enroll"]
    material = rules.policy_material()
    return {"log_id": log_id, "redacted": 0, "leaves": out_leaves, "checkpoints": notes,
            "pubkeys": {"log": vk["log"], "w1": vk["w1"], "w2": getattr(settings, "w2_vkey", None)},
            "approvers": approvers,
            "policies": {rules.policy_hash(): material},  # verbatim: sha256(canonical_json(material)) == key
            "snapshots": {}, "render_profile": settings.render_profile}
