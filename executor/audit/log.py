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
from executor.store import Put, TxConflict, UpdateIf

DIGESTS = ("policy_hash", "inputs_digest", "facts_digest", "hints_digest")
_DECISION_RELEVANT = {e.value for e in DECISION_RELEVANT_EVENTS}
_EVENT_TYPES = {e.value for e in AuditEventType}


# Store keys (CONTRACTS §3.1). Kept in one place so a backend key-shape change touches only these helpers.
def leaf_key(log_id: str, seq: int) -> dict[str, Any]:
    return {"log_id": log_id, "seq": seq}


def head_key(log_id: str) -> dict[str, Any]:
    return {"log_id": f"head#{log_id}", "seq": 0}


def checkpoint_pk(log_id: str) -> tuple[str, str]:
    return ("pk", f"checkpoint#{log_id}")


def checkpoint_key(log_id: str, size: int) -> dict[str, Any]:
    return {"pk": f"checkpoint#{log_id}", "sk": f"{size:012d}"}


def now_iso(settings: Any) -> str:
    """UTC ISO 8601 with milliseconds and 'Z' (honours AIRGAP_FAKE_NOW off AWS)."""
    return config.now(settings).astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def make_event(event_type: str, data: dict[str, Any], *, subject_id: str | None, actor: str, log_id: str = "audit",
               policy_hash: str | None = None, inputs_digest: str | None = None, facts_digest: str | None = None,
               hints_digest: str | None = None, ts: str | None = None) -> dict[str, Any]:
    """Build a v2 event without seq (digests required for models.DECISION_RELEVANT_EVENTS)."""
    if event_type not in _EVENT_TYPES:
        raise ValueError(f"unknown event type {event_type!r}")
    digests: dict[str, str | None] = {"policy_hash": policy_hash, "inputs_digest": inputs_digest, "facts_digest": facts_digest,
               "hints_digest": hints_digest}
    if event_type in _DECISION_RELEVANT:
        missing = [k for k, v in digests.items() if not v]
        if missing:
            raise ValueError(f"{event_type} event requires {', '.join(missing)}")
    else:
        digests = dict.fromkeys(DIGESTS)
    return {"v": 2, "log_id": log_id, "ts": ts, "type": event_type, "actor": actor, "subject_id": subject_id,
            "data": data, **digests}


def leaf_hash(event: dict[str, Any]) -> str:
    """sha256(0x00 || canonical_json(event)) hex."""
    return merkle.leaf_hash(canonical_json(event)).hex()


def _next_seq(log_id: str, store: Any) -> int:
    head = store.get("audit", head_key(log_id))
    if head is None:
        store.put_if_absent("audit", {**head_key(log_id), "next_seq": 0}, "log_id")
        head = store.get("audit", head_key(log_id))
    return int(head["next_seq"])


def leaf_ops(event: dict[str, Any], expected_seq: int) -> tuple[dict[str, Any], list[Any]]:
    """(stored item, [leaf Put, head UpdateIf]) for one leaf at expected_seq (CONTRACTS §3.2 steps 1-2)."""
    log_id = event["log_id"]
    ev = {**event, "seq": expected_seq}
    item = {**leaf_key(log_id, expected_seq), "event": canonical_json(ev).decode("utf-8"), "leaf_hash": leaf_hash(ev),
            "ts": ev["ts"]}
    return item, [Put("audit", item, if_absent_key="seq"),
                  UpdateIf("audit", head_key(log_id), {"next_seq": expected_seq + 1}, {"next_seq": expected_seq})]


def append(event: dict[str, Any], *, store: Any, settings: Any, checkpoint: bool = True) -> int:
    """Append one leaf (sets seq); returns seq. Triggers a checkpoint every N leaves / max seconds."""
    event = dict(event)
    event.pop("seq", None)
    if event.get("ts") is None:
        event["ts"] = now_iso(settings)
    log_id = event["log_id"]
    for _ in range(50):
        seq = _next_seq(log_id, store)
        _, ops = leaf_ops(event, seq)
        try:
            if store.transact(ops):
                break
        except TxConflict:
            pass
    else:
        raise TxConflict(f"could not append to {log_id} after 50 attempts")
    if checkpoint and _checkpoint_due(log_id, seq + 1, store=store, settings=settings):
        from executor.audit import checkpoint as cp

        cp.make_checkpoint(log_id, store=store, settings=settings)
    return seq


def _checkpoint_due(log_id: str, size: int, *, store: Any, settings: Any) -> bool:
    from executor.audit import checkpoint as cp

    prev = cp.latest(log_id, store=store)
    if prev is None:
        return True
    if size - int(prev["size"]) >= settings.checkpoint_every_n_leaves:
        return True
    age = config.now(settings) - datetime.fromisoformat(prev["created_at"].replace("Z", "+00:00"))
    return age.total_seconds() >= settings.checkpoint_max_seconds


def tick(log_id: str = "audit", *, store: Any, settings: Any) -> str | None:
    """Scheduler entry: checkpoint if leaves exist that no checkpoint covers. Returns the new note or None."""
    from executor.audit import checkpoint as cp

    size = _next_seq(log_id, store)
    prev = cp.latest(log_id, store=store)
    if size == 0 or (prev is not None and int(prev["size"]) >= size):
        return None
    return cp.make_checkpoint(log_id, store=store, settings=settings)


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
    notes = [r["note"] for r in sorted(store.query("checkpoints", checkpoint_pk(log_id)), key=lambda r: r["sk"])]
    vk = cp.vkeys(settings)
    approvers = [{"address": e["data"]["address"], "role": e["data"]["role"], "device": e["data"]["device"],
                  "enroll_seq": le["seq"]} for le in out_leaves if (e := le["event"])["type"] == "enroll"]
    material = rules.policy_material()
    return {"log_id": log_id, "redacted": 0, "leaves": out_leaves, "checkpoints": notes,
            "pubkeys": {"log": vk["log"], "w1": vk["w1"], "w2": getattr(settings, "w2_vkey", None)},
            "approvers": approvers,
            "policies": {rules.policy_hash(): {
                "cedar_policies_text": material.get("cedar_policies_text", ""),
                "cedar_schema": material.get("cedar_schema", ""),
                "translit_table": material.get("translit_table"),
                "fact_severity_table": material.get("fact_severity_table"),
                "policy_v": material.get("policy_v")}},
            "snapshots": {}, "render_profile": settings.render_profile}
