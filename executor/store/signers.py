"""Enrolled signers: row + `enroll` leaf in one transaction, and the online "enrolled before used" check.

An `enrolled_signers` row is only valid with `enroll_seq` = the audit seq of its own `enroll` leaf, written in the
same TransactWriteItems (§3.2 steps 1-2 + the row Put). POST /signatures accepts a recovered address only if its
row is active for the role AND that leaf exists, is an `enroll` leaf for that address and role (CONTRACTS §4.3
step 6). tools/enroll.py (WS-C) and tools/seed_data.py (WS-D) enrol through enroll(). Owner: WS-A.
"""
from __future__ import annotations

import json
from typing import Any

from executor.store import Put, TxConflict, ensure_head, leaf_ops, next_seq, shims

ENROLL_FIELDS = ("address", "role", "label", "device", "device_model", "firmware_version", "cert_chain_sha256",
                 "fw_hash", "derivation_path", "enroll_sig", "active")


def enroll(store: Any, row: dict[str, Any], *, settings: Any, actor: str = "executor") -> int:
    """Write the enrolled_signers row and its enroll leaf atomically; returns enroll_seq. `row` needs at least
    address, role, device; missing optional ENROLL_FIELDS are logged as null."""
    row = {**row, "address": row["address"].lower(), "active": bool(row.get("active", True))}
    data = {k: row.get(k) for k in ENROLL_FIELDS}
    event = shims.make_event("enroll", data, subject_id=row["address"], actor=actor, settings=settings)
    ensure_head(store)
    for _ in range(20):
        seq = next_seq(store)
        if store.transact(leaf_ops(event, seq) + [Put("enrolled_signers", {**row, "enroll_seq": seq})]):
            from executor import oplog

            oplog.leaf({**event, "seq": seq}, seq)
            shims.after_commit(store=store, settings=settings)
            return seq
    raise TxConflict("audit head contention while enrolling")


def enrolled(store: Any, address: str, role: str) -> dict[str, Any] | None:
    """The active enrolled_signers row for (address, role) whose enroll_seq points at its own enroll leaf, or None."""
    s = store.get("enrolled_signers", {"address": address.lower()})
    if not s or not s.get("active") or s.get("role") != role:
        return None
    seq = s.get("enroll_seq")
    if not isinstance(seq, int) or isinstance(seq, bool):
        return None
    leaf = store.get("audit", {"log_id": "audit", "seq": seq})
    if leaf is None:
        return None
    ev = json.loads(leaf["event"])
    d = ev.get("data") or {}
    if ev.get("type") != "enroll" or d.get("address") != s["address"] or d.get("role") != role \
            or d.get("active") is not True:
        return None
    return s


def deactivate(store: Any, address: str, *, settings: Any, actor: str = "executor") -> int:
    """Revoke a signer: a new enroll leaf with active=false and the row repointed at it (one transaction)."""
    s = store.get("enrolled_signers", {"address": address.lower()})
    if s is None:
        raise KeyError(f"{address} is not enrolled")
    row = {k: v for k, v in s.items() if k != "enroll_seq"}
    return enroll(store, {**row, "active": False}, settings=settings, actor=actor)
