"""In-memory fakes for WS-D tests: FakeStore (executor.store.Store protocol) and FakeAudit. CONTRACTS.md v2 §3.3, §7.2.

Owner: WS-D.

Test doubles only: the real backends are executor.store.memory / executor.store.dynamo (WS-A) and executor.audit (WS-B).
"""
from __future__ import annotations

import copy
import threading
from typing import Any

from executor.store import IncrementBounded, Op, Put, UpdateIf

# Logical table -> key attributes (CONTRACTS §3.1). The last attribute is the sort key when there are two.
KEY_ATTRS: dict[str, tuple[str, ...]] = {
    "registry": ("vendor_id",),
    "changes": ("change_id",),
    "nonces": ("nonce",),
    "counters": ("name",),
    "attestations": ("change_id", "n"),
    "portal_notifications": ("ico", "notif_id"),
    "enrolled_signers": ("address",),
    "inbox": ("email_id",),
    "proposals": ("proposal_id",),
    "mandates": ("mandate_id",),
    "ledger": ("tx_id",),
    "audit": ("log_id", "seq"),
    "vendor_policies": ("ico", "policy_v"),
    "checkpoints": ("log_id", "size"),
    "tool_calls": ("session_id", "step"),
    "witness_state": ("origin",),
}


class FakeStore:
    """Dict-backed Store with one lock; `transact` checks every condition before writing anything."""

    def __init__(self) -> None:
        self.tables: dict[str, dict[tuple[Any, ...], dict[str, Any]]] = {}
        self._lock = threading.RLock()
        self.transactions: list[list[Op]] = []

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _attrs(table: str) -> tuple[str, ...]:
        if table not in KEY_ATTRS:
            raise KeyError(f"unknown logical table {table!r}")
        return KEY_ATTRS[table]

    def _key(self, table: str, obj: dict[str, Any]) -> tuple[Any, ...]:
        try:
            return tuple(obj[a] for a in self._attrs(table))
        except KeyError as e:
            raise KeyError(f"{table}: missing key attribute {e}") from None

    def _t(self, table: str) -> dict[tuple[Any, ...], dict[str, Any]]:
        self._attrs(table)
        return self.tables.setdefault(table, {})

    @staticmethod
    def _matches(item: dict[str, Any] | None, expect: dict[str, Any]) -> bool:
        if not expect:
            return True
        if item is None:
            return False
        return all(item.get(k) == v for k, v in expect.items())

    # ------------------------------------------------------------------ Store protocol
    def get(self, table: str, key: dict[str, Any]) -> dict[str, Any] | None:
        with self._lock:
            item = self._t(table).get(self._key(table, key))
            return copy.deepcopy(item)

    def put(self, table: str, item: dict[str, Any]) -> None:
        with self._lock:
            self._t(table)[self._key(table, item)] = copy.deepcopy(item)

    def put_if_absent(self, table: str, item: dict[str, Any], key_attr: str) -> bool:
        with self._lock:
            k = self._key(table, item)
            if k in self._t(table):
                return False
            self._t(table)[k] = copy.deepcopy(item)
            return True

    def update_if(self, table: str, key: dict[str, Any], set_: dict[str, Any], expect: dict[str, Any]) -> bool:
        with self._lock:
            return self._apply_update(table, key, set_, expect, dry=False)

    def increment(self, table: str, key: dict[str, Any], attr: str, by: int = 1) -> int:
        with self._lock:
            k = self._key(table, key)
            item = self._t(table).setdefault(k, dict(key))
            item[attr] = int(item.get(attr, 0)) + by
            return item[attr]

    def query(self, table: str, pk: tuple[str, Any], index: str | None = None,
              sk_range: tuple[Any, Any] | None = None, limit: int | None = None,
              reverse: bool = False) -> list[dict[str, Any]]:
        attr, value = pk
        attrs = self._attrs(table)
        sk = attrs[-1] if len(attrs) > 1 else None
        with self._lock:
            rows = [copy.deepcopy(r) for r in self._t(table).values() if r.get(attr) == value]
        if sk is not None:
            rows.sort(key=lambda r: r.get(sk))
            if sk_range is not None:
                lo, hi = sk_range
                rows = [r for r in rows if lo <= r.get(sk) <= hi]
        if reverse:
            rows.reverse()
        return rows[:limit] if limit is not None else rows

    def scan(self, table: str) -> list[dict[str, Any]]:
        with self._lock:
            return [copy.deepcopy(r) for r in self._t(table).values()]

    def transact(self, ops: list[Op], client_request_token: str | None = None) -> bool:
        with self._lock:
            for op in ops:
                if not self._check(op):
                    return False
            for op in ops:
                self._apply(op)
            self.transactions.append(list(ops))
            return True

    # ------------------------------------------------------------------ transact internals
    def _check(self, op: Op) -> bool:
        if isinstance(op, Put):
            return op.if_absent_key is None or self._key(op.table, op.item) not in self._t(op.table)
        if isinstance(op, UpdateIf):
            return self._apply_update(op.table, op.key, op.set_, op.expect, dry=True)
        if isinstance(op, IncrementBounded):
            item = self._t(op.table).get(self._key(op.table, op.key))
            if not self._matches(item, op.expect):
                return False
            for a, cap in op.max_after.items():
                if int((item or {}).get(a, 0)) + op.by.get(a, 0) > cap:
                    return False
            return True
        raise TypeError(f"unknown op {op!r}")

    def _apply(self, op: Op) -> None:
        if isinstance(op, Put):
            self._t(op.table)[self._key(op.table, op.item)] = copy.deepcopy(op.item)
        elif isinstance(op, UpdateIf):
            self._apply_update(op.table, op.key, op.set_, op.expect, dry=False)
        elif isinstance(op, IncrementBounded):
            item = self._t(op.table).setdefault(self._key(op.table, op.key), dict(op.key))
            for a, by in op.by.items():
                item[a] = int(item.get(a, 0)) + by

    def _apply_update(self, table: str, key: dict[str, Any], set_: dict[str, Any], expect: dict[str, Any],
                      *, dry: bool) -> bool:
        k = self._key(table, key)
        item = self._t(table).get(k)
        if not self._matches(item, expect):
            return False
        if not dry:
            new = dict(item) if item is not None else dict(key)
            new.update(copy.deepcopy(set_))
            self._t(table)[k] = new
        return True

    def all_rows(self) -> list[tuple[str, dict[str, Any]]]:
        """Every (table, row) pair; used by the 'no plaintext callback code' scan."""
        with self._lock:
            return [(t, copy.deepcopy(r)) for t, rows in self.tables.items() for r in rows.values()]


class FakeAudit:
    """Captures leaves instead of executor.audit.log (monkeypatch executor.change.ports.emit with .emit)."""

    def __init__(self) -> None:
        self.leaves: list[dict[str, Any]] = []

    def emit(self, store: Any, settings: Any, type: str, data: dict[str, Any], *, subject_id: str | None,
             actor: str, facts_digest: str | None = None, hints_digest: str | None = None,
             log_id: str = "audit") -> int:
        self.leaves.append({"seq": len(self.leaves), "type": type, "data": copy.deepcopy(data),
                            "subject_id": subject_id, "actor": actor, "facts_digest": facts_digest,
                            "hints_digest": hints_digest, "log_id": log_id})
        return len(self.leaves) - 1

    def of_type(self, type: str, subject_id: str | None = None) -> list[dict[str, Any]]:
        return [x for x in self.leaves if x["type"] == type and (subject_id is None or x["subject_id"] == subject_id)]

    def events(self, subject_id: str | None = None) -> list[str]:
        """change_event kinds in order."""
        return [x["data"]["event"] for x in self.of_type("change_event", subject_id)]

    def transitions(self, subject_id: str | None = None) -> list[tuple[str | None, str, str]]:
        return [(x["data"]["from"], x["data"]["to"], x["data"]["event"])
                for x in self.of_type("state_transition", subject_id)]
