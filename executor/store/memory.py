"""In-memory Store backend (dicts + one threading.Lock). Implements CONTRACTS.md v2 §3.3 (dev/CI only).

Semantics mirror the DynamoDB backend (see executor.store docstring): natural keys via KEY_SCHEMA, conditions with
MISSING / AnyOf, updates create missing items, transact is all-or-nothing with a ~10 min ClientRequestToken window.

Owner: WS-A.
"""
from __future__ import annotations

import copy
import threading
import time
from typing import Any

from executor.store import INDEXES, KEY_SCHEMA, MISSING, AnyOf, IncrementBounded, Put, UpdateIf

TOKEN_TTL_SECONDS = 600.0


def check_expect(item: dict[str, Any] | None, expect: dict[str, Any]) -> bool:
    """Evaluate {attr: value | MISSING | AnyOf(...)} against an item (None = item does not exist)."""
    for attr, want in expect.items():
        cur = MISSING if item is None or attr not in item else item[attr]
        allowed = want.values if isinstance(want, AnyOf) else (want,)
        if not any((a is MISSING and cur is MISSING) or (a is not MISSING and cur is not MISSING and cur == a)
                   for a in allowed):
            return False
    return True


class MemoryStore:
    """Implements executor.store.Store."""

    def __init__(self, settings: Any) -> None:
        self.settings = settings
        self._lock = threading.Lock()
        self._tables: dict[str, dict[tuple[Any, ...], dict[str, Any]]] = {t: {} for t in KEY_SCHEMA}
        self._tokens: dict[str, tuple[float, str]] = {}

    # ------------------------------------------------------------ helpers (call with the lock held)

    @staticmethod
    def _k(table: str, key: dict[str, Any]) -> tuple[Any, ...]:
        pk, sk = KEY_SCHEMA[table]
        return (key[pk],) if sk is None else (key[pk], key[sk])

    def _key_attrs(self, table: str, key: dict[str, Any]) -> dict[str, Any]:
        pk, sk = KEY_SCHEMA[table]
        return {pk: key[pk]} if sk is None else {pk: key[pk], sk: key[sk]}

    def _raw(self, table: str, key: dict[str, Any]) -> dict[str, Any] | None:
        return self._tables[table].get(self._k(table, key))

    def _check_op(self, op: Any) -> bool:
        if isinstance(op, Put):
            return op.if_absent_key is None or self._raw(op.table, op.item) is None
        item = self._raw(op.table, op.key)
        if not check_expect(item, op.expect):
            return False
        if isinstance(op, IncrementBounded):
            for attr, limit in op.max_after.items():
                if int((item or {}).get(attr, 0)) + int(op.by.get(attr, 0)) > limit:
                    return False
        return True

    def _apply(self, op: Any) -> dict[str, Any]:
        tbl = self._tables[op.table]
        if isinstance(op, Put):
            item = copy.deepcopy(op.item)
            tbl[self._k(op.table, item)] = item
            return item
        k = self._k(op.table, op.key)
        item = tbl.setdefault(k, copy.deepcopy(self._key_attrs(op.table, op.key)))
        if isinstance(op, UpdateIf):
            item.update(copy.deepcopy(op.set_))
        else:
            for attr, by in op.by.items():
                item[attr] = int(item.get(attr, 0)) + int(by)
        return item

    # ------------------------------------------------------------ Store API

    def get(self, table: str, key: dict[str, Any]) -> dict[str, Any] | None:
        with self._lock:
            return copy.deepcopy(self._raw(table, key))

    def put(self, table: str, item: dict[str, Any]) -> None:
        with self._lock:
            self._apply(Put(table, item))

    def put_if_absent(self, table: str, item: dict[str, Any], key_attr: str) -> bool:
        op = Put(table, item, if_absent_key=key_attr)
        with self._lock:
            if not self._check_op(op):
                return False
            self._apply(op)
            return True

    def update_if(self, table: str, key: dict[str, Any], set_: dict[str, Any], expect: dict[str, Any]) -> bool:
        op = UpdateIf(table, key, set_, expect)
        with self._lock:
            if not self._check_op(op):
                return False
            self._apply(op)
            return True

    def increment(self, table: str, key: dict[str, Any], attr: str, by: int = 1) -> int:
        with self._lock:
            return int(self._apply(IncrementBounded(table, key, {attr: by}))[attr])

    def query(self, table: str, pk: tuple[str, Any], index: str | None = None, sk_range: tuple[Any, Any] | None = None,
              limit: int | None = None, reverse: bool = False) -> list[dict[str, Any]]:
        attr, value = pk
        if index is None:
            hash_attr, range_attr = KEY_SCHEMA[table]
        else:
            hash_attr, range_attr = INDEXES[(table, index)]
        if attr != hash_attr:
            raise ValueError(f"query on {table}/{index}: partition attr is {hash_attr!r}, not {attr!r}")
        with self._lock:
            rows = [it for it in self._tables[table].values()
                    if it.get(hash_attr, MISSING) == value and (range_attr is None or range_attr in it)]
            rows = copy.deepcopy(rows)
        if range_attr is not None:
            if sk_range is not None:
                lo, hi = sk_range
                rows = [r for r in rows if lo <= r[range_attr] <= hi]
            rows.sort(key=lambda r: r[range_attr], reverse=reverse)
        return rows if limit is None else rows[:limit]

    def scan(self, table: str) -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(list(self._tables[table].values()))

    def transact(self, ops: list[Any], client_request_token: str | None = None) -> bool:
        with self._lock:
            fingerprint = repr(ops)
            if client_request_token is not None:
                now = time.monotonic()
                self._tokens = {t: v for t, v in self._tokens.items() if now - v[0] < TOKEN_TTL_SECONDS}
                seen = self._tokens.get(client_request_token)
                if seen is not None:
                    if seen[1] != fingerprint:
                        from executor.store import IdempotencyMismatch

                        raise IdempotencyMismatch(f"ClientRequestToken {client_request_token} reused with other ops")
                    return True
            if not all(self._check_op(op) for op in ops):
                return False
            for op in ops:
                self._apply(op)
            if client_request_token is not None:
                self._tokens[client_request_token] = (time.monotonic(), fingerprint)
            return True
