"""Minimal Store stand-in for WS-B tests until WS-A's MemoryStore lands (CONTRACTS.md v2 §3.3 semantics, only the
tables the audit log and witness touch). Not a backend: tests only."""
from __future__ import annotations

import copy
import threading
from dataclasses import replace
from typing import Any

from executor.config import Settings
from executor.store import IncrementBounded, Put, TxConflict, UpdateIf

KEYS = {"audit": ("log_id", "seq"), "checkpoints": ("pk", "sk"), "witness_state": ("origin",),
        "enrolled_signers": ("pk", "sk")}


class FakeStore:
    def __init__(self) -> None:
        self.tables: dict[str, dict[tuple, dict[str, Any]]] = {t: {} for t in KEYS}
        self.lock = threading.RLock()

    def _k(self, table: str, d: dict[str, Any]) -> tuple:
        return tuple(d[a] for a in KEYS[table])

    def get(self, table, key):
        with self.lock:
            item = self.tables[table].get(self._k(table, key))
            return copy.deepcopy(item)

    def put(self, table, item):
        with self.lock:
            self.tables[table][self._k(table, item)] = copy.deepcopy(item)

    def put_if_absent(self, table, item, key_attr):
        with self.lock:
            if self._k(table, item) in self.tables[table]:
                return False
            self.put(table, item)
            return True

    def update_if(self, table, key, set_, expect):
        with self.lock:
            item = self.tables[table].get(self._k(table, key))
            if item is None or any(item.get(k) != v for k, v in expect.items()):
                return False
            item.update(copy.deepcopy(set_))
            return True

    def increment(self, table, key, attr, by=1):
        raise NotImplementedError

    def query(self, table, pk, index=None, sk_range=None, limit=None, reverse=False):
        attr, value = pk
        with self.lock:
            sk = KEYS[table][-1]
            rows = sorted((copy.deepcopy(i) for i in self.tables[table].values() if i.get(attr) == value),
                          key=lambda i: i[sk], reverse=reverse)
        return rows[:limit] if limit else rows

    def scan(self, table):
        with self.lock:
            return copy.deepcopy(list(self.tables[table].values()))

    def transact(self, ops, client_request_token=None):
        with self.lock:
            snapshot = copy.deepcopy(self.tables)
            for op in ops:
                if isinstance(op, Put):
                    ok = (self.put_if_absent(op.table, op.item, op.if_absent_key) if op.if_absent_key
                          else (self.put(op.table, op.item) or True))
                elif isinstance(op, UpdateIf):
                    ok = self.update_if(op.table, op.key, op.set_, op.expect)
                elif isinstance(op, IncrementBounded):
                    raise NotImplementedError
                if not ok:
                    self.tables = snapshot
                    raise TxConflict(repr(op))
            return True


def make_settings(tmp_path, **kw) -> Settings:
    return replace(Settings(), local_key_dir=str(tmp_path / "keys"), **kw)
