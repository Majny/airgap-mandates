"""In-memory Store backend (dicts + one threading.Lock). Implements CONTRACTS.md §3.3.

Owner: WS-A.
"""
from __future__ import annotations

from typing import Any


class MemoryStore:
    """Implements executor.store.Store."""

    def __init__(self, settings: Any) -> None:
        raise NotImplementedError("TODO WS-A")

    def get(self, table: str, key: dict[str, Any]) -> dict[str, Any] | None:
        raise NotImplementedError("TODO WS-A")

    def put(self, table: str, item: dict[str, Any]) -> None:
        raise NotImplementedError("TODO WS-A")

    def put_if_absent(self, table: str, item: dict[str, Any], key_attr: str) -> bool:
        raise NotImplementedError("TODO WS-A")

    def update_if(self, table: str, key: dict[str, Any], set_: dict[str, Any], expect: dict[str, Any]) -> bool:
        raise NotImplementedError("TODO WS-A")

    def increment(self, table: str, key: dict[str, Any], attr: str, by: int = 1) -> int:
        raise NotImplementedError("TODO WS-A")

    def query(self, table: str, pk: tuple[str, Any], index: str | None = None, sk_range: tuple[Any, Any] | None = None,
              limit: int | None = None, reverse: bool = False) -> list[dict[str, Any]]:
        raise NotImplementedError("TODO WS-A")

    def scan(self, table: str) -> list[dict[str, Any]]:
        raise NotImplementedError("TODO WS-A")

    def transact(self, ops: list[Any]) -> bool:
        raise NotImplementedError("TODO WS-A")
