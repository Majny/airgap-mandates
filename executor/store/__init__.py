"""Storage interface. Owner: WS-A. Implements CONTRACTS.md §3.3.

Backends: executor.store.memory.MemoryStore (dicts + one lock) and executor.store.dynamo.DynamoStore
(boto3; also used against moto). Logical table names are the TABLES in executor.config; the backend
maps them to physical names. Numbers come back as int (never Decimal).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from executor.config import Settings


@dataclass(frozen=True)
class Put:
    table: str
    item: dict[str, Any]
    if_absent_key: str | None = None  # condition attribute_not_exists(<key attr>)


@dataclass(frozen=True)
class UpdateIf:
    table: str
    key: dict[str, Any]
    set_: dict[str, Any]
    expect: dict[str, Any] = field(default_factory=dict)  # attribute equality conditions


@dataclass(frozen=True)
class IncrementBounded:
    """ADD each attr in `by`; condition: value_after <= max_after[attr] for listed attrs, plus expect equality."""

    table: str
    key: dict[str, Any]
    by: dict[str, int]
    max_after: dict[str, int] = field(default_factory=dict)
    expect: dict[str, Any] = field(default_factory=dict)


Op = Put | UpdateIf | IncrementBounded


class Store(Protocol):
    def get(self, table: str, key: dict[str, Any]) -> dict[str, Any] | None: ...

    def put(self, table: str, item: dict[str, Any]) -> None: ...

    def put_if_absent(self, table: str, item: dict[str, Any], key_attr: str) -> bool: ...

    def update_if(self, table: str, key: dict[str, Any], set_: dict[str, Any], expect: dict[str, Any]) -> bool: ...

    def increment(self, table: str, key: dict[str, Any], attr: str, by: int = 1) -> int: ...

    def query(
        self,
        table: str,
        pk: tuple[str, Any],
        index: str | None = None,
        sk_range: tuple[Any, Any] | None = None,
        limit: int | None = None,
        reverse: bool = False,
    ) -> list[dict[str, Any]]: ...

    def scan(self, table: str) -> list[dict[str, Any]]: ...

    def transact(self, ops: list[Op]) -> bool: ...


def get_store(settings: "Settings") -> Store:
    """Factory: memory -> MemoryStore, moto/aws -> DynamoStore."""
    raise NotImplementedError("TODO WS-A")
