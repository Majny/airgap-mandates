"""Storage interface. Owner: WS-A. Implements CONTRACTS.md v2 §3.2-§3.3.

Backends: executor.store.memory.MemoryStore (dicts + one lock; dev/CI) and executor.store.dynamo.DynamoStore
(boto3; real DynamoDB in the demo, moto in CI). Table arguments are logical names (executor.config.LOGICAL_TABLES);
the backend maps them to physical tables (airgap-main entities get pk "<entity>#<id>"). Numbers come back as int.

Keys. Callers address items by their natural attributes (KEY_SCHEMA): e.g. get("proposals", {"proposal_id": "prp_1"}),
get("audit", {"log_id": "audit", "seq": 3}). Items keep those attributes. For entities in `main` the backend adds
pk = "<MAIN_PK_PREFIX>#<pk value>" and sk = str(<sk value>) (or "0" when the entity has no sort attribute) and strips
pk/sk again on read. The audit head is the item {"log_id": "head#<log_id>", "seq": 0, "next_seq": N}.

Conditions (UpdateIf.expect / IncrementBounded.expect / update_if expect): {attr: value} means attr == value;
value MISSING means attribute_not_exists(attr); value AnyOf(a, b, ...) means attr equals one of them (AnyOf may contain
MISSING). Every condition on a missing item fails except MISSING. An update whose conditions pass on a missing item
creates it (DynamoDB UpdateItem semantics).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

from executor.canonical import canonical_json, sha256_hex

if TYPE_CHECKING:
    from executor.config import Settings


class _Missing:
    def __repr__(self) -> str:
        return "MISSING"


MISSING: Any = _Missing()


@dataclass(frozen=True)
class AnyOf:
    values: tuple[Any, ...]

    def __init__(self, *values: Any) -> None:
        object.__setattr__(self, "values", tuple(values))


# logical table -> (partition attr, sort attr | None). Sort attr None in `main` => sk "0".
KEY_SCHEMA: dict[str, tuple[str, str | None]] = {
    "ledger": ("tx_id", None),
    "mandates": ("mandate_id", None),
    "audit": ("log_id", "seq"),
    "registry": ("vendor_id", None),
    "witness_state": ("origin", None),
    "proposals": ("proposal_id", None),
    "changes": ("change_id", None),
    "attestations": ("change_id", "sk"),
    "vendor_policies": ("ico", "sk"),
    "nonces": ("nonce", None),
    "counters": ("name", None),
    "enrolled_signers": ("address", None),
    "inbox": ("email_id", None),
    "checkpoints": ("log_id", "sk"),
    "tool_calls": ("session_id", "sk"),
    "portal_notifications": ("ico", "notif_id"),
}

# (logical table, index name) -> (hash attr, range attr). `gsi1` exists on every `main` entity.
INDEXES: dict[tuple[str, str], tuple[str, str]] = {
    ("ledger", "by_vendor"): ("vendor_id", "executed_at"),
    ("mandates", "by_status"): ("status", "mandate_no"),
    **{(t, "gsi1"): ("gsi1pk", "gsi1sk") for t in
       ("proposals", "changes", "attestations", "vendor_policies", "nonces", "counters", "enrolled_signers", "inbox",
        "checkpoints", "tool_calls")},
}


def key_of(table: str, item: dict[str, Any]) -> dict[str, Any]:
    """Natural key dict of an item."""
    pk, sk = KEY_SCHEMA[table]
    return {pk: item[pk]} if sk is None else {pk: item[pk], sk: item[sk]}


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
    expect: dict[str, Any] = field(default_factory=dict)  # see module docstring


@dataclass(frozen=True)
class IncrementBounded:
    """ADD each attr in `by`; condition: value_after <= max_after[attr] for listed attrs, plus expect."""

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

    def transact(self, ops: list[Op], client_request_token: str | None = None) -> bool: ...


class TxConflict(Exception):
    """A TransactWriteItems condition failed; nothing was written."""


class IdempotencyMismatch(TxConflict):
    """The ClientRequestToken was already used (within ~10 min) for a transaction with different parameters."""


def request_token(tx_id: str, leaf_hash: str) -> str:
    """ClientRequestToken for an execution (<= 36 chars): tx_id salted with the execution leaf hash. A retry of the
    identical transaction reuses it (idempotent); after a table reset, where tx_ids repeat (mnd_1|prp_1), the leaf
    (seq, ts) differs and so does the token, so DynamoDB never reports IdempotentParameterMismatch."""
    return f"{tx_id}-{leaf_hash[:16]}"


def head_key(log_id: str = "audit") -> dict[str, Any]:
    return {"log_id": f"head#{log_id}", "seq": 0}


def ensure_head(store: Store, log_id: str = "audit") -> None:
    """Create the audit head item (next_seq 0) if it does not exist yet."""
    store.put_if_absent("audit", {**head_key(log_id), "next_seq": 0}, "log_id")


def next_seq(store: Store, log_id: str = "audit") -> int:
    head = store.get("audit", head_key(log_id))
    return int(head["next_seq"]) if head else 0


def audit_item(event: dict[str, Any]) -> dict[str, Any]:
    """Row of the `audit` table for a complete event (seq set): exact canonical JSON bytes + leaf hash."""
    raw = canonical_json(event)
    return {"log_id": event["log_id"], "seq": event["seq"], "event": raw.decode("utf-8"),
            "leaf_hash": sha256_hex(b"\x00" + raw), "ts": event["ts"]}


def leaf_ops(event: dict[str, Any], expected_seq: int) -> list[Op]:
    """§3.2 steps 1-2 for one event: leaf Put (attribute_not_exists(seq)) + head Update next_seq == expected_seq."""
    ev = {**event, "seq": expected_seq}
    log_id = ev["log_id"]
    return [
        Put("audit", audit_item(ev), if_absent_key="seq"),
        UpdateIf("audit", head_key(log_id), {"next_seq": expected_seq + 1}, {"next_seq": expected_seq}),
    ]


def tx_execute(store: Store, *, leaf_event: dict[str, Any], expected_seq: int, ledger_row: dict[str, Any],
               proposal_id: str, mandate_debit: dict[str, Any] | None,
               proposal_set: dict[str, Any] | None = None) -> int:
    """CONTRACTS §3.2 execution transaction: audit leaf Put (attribute_not_exists(seq)) + audit head Update
    (next_seq = expected_seq) + mandate debit (mandate path; {mandate_id, amount_minor, max_total_minor,
    max_count}) + ledger Put (attribute_not_exists(tx_id)) + proposal Update to EXECUTED, with
    ClientRequestToken = request_token(tx_id, leaf_hash). Returns the leaf seq; raises TxConflict.

    proposal_set (WS-A addition, optional): extra proposal attributes written in the same Update (the allow path
    creates the proposal row inside the transaction; condition status = PENDING_SIG or item new)."""
    tx_id = ledger_row["tx_id"]
    if leaf_event.get("data", {}).get("tx_id") != tx_id:
        raise ValueError("execution leaf data.tx_id must equal ledger_row tx_id")
    ops: list[Op] = leaf_ops(leaf_event, expected_seq)
    if mandate_debit is not None:
        d = mandate_debit
        ops.append(IncrementBounded("mandates", {"mandate_id": d["mandate_id"]},
                                    by={"spent_minor": int(d["amount_minor"]), "count": 1},
                                    max_after={"spent_minor": int(d["max_total_minor"]), "count": int(d["max_count"])},
                                    expect={"status": "ACTIVE"}))
    ops.append(Put("ledger", {**ledger_row, "seq": expected_seq}, if_absent_key="tx_id"))
    ops.append(UpdateIf("proposals", {"proposal_id": proposal_id},
                        {**(proposal_set or {}), "status": "EXECUTED", "tx_id": tx_id},
                        {"status": AnyOf(MISSING, "PENDING_SIG")}))
    token = request_token(tx_id, ops[0].item["leaf_hash"])  # ops[0] is the audit leaf Put
    if not store.transact(ops, client_request_token=token):
        raise TxConflict(f"execution transaction for {tx_id} cancelled")
    from executor import oplog

    oplog.leaf({**leaf_event, "seq": expected_seq}, expected_seq)  # after commit only (never logs a cancelled one)
    return expected_seq


def get_store(settings: "Settings") -> Store:
    """Factory: memory -> MemoryStore, moto/aws -> DynamoStore."""
    if settings.backend == "memory":
        from executor.store.memory import MemoryStore

        return MemoryStore(settings)
    if settings.backend in ("moto", "aws"):
        from executor.store.dynamo import DynamoStore

        return DynamoStore(settings)
    raise ValueError(f"unknown backend {settings.backend!r}")
