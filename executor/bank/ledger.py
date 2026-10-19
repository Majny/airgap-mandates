"""Mock ledger: execution via one TransactWriteItems (S1, S6). CONTRACTS.md v2 §3.2. Owner: WS-A.

The execution leaf, audit head, mandate debit, ledger row and proposal EXECUTED land in a single transaction
(executor.store.tx_execute); a crash before it leaves nothing, a crash after it leaves everything.
"""
from __future__ import annotations

import hashlib
from typing import Any

from executor import config
from executor.store import TxConflict, ensure_head, next_seq, shims, tx_execute

MAX_ATTEMPTS = 10


def tx_id_for(auth_ref: str, proposal_id: str) -> str:
    """'tx_' + sha256(f'{auth_ref}|{proposal_id}')[:16]; auth_ref = mandate_id (mandate path) or nonce (step-up)."""
    return "tx_" + hashlib.sha256(f"{auth_ref}|{proposal_id}".encode()).hexdigest()[:16]


def execute(proposal: dict[str, Any], authorization: dict[str, Any], *, store: Any, settings: Any,
            mandate: dict[str, Any] | None = None, leaf_extra: dict[str, Any] | None = None,
            proposal_set: dict[str, Any] | None = None) -> dict[str, Any]:
    """store.tx_execute(): execution leaf + head seq + mandate debit + ledger row + proposal EXECUTED. Returns ledger tx.

    proposal: {proposal_id, vendor_id, invoice, iban (from the registry, resolved by the caller)}.
    authorization: {kind: mandate|stepup, mandate_id?, nonce?, signer_address?}; mandate: the mandate row (mandate
    path). leaf_extra: {policy_hash, inputs_digest, facts_digest, hints_digest} for the execution leaf.
    proposal_set: extra proposal attributes written in the same transaction (allow path creates the proposal).
    Idempotent: re-executing the same (auth_ref, proposal_id) returns the existing ledger row.
    """
    invoice = proposal["invoice"]
    proposal_id = proposal["proposal_id"]
    kind = authorization["kind"]
    auth_ref = authorization["mandate_id"] if kind == "mandate" else authorization["nonce"]
    tx_id = tx_id_for(auth_ref, proposal_id)
    ledger_row: dict[str, Any] = {
        "tx_id": tx_id,
        "proposal_id": proposal_id,
        "vendor_id": proposal["vendor_id"],
        "iban": proposal["iban"],
        "amount_minor": int(invoice["amount_minor"]),
        "currency": invoice["currency"],
        "authorization": dict(authorization),
        "executed_at": config.iso(config.now(settings)),
        "rail": {"status": "PENDING", "xml_c14n_sha256": None},
    }
    if invoice.get("vs"):
        ledger_row["vs"] = invoice["vs"]
    extra = leaf_extra or {}
    event = shims.make_event(
        "execution",
        {k: ledger_row[k] for k in ("tx_id", "proposal_id", "vendor_id", "iban", "amount_minor", "currency",
                                    "authorization")},
        subject_id=proposal_id, actor="executor", settings=settings,
        policy_hash=extra.get("policy_hash"), inputs_digest=extra.get("inputs_digest"),
        facts_digest=extra.get("facts_digest"), hints_digest=extra.get("hints_digest"))
    mandate_debit = None
    if kind == "mandate":
        if mandate is None:
            raise ValueError("mandate path requires the mandate row")
        mandate_debit = {"mandate_id": mandate["mandate_id"], "amount_minor": ledger_row["amount_minor"],
                         "max_total_minor": int(mandate["max_total_minor"]), "max_count": int(mandate["max_count"])}

    log_id = event.get("log_id", "audit")
    ensure_head(store, log_id)
    for _ in range(MAX_ATTEMPTS):
        expected = next_seq(store, log_id)
        try:
            seq = tx_execute(store, leaf_event=event, expected_seq=expected, ledger_row=ledger_row,
                             proposal_id=proposal_id, mandate_debit=mandate_debit, proposal_set=proposal_set)
        except TxConflict:
            existing = store.get("ledger", {"tx_id": tx_id})
            if existing is not None:
                return existing
            if next_seq(store, log_id) != expected:
                continue
            raise
        shims.after_commit(store=store, settings=settings)
        return {**ledger_row, "seq": seq}
    raise TxConflict(f"audit head contention executing {tx_id}")
