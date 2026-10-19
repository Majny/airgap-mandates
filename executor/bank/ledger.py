"""Mock ledger: execution via one TransactWriteItems (S1, S6). CONTRACTS.md v2 §3.2. Owner: WS-A."""
from __future__ import annotations

from typing import Any


def tx_id_for(auth_ref: str, proposal_id: str) -> str:
    """'tx_' + sha256(f'{auth_ref}|{proposal_id}')[:16]; auth_ref = mandate_id (mandate path) or nonce (step-up)."""
    raise NotImplementedError("TODO WS-A")


def execute(proposal: dict[str, Any], authorization: dict[str, Any], *, store: Any, settings: Any) -> dict[str, Any]:
    """store.tx_execute(): execution leaf + head seq + mandate debit + ledger row + proposal EXECUTED. Returns ledger tx."""
    raise NotImplementedError("TODO WS-A")
