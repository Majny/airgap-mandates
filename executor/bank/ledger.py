"""Mock ledger: atomic execution after execution leaf (S1, S6). CONTRACTS.md §3.2.

Owner: WS-A.
"""
from __future__ import annotations

from typing import Any


def execute(proposal: dict[str, Any], authorization: dict[str, Any], *, store: Any, settings: Any) -> dict[str, Any]:
    """Append execution leaf, then TransactWriteItems (ledger + mandate spend + proposal). Returns ledger tx."""
    raise NotImplementedError("TODO WS-A")


def receipt(tx_id: str, *, store: Any, settings: Any) -> dict[str, Any]:
    """Receipt with inclusion proof + STH."""
    raise NotImplementedError("TODO WS-A")
