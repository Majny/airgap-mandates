"""F-ATTEST: vendor attestation k/n for the IBAN, from executor.attest (WS-B). CONTRACTS.md §2.1.

Owner: WS-E.
"""
from __future__ import annotations

from typing import Any


def attest_fact(vendor: dict[str, Any], iban: str, *, store: Any) -> dict[str, Any]:
    """BLOCK if in-network and no valid quorum for iban, e.g. 'dodavatel 0/3'."""
    raise NotImplementedError("TODO WS-E")
