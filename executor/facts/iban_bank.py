"""F-BANK: bank from IBAN (schwifty + data/bank_codes.json). CONTRACTS.md §2.1.

Owner: WS-E.
"""
from __future__ import annotations

from typing import Any


def bank_fact(iban: str, vendor_country: str) -> dict[str, Any]:
    """WARN for foreign/EMI bank for a CZ vendor, e.g. 'banka: EMI Litva (fiktivni)'."""
    raise NotImplementedError("TODO WS-E")
