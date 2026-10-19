"""F-BANK: bank from IBAN (data/bank_codes.json). CONTRACTS.md v2 §2.1.

Domestic -> INFO 'BANK DOMESTIC'; foreign or EMI for a CZ vendor -> WARN 'BANK FOREIGN EMI'. Owner: WS-D.
"""
from __future__ import annotations

from typing import Any

from executor.models import Fact


def bank_fact(iban: str, vendor_country: str, *, snapshot: Any) -> Fact:
    """Bank code from the IBAN; never a bank brand in display_line."""
    raise NotImplementedError("TODO WS-D")
