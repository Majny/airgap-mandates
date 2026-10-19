"""F-VAT: ADIS published accounts / unreliable payer + ARES (cache in data/adis_cache/, AIRGAP_ADIS_MODE). CONTRACTS.md §2.1.

Owner: WS-D.
"""
from __future__ import annotations

from typing import Any


def vat_fact(ico: str, iban: str, *, settings: Any) -> dict[str, Any]:
    """WARN if account not published, BLOCK if unreliable payer; 'VAT acct: YES|NE'."""
    raise NotImplementedError("TODO WS-D")
