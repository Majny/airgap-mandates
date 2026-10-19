"""F-DPH: ADIS published accounts / unreliable payer + ARES (cache in data/adis_cache/, AIRGAP_ADIS_MODE). CONTRACTS.md §2.1.

Owner: WS-E.
"""
from __future__ import annotations

from typing import Any


def dph_fact(ico: str, iban: str, *, settings: Any) -> dict[str, Any]:
    """WARN if account not published, BLOCK if unreliable payer; 'DPH ucet: ANO|NE'."""
    raise NotImplementedError("TODO WS-E")
