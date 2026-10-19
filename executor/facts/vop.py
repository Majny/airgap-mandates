"""F-VOP: Verification of Payee mock (MTCH / CMTC / NMTC / NOAP), EUR only. CONTRACTS.md §2.1.

Owner: WS-E.
"""
from __future__ import annotations

from typing import Any


def vop_fact(iban: str, name: str) -> dict[str, Any] | None:
    """NMTC -> BLOCK, CMTC -> WARN, None for non-EUR."""
    raise NotImplementedError("TODO WS-E")
