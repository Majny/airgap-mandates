"""F-DKIM: dkimpy.verify with dnsfunc over data/dns_snapshot.json. CONTRACTS.md §2.1.

Owner: WS-E.
"""
from __future__ import annotations

from typing import Any


def dkim_fact(raw_eml: bytes, *, dns_snapshot: dict[str, Any]) -> dict[str, Any]:
    """F-DKIM fact (BLOCK on fail, INFO 'DKIM ok d=<domain>' on pass)."""
    raise NotImplementedError("TODO WS-E")
