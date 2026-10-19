"""DLP content checks: IBANs, ICOs, registry names, card numbers (Luhn), record counts, encoded payloads. CONTRACTS.md §4.2.

Owner: WS-E.
"""
from __future__ import annotations

from typing import Any


def scan(content: str, attachments: list[dict[str, Any]], *, vendors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Findings [{rule_id, detail, count}]."""
    raise NotImplementedError("TODO WS-E")
