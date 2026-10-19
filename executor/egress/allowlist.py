"""Destination allowlist (vendor domains from registry + internal addresses). CONTRACTS.md §4.2.

Owner: WS-C.
"""
from __future__ import annotations

from typing import Any


def is_allowed(tool: str, target: str, *, vendors: list[dict[str, Any]]) -> bool:
    """True if target is on the allowlist."""
    raise NotImplementedError("TODO WS-C")


def url_data_findings(target: str) -> list[dict[str, Any]]:
    """E-URLDATA findings for data smuggled in URL query/path."""
    raise NotImplementedError("TODO WS-C")
