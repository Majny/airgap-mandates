"""Replay a month generator: ~600 invoices, 40 vendors, ~20 frauds, seed 42. CONTRACTS.md §8.1.

Owner: WS-F.
"""
from __future__ import annotations

from typing import Any


def generate(out_path: str, *, seed: int = 42) -> list[dict[str, Any]]:
    """Synthetic month of invoices with labeled frauds."""
    raise NotImplementedError("TODO WS-F")
