"""Bench report: ASR, false-block rate, exceptions/100, signatures/100, 95% Wilson intervals. CONTRACTS.md §1.

Owner: WS-D.
"""
from __future__ import annotations

from typing import Any


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval."""
    raise NotImplementedError("TODO WS-D")


def report(results_dir: str) -> str:
    """Markdown table."""
    raise NotImplementedError("TODO WS-D")
