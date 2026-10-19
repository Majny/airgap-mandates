"""Replay a month through the in-process executor (handler.dispatch). CONTRACTS.md §8.1.

Owner: WS-D.
"""
from __future__ import annotations

from typing import Any


def replay(month_path: str, *, settings: Any = None) -> dict[str, Any]:
    """Metrics: caught/20 by type, false exceptions, exceptions per approver per day, signatures per 100 payments."""
    raise NotImplementedError("TODO WS-D")
