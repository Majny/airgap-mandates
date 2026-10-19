"""Egress client: every outbound tool effect -> POST /egress. CONTRACTS.md §4.2.

Owner: WS-E.
"""
from __future__ import annotations

from typing import Any


def send(tool: str, target: str, content: str, attachments: list[dict[str, Any]] | None = None, *, executor_url: str | None = None) -> dict[str, Any]:
    """Ask the executor; perform the effect only on allow."""
    raise NotImplementedError("TODO WS-E")
