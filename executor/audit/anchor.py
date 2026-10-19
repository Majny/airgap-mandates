"""Anchors to S3 Object Lock (audit-anchor/<log_id>/<tree_size:012d>.json). CONTRACTS.md §7.3.

Owner: WS-A.
"""
from __future__ import annotations

from typing import Any


def anchor(log_id: str, *, store: Any, settings: Any) -> dict[str, Any]:
    """Write anchor object (+ RFC 3161 token) and an anchor leaf."""
    raise NotImplementedError("TODO WS-A")
