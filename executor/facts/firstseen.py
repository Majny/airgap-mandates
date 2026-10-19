"""F-FIRSTSEEN: first time the sender domain appears in our inbox (inbox.by_domain GSI). CONTRACTS.md §2.1.

Owner: WS-D.
"""
from __future__ import annotations

from typing import Any


def firstseen_fact(from_domain: str, *, store: Any, now: Any) -> dict[str, Any]:
    """WARN if first seen < 72 h ago, e.g. 'domain first seen 2h'."""
    raise NotImplementedError("TODO WS-D")
