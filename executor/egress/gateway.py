"""POST /egress implementation: allow or 403 egress_blocked + egress_block leaf. CONTRACTS.md §4.2.

Owner: WS-E.
"""
from __future__ import annotations

from typing import Any


def handle_egress(req: dict[str, Any], *, store: Any, settings: Any) -> dict[str, Any]:
    """Return allow body or raise ApiError(egress_blocked, details={'decision': ...})."""
    raise NotImplementedError("TODO WS-E")
