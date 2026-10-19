"""Commercial register (OR) snapshot + ARES binding: key <-> person with authority. CONTRACTS.md §6.

Owner: WS-B.
"""
from __future__ import annotations

from typing import Any


def load_or_snapshot(data_dir: str) -> dict[str, Any]:
    """Load data/or_snapshot.json."""
    raise NotImplementedError("TODO WS-B")


def enroll_vendor(ico: str, signers: list[dict[str, Any]], *, store: Any, settings: Any) -> dict[str, Any]:
    """Create policy_v 1 from OR snapshot (threshold from 'zpusob jednani')."""
    raise NotImplementedError("TODO WS-B")
