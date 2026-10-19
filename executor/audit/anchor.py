"""S3 Object Lock (GOVERNANCE, 1 day) copies of checkpoints and leaf batches + anchor leaf. CONTRACTS.md v2 §7.3.

Owner: WS-B.
"""
from __future__ import annotations

from typing import Any


def anchor(log_id: str, *, store: Any, settings: Any) -> dict[str, Any]:
    """Write <log_id>/<tree_size:012d>.json to AIRGAP_ANCHOR_BUCKET and an anchor leaf."""
    raise NotImplementedError("TODO WS-B")
