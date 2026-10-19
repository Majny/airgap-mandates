"""RFC 3161 timestamping via rfc3161ng (AIRGAP_TSA_URL). CONTRACTS.md §7.3.

Owner: WS-A.
"""
from __future__ import annotations

from typing import Any


def timestamp(data: bytes, *, settings: Any) -> bytes | None:
    """TSA token (DER) or None when AIRGAP_TSA_URL=off / unreachable."""
    raise NotImplementedError("TODO WS-A")
