"""Optional RFC 3161 timestamping (AIRGAP_TSA_URL, default off; extra [tsa]). CONTRACTS.md v2 §7.3. Owner: WS-B."""
from __future__ import annotations

from typing import Any


def timestamp(data: bytes, *, settings: Any) -> bytes | None:
    """TSA token (DER) or None when AIRGAP_TSA_URL=off / unreachable."""
    raise NotImplementedError("TODO WS-B")
