"""W2 relay: pull checkpoint + proof from the export API, POST to an unmodified litewitness, upload the cosignature.

"independent supervisor witness (simulated operator)". CONTRACTS.md v2 §7.3. Owner: WS-B.
"""
from __future__ import annotations


def relay_once(*, executor_url: str, w2_url: str) -> int:
    """One relay round; returns the HTTP status from W2."""
    raise NotImplementedError("TODO WS-B")
