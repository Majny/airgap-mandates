"""W1 witness: C2SP tlog-witness add-checkpoint, timestamped Ed25519 cosignature (type 0x04).

Refuses forks (409 stale / 422 bad proof), 403 bad signature, 404 unknown origin; size check + persistence in one
conditional write on witness_state. CONTRACTS.md v2 §7.3. Owner: WS-B.
"""
from __future__ import annotations

from typing import Any


def add_checkpoint(body: bytes, *, store: Any, settings: Any) -> tuple[int, str, bytes]:
    """Return (http_status, content_type, body): 200 text/plain cosignature line(s) | 409 text/x.tlog.size | 403 | 404 | 422."""
    raise NotImplementedError("TODO WS-B")


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """W1 λ entry point (own role, own KMS key, own table)."""
    raise NotImplementedError("TODO WS-B")
