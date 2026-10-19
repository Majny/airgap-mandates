"""Vendor account attestations: propose, collect signatures, publish to tlog, revoke. CONTRACTS.md §3.1 attestations, §4.2.

Owner: WS-D.
"""
from __future__ import annotations

import hashlib
from typing import Any

from executor.canonical import canonical_json


def propose(req: dict[str, Any], *, store: Any, settings: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Create PENDING_SIGS attestation + one VENDOR_ATTEST challenge per policy signer role."""
    raise NotImplementedError("TODO WS-D")


def on_signature(ico: str, v: int, role: str, signer_address: str, sig: str, nonce: str, *, store: Any, settings: Any) -> dict[str, Any]:
    """Add sig; on quorum -> PUBLISHED + tlog leaf; re-check pending changes for ico."""
    raise NotImplementedError("TODO WS-D")


def revoke(ico: str, revokes_v: int, *, store: Any, settings: Any) -> dict[str, Any]:
    """Revocation record (needs quorum) + tlog leaf."""
    raise NotImplementedError("TODO WS-D")


def valid_attestation_for(ico: str, iban: str, *, store: Any) -> dict[str, Any] | None:
    """Latest PUBLISHED, non-revoked attestation for iban with quorum under current policy."""
    raise NotImplementedError("TODO WS-D")


def commitment(body: dict[str, Any], commit_nonce: bytes) -> str:
    """SHA256(canonical_json(body) || nonce128) hex — never a bare IBAN hash."""
    if len(commit_nonce) != 16:
        raise ValueError("commit_nonce must be 16 bytes (128 bit)")
    return hashlib.sha256(canonical_json(body) + commit_nonce).hexdigest()
