"""Vendor signers (director/accountant/finance emulators) sign VENDOR_ATTEST challenges. CONTRACTS.md §5.2, §6.

Owner: WS-B.
"""
from __future__ import annotations

from typing import Any


def sign_attestation_challenge(nonce: str, role: str, *, transport: str | None = None, executor_url: str | None = None) -> dict[str, Any]:
    """Fetch challenge, sign on device, POST /signatures."""
    raise NotImplementedError("TODO WS-B")
