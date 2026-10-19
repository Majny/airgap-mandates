"""Signer abstraction: AWS KMS ECDSA_SHA_256 (ECC_NIST_P256) or local P-256 PEM in AIRGAP_LOCAL_KEY_DIR. CONTRACTS.md §7.3, §9.

Owner: WS-A.
"""
from __future__ import annotations

from typing import Any


def sign(message: bytes, *, settings: Any, key: str = 'executor') -> str:
    """Base64 DER ECDSA signature."""
    raise NotImplementedError("TODO WS-A")


def public_key_pem(*, settings: Any, key: str = 'executor') -> str:
    """PEM public key for audit export."""
    raise NotImplementedError("TODO WS-A")


def verify(message: bytes, sig_b64: str, public_key_pem: str) -> bool:
    """Offline verification."""
    raise NotImplementedError("TODO WS-A")
