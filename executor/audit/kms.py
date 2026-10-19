"""Ed25519 signer: AWS KMS (ECC_NIST_EDWARDS25519, ED25519_SHA_512, RAW) or local key (dev/CI; Secrets Manager
fallback on AWS). CONTRACTS.md v2 §7.3, §9. Owner: WS-B.
"""
from __future__ import annotations

from typing import Any


def sign_ed25519(message: bytes, *, settings: Any, key: str = "log") -> bytes:
    """64-byte Ed25519 signature; key 'log' (checkpointer) or 'w1' (witness)."""
    raise NotImplementedError("TODO WS-B")


def public_key(*, settings: Any, key: str = "log") -> bytes:
    """32-byte raw Ed25519 public key."""
    raise NotImplementedError("TODO WS-B")


def verify_ed25519(message: bytes, sig: bytes, pubkey: bytes) -> bool:
    """Offline verification (PyNaCl / cryptography)."""
    raise NotImplementedError("TODO WS-B")
