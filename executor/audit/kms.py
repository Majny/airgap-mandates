"""Ed25519 signer: AWS KMS (ECC_NIST_EDWARDS25519, ED25519_SHA_512, RAW) or local key (dev/CI; Secrets Manager
fallback on AWS). CONTRACTS.md v2 §7.3, §9. Owner: WS-B.
"""
from __future__ import annotations

import functools
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

KEYS = ("log", "w1")


ENV = {"log": "AIRGAP_KMS_KEY_ID", "w1": "AIRGAP_WITNESS_KMS_KEY_ID"}


class KeyNotConfigured(RuntimeError):
    """backend=aws without the KMS key id: never fall back to a local key on AWS."""


def _kms_key_id(settings: Any, key: str) -> str | None:
    if key not in KEYS:
        raise ValueError(f"unknown signing key {key!r}")
    key_id = settings.kms_key_id if key == "log" else settings.witness_kms_key_id
    if not key_id and getattr(settings, "backend", None) == "aws":
        raise KeyNotConfigured(f"backend=aws but {ENV[key]} is not set: refusing to use a local '{key}' key")
    return key_id


@functools.lru_cache(maxsize=8)
def _kms_client(region: str) -> Any:
    import boto3

    return boto3.client("kms", region_name=region)


@functools.lru_cache(maxsize=8)
def _local_key(key_dir: str, key: str) -> Ed25519PrivateKey:
    """Seed file <key_dir>/<key>.ed25519 (32 raw bytes), created on first use. Dev/CI only."""
    path = Path(key_dir) / f"{key}.ed25519"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(32))
    return Ed25519PrivateKey.from_private_bytes(path.read_bytes())


def sign_ed25519(message: bytes, *, settings: Any, key: str = "log") -> bytes:
    """64-byte Ed25519 signature; key 'log' (checkpointer) or 'w1' (witness)."""
    key_id = _kms_key_id(settings, key)
    if key_id:
        resp = _kms_client(settings.aws_region).sign(KeyId=key_id, Message=message, MessageType="RAW",
                                                      SigningAlgorithm="ED25519_SHA_512")
        return resp["Signature"]
    return _local_key(settings.local_key_dir, key).sign(message)


@functools.lru_cache(maxsize=8)
def _kms_public_key(region: str, key_id: str) -> bytes:
    der = _kms_client(region).get_public_key(KeyId=key_id)["PublicKey"]
    return load_der_public_key(der).public_bytes(Encoding.Raw, PublicFormat.Raw)


def public_key(*, settings: Any, key: str = "log") -> bytes:
    """32-byte raw Ed25519 public key."""
    key_id = _kms_key_id(settings, key)
    if key_id:
        return _kms_public_key(settings.aws_region, key_id)
    return _local_key(settings.local_key_dir, key).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def verify_ed25519(message: bytes, sig: bytes, pubkey: bytes) -> bool:
    """Offline verification (PyNaCl / cryptography)."""
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(sig, message)
    except (InvalidSignature, ValueError):
        return False
    return True
