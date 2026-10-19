"""C2SP tlog-checkpoint in a signed-note (Ed25519), cosigned by W1/W2. CONTRACTS.md v2 §7.3. Owner: WS-B."""
from __future__ import annotations

from typing import Any


def checkpoint_body(origin: str, size: int, root_hash_hex: str, *, policy_hash: str, code_sha256: str) -> str:
    """'<origin>\\n<size>\\n<b64 root>\\npolicy sha256:<hex>\\ncode sha256:<hex> pcr0 -\\n'."""
    raise NotImplementedError("TODO WS-B")


def key_id(name: str, pubkey: bytes, sig_type: int = 0x01) -> bytes:
    """SHA-256(name || 0x0A || sig_type || pubkey)[:4] (0x01 Ed25519 note sig, 0x04 timestamped cosignature)."""
    raise NotImplementedError("TODO WS-B")


def verifier_key(name: str, pubkey: bytes) -> str:
    """Go sumdb/note verifier key 'name+<keyid hex>+<b64(0x01||pubkey)>'."""
    raise NotImplementedError("TODO WS-B")


def sign_note(body: str, *, name: str, settings: Any) -> str:
    """Body + blank line + '— <name> <b64(keyid||sig)>' (KMS Ed25519 or local fallback)."""
    raise NotImplementedError("TODO WS-B")


def make_checkpoint(log_id: str, *, store: Any, settings: Any) -> str:
    """Compute root, sign, send to W1 (and W2 relay), store the cosigned note in `checkpoints`, S3 Object Lock copy,
    checkpoint leaf. Returns the cosigned note text."""
    raise NotImplementedError("TODO WS-B")


def parse_note(note: str) -> dict[str, Any]:
    """{origin, size, root_hash, extensions[], signatures[{name, key_id, sig, timestamp?}]}."""
    raise NotImplementedError("TODO WS-B")
