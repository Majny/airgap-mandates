"""RFC 9162 §2.1 Merkle primitives (pure). CONTRACTS.md §7.3.

Owner: WS-B.
"""
from __future__ import annotations



def leaf_hash(leaf_bytes: bytes) -> bytes:
    """SHA256(0x00 || leaf_bytes)."""
    raise NotImplementedError("TODO WS-B")


def node_hash(left: bytes, right: bytes) -> bytes:
    """SHA256(0x01 || left || right)."""
    raise NotImplementedError("TODO WS-B")


def root(leaf_hashes: list[bytes]) -> bytes:
    """MTH; empty tree = SHA256(b'')."""
    raise NotImplementedError("TODO WS-B")


def inclusion_proof(index: int, leaf_hashes: list[bytes]) -> list[bytes]:
    """RFC 9162 §2.1.3 audit path."""
    raise NotImplementedError("TODO WS-B")


def verify_inclusion(index: int, tree_size: int, leaf: bytes, path: list[bytes], root_hash: bytes) -> bool:
    """Verify inclusion proof."""
    raise NotImplementedError("TODO WS-B")


def consistency_proof(old_size: int, leaf_hashes: list[bytes]) -> list[bytes]:
    """RFC 9162 §2.1.4."""
    raise NotImplementedError("TODO WS-B")


def verify_consistency(old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: list[bytes]) -> bool:
    """Verify consistency proof."""
    raise NotImplementedError("TODO WS-B")
