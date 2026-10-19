"""RFC 9162 §2.1 Merkle primitives (pure). CONTRACTS.md §7.3.

Owner: WS-B.
"""
from __future__ import annotations

import hashlib


def leaf_hash(leaf_bytes: bytes) -> bytes:
    """SHA256(0x00 || leaf_bytes)."""
    return hashlib.sha256(b"\x00" + leaf_bytes).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """SHA256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def root(leaf_hashes: list[bytes]) -> bytes:
    """MTH; empty tree = SHA256(b'')."""
    n = len(leaf_hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hashes[0]
    k = _split(n)
    return node_hash(root(leaf_hashes[:k]), root(leaf_hashes[k:]))


def inclusion_proof(index: int, leaf_hashes: list[bytes]) -> list[bytes]:
    """RFC 9162 §2.1.3 audit path."""
    n = len(leaf_hashes)
    if not 0 <= index < n:
        raise ValueError(f"index {index} out of range for tree size {n}")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(index, leaf_hashes[:k]) + [root(leaf_hashes[k:])]
    return inclusion_proof(index - k, leaf_hashes[k:]) + [root(leaf_hashes[:k])]


def verify_inclusion(index: int, tree_size: int, leaf: bytes, path: list[bytes], root_hash: bytes) -> bool:
    """Verify inclusion proof (RFC 9162 §2.1.3.2); `leaf` is the leaf hash."""
    if not 0 <= index < tree_size:
        return False
    fn, sn, r = index, tree_size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root_hash


def _subproof(m: int, leaves: list[bytes], complete: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if complete else [root(leaves)]
    k = _split(n)
    if m <= k:
        return _subproof(m, leaves[:k], complete) + [root(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [root(leaves[:k])]


def consistency_proof(old_size: int, leaf_hashes: list[bytes]) -> list[bytes]:
    """RFC 9162 §2.1.4."""
    n = len(leaf_hashes)
    if not 0 <= old_size <= n:
        raise ValueError(f"old size {old_size} out of range for tree size {n}")
    if old_size in (0, n):
        return []
    return _subproof(old_size, leaf_hashes, True)


def verify_consistency(old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: list[bytes]) -> bool:
    """Verify consistency proof (RFC 9162 §2.1.4.2)."""
    if not 0 <= old_size <= new_size:
        return False
    if old_size == new_size:
        return not proof and old_root == new_root
    if old_size == 0:
        return not proof
    if not proof:
        return False
    path = list(proof)
    if old_size & (old_size - 1) == 0:  # power of two: old root is the first node
        path.insert(0, old_root)
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root
