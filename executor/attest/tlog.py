"""Attestation transparency log (log_id 'attest') on top of executor.audit.merkle. CONTRACTS.md §7.3.

Owner: WS-B.
"""
from __future__ import annotations

from typing import Any


def append_commitment(ico: str, v: int, commitment: str, *, store: Any, settings: Any) -> int:
    """Append attestation leaf, return leaf index."""
    raise NotImplementedError("TODO WS-B")


def inclusion_proof(leaf_index: int, *, store: Any) -> dict[str, Any]:
    """{log_id, leaf_index, tree_size, audit_path, sth}."""
    raise NotImplementedError("TODO WS-B")
