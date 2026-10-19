"""Canonical JSON (CONTRACTS.md §7.1).

json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8");
floats are forbidden (raise TypeError/ValueError).

Owner: WS-B.
"""
from __future__ import annotations

from typing import Any


def canonical_json(obj: Any) -> bytes:
    """Canonical UTF-8 JSON bytes; raises on floats/NaN."""
    raise NotImplementedError("TODO WS-B")


def sha256_hex(data: bytes) -> str:
    """Lowercase hex SHA-256."""
    raise NotImplementedError("TODO WS-B")
