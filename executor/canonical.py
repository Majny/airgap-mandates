"""Canonical JSON (CONTRACTS.md §7.1).

json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8");
floats are forbidden (raise TypeError).

For our domain (integers only, ASCII object keys) this is byte-identical to RFC 8785 JCS
(tests/test_canonical.py checks JCS vectors).

Owner: WS-B.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def _reject_floats(obj: Any) -> None:
    if isinstance(obj, float):
        raise TypeError("floats are forbidden in canonical JSON")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise TypeError("object keys must be strings")
            _reject_floats(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _reject_floats(v)


def canonical_json(obj: Any) -> bytes:
    """Canonical UTF-8 JSON bytes; raises TypeError on floats/NaN or non-string keys."""
    _reject_floats(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Lowercase hex SHA-256."""
    return hashlib.sha256(data).hexdigest()
