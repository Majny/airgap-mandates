"""Signed tree heads: body, executor KMS signature, witness cosign. CONTRACTS.md §7.3.

Owner: WS-A.
"""
from __future__ import annotations

from typing import Any


def make_sth(log_id: str, *, store: Any, settings: Any) -> dict[str, Any]:
    """Compute root, sign canonical_json(body), request witness cosign, store in sth table."""
    raise NotImplementedError("TODO WS-A")
