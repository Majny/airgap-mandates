"""Witness: verify consistency with last seen STH, cosign canonical_json(sth_body) with own key; refuse forks. CONTRACTS.md §7.3.

Owner: WS-B.
"""
from __future__ import annotations

from typing import Any


def cosign(sth_body: dict[str, Any], consistency_proof: list[str], *, settings: Any) -> str:
    """Base64 DER witness signature; raises on inconsistency."""
    raise NotImplementedError("TODO WS-B")


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Witness Lambda entry point."""
    raise NotImplementedError("TODO WS-B")
