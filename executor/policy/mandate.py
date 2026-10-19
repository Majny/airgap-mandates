"""Mandate lifecycle (M0): create from form, activation on signature, spend accounting. CONTRACTS.md §4.2, §3.2.

Owner: WS-A.
"""
from __future__ import annotations

from typing import Any


def create_mandate(form: dict[str, Any], *, store: Any, settings: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate form, allocate mandate_no, create MANDATE challenge -> (mandate, challenge_ref)."""
    raise NotImplementedError("TODO WS-A")


def activate_mandate(mandate_id: str, signer_address: str, nonce: str, *, store: Any, settings: Any) -> dict[str, Any]:
    """PENDING_SIG -> ACTIVE, previous ACTIVE -> SUPERSEDED, mandate_signed leaf."""
    raise NotImplementedError("TODO WS-A")


def get_active_mandate(*, store: Any, settings: Any) -> dict[str, Any] | None:
    """The single ACTIVE, unexpired mandate with current policy_hash, or None."""
    raise NotImplementedError("TODO WS-A")
