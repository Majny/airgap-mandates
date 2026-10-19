"""Mandate lifecycle (2/2 above the dual threshold). CONTRACTS.md v2 §4.2, §3.2. Owner: WS-A."""
from __future__ import annotations

from typing import Any


def create_mandate(form: dict[str, Any], *, store: Any, settings: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate form, pin registry version/hash, sig_required = 2 if max_total_minor > dual threshold;
    allocate mandate_no; create MANDATE challenge (clerk, ROLE CLERK 1/n) -> (mandate PENDING_SIG_CLERK, challenge)."""
    raise NotImplementedError("TODO WS-A")


def on_mandate_signature(mandate_id: str, role: str, signer_address: str, nonce: str, *, store: Any,
                         settings: Any) -> dict[str, Any]:
    """PENDING_SIG_CLERK -> (PENDING_SIG_TREASURY + treasury challenge | ACTIVE); treasury address != clerk;
    activation supersedes the previous ACTIVE mandate; mandate_signed leaf."""
    raise NotImplementedError("TODO WS-A")


def get_active_mandate(*, store: Any, settings: Any) -> dict[str, Any] | None:
    """The single ACTIVE, unexpired mandate with the current policy_hash, or None."""
    raise NotImplementedError("TODO WS-A")
