"""Vendor key policies (signers, threshold, policy_v), rotation under old quorum. CONTRACTS.md §3.1 vendor_policies, §6.

Owner: WS-D.
"""
from __future__ import annotations

from typing import Any


def current_policy(ico: str, *, store: Any) -> dict[str, Any] | None:
    """ACTIVE vendor policy."""
    raise NotImplementedError("TODO WS-D")


def signer_role(ico: str, address: str, *, store: Any) -> str | None:
    """Role of address in current policy, or None (foreign / revoked)."""
    raise NotImplementedError("TODO WS-D")
