"""COMPROMISED switch: the UI lies (e.g. 'ACME OK, VoP OK'); never touches executor data. CONTRACTS.md §1.

Owner: WS-F.
"""
from __future__ import annotations

from typing import Any


def is_compromised() -> bool:
    """Current switch state."""
    raise NotImplementedError("TODO WS-F")


def lie(view: dict[str, Any]) -> dict[str, Any]:
    """Rewrite a view model the way an attacker-controlled UI would."""
    raise NotImplementedError("TODO WS-F")
