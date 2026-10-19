"""Fact orchestration: run all fact producers for a proposal or change. CONTRACTS.md §2.1.

Owner: WS-E.
"""
from __future__ import annotations

from typing import Any


def facts_for_proposal(invoice: dict[str, Any], vendor: dict[str, Any] | None, hints: list[dict[str, Any]], *, store: Any, settings: Any) -> list[dict[str, Any]]:
    """All F facts + H facts (from hints) for a payment proposal."""
    raise NotImplementedError("TODO WS-E")


def facts_for_change(vendor: dict[str, Any], new_iban: str, email_id: str | None, hints: list[dict[str, Any]], *, store: Any, settings: Any) -> list[dict[str, Any]]:
    """All F facts + H facts for a payee change request."""
    raise NotImplementedError("TODO WS-E")


def hint_facts(hints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """H-AGENT / H-UI facts, severity INFO, display_line 'agent: "<text>"'."""
    raise NotImplementedError("TODO WS-E")
