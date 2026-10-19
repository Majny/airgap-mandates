"""Pure decision function, Cedar via cedarpy (replayed offline by tools/verify_audit.py). CONTRACTS.md v2 §2.2, §8.1.

No I/O, no LLM. Owner: WS-A.
"""
from __future__ import annotations

from typing import Any

from executor.models import DecisionObj, FactSet


def decide(subject: dict[str, Any], facts: FactSet, state: dict[str, Any], policy: dict[str, Any]) -> DecisionObj:
    """Tri-state decision for a payment proposal.

    subject: the proposal (`invoice` incl. vendor_id, amount_minor, ...).
    facts:   FactSet from executor.facts.compute.compute() (H facts are ignored entirely).
    state:   {"mandate": Mandate | None, "payee": registry row | None, "history": [ledger rows], "now": iso str}.
    policy:  executor.policy.rules.policy_material() (or the logged material for policy_hash on replay).
    Returns the Decision object without 'challenge' (the caller attaches it iff decision == "challenge").
    """
    raise NotImplementedError("TODO WS-A")


def may_issue_chg_challenge(change: dict[str, Any], facts: FactSet, *, now: Any,
                            policy: dict[str, Any]) -> tuple[bool, list[str]]:
    """Policy set `change` (I-ATTEST, I-CALLBACK, I-COOLOFF, I-BLOCK): (allowed, rule_ids). R0."""
    raise NotImplementedError("TODO WS-A")
