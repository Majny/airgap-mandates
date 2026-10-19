"""Thin ports from the payee-change FSM to audit, challenges and policy. CONTRACTS.md v2 §2.3, §3.1, §6.1, §7.2.

Owner: WS-D.

machine.py only talks to the audit log (executor.store.shims -> executor.audit.log, WS-B), the challenge issuer
(executor.policy.challenge, WS-A) and policy set `change` (executor.policy.decide, WS-A) through this module.
CHG_REJECT challenges are issued by WS-A's handler (POST /changes/{id}/reject), not here.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from executor.models import DECISION_RELEVANT_EVENTS, AuditEventType, ChallengeRef, FactSet, Purpose
from executor.store import shims


def _f_facts(facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [f for f in facts or [] if f.get("kind") == "F"]


def facts_digest_of(facts: list[dict[str, Any]]) -> str:
    """CONTRACTS §2.1 facts_digest (F facts only, canonical order)."""
    from executor.facts.compute import facts_digest

    return facts_digest(list(facts or []))


def emit(store: Any, settings: Any, type: str, data: dict[str, Any], *, subject_id: str | None, actor: str,
         facts_digest: str | None = None, hints_digest: str | None = None, log_id: str = "audit") -> int:
    """Append one audit leaf (shims.make_event + shims.append -> executor.audit.log, which checkpoints when due);
    returns its seq. Decision-relevant events always carry policy_hash, inputs_digest (= digest of `data`),
    facts_digest and hints_digest."""
    from executor.policy.rules import policy_hash

    relevant = AuditEventType(type) in DECISION_RELEVANT_EVENTS
    empty = shims.digest([])
    event = shims.make_event(
        type, data, subject_id=subject_id, actor=actor, settings=settings, log_id=log_id,
        policy_hash=policy_hash() if relevant else None,
        inputs_digest=shims.digest(data) if relevant else None,
        facts_digest=(facts_digest or empty) if relevant else facts_digest,
        hints_digest=(hints_digest or empty) if relevant else hints_digest,
    )
    return shims.append(event, store=store, settings=settings)


def chg_params(change: dict[str, Any], *, sig_index: int) -> dict[str, Any]:
    """render_change kwargs minus nonce / subject_hash / deployment / role (issue_challenge adds those)."""
    return {
        "change_no": change["change_no"], "vendor_name": change["vendor_name"], "vendor_ico": change["vendor_ico"],
        "old_iban": change["old_iban"], "old_since": change["old_since"], "new_iban": change["new_iban"],
        "facts": _f_facts(change["facts"]), "sig_index": sig_index, "sig_total": 2,
    }


def issue_chg_challenge(change: dict[str, Any], *, role: str, sig_index: int, store: Any, settings: Any,
                        now: datetime) -> ChallengeRef:
    """CHG challenge (clerk 1/2 on entering SIG_CLERK, treasury 2/2 after the clerk signed; same body, new nonce)
    via executor.policy.challenge.issue_challenge (nonces row + `challenge` leaf)."""
    from executor.policy.challenge import issue_challenge

    return issue_challenge(purpose=Purpose.CHG.value, role=role, subject_id=change["change_id"],
                           params=chg_params(change, sig_index=sig_index),
                           facts_digest=facts_digest_of(_f_facts(change["facts"])), store=store, settings=settings,
                           now=now)


def may_issue_chg_challenge(change: dict[str, Any], facts: FactSet, now: datetime) -> tuple[bool, list[str]]:
    """Policy set `change` (I-ATTEST, I-CALLBACK, I-COOLOFF, I-BLOCK) via executor.policy.decide (Cedar)."""
    from executor.policy import decide
    from executor.policy.rules import policy_material

    return decide.may_issue_chg_challenge(change, facts, now=now, policy=policy_material())
