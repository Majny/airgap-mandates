"""Thin ports from the payee-change FSM to audit, render/nonces and policy. CONTRACTS.md v2 §2.3, §3.1, §6.1, §7.2.

Owner: WS-D.

machine.py only talks to the audit log, the challenge store and the `change` policy set through this module, so
tests can monkeypatch `emit` (tests/fakes.FakeAudit) while the WS-A/WS-B modules are being written.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Any

from executor import render
from executor.canonical import canonical_json, sha256_hex
from executor.config import iso
from executor.errors import ApiError, ErrorCode
from executor.models import DECISION_RELEVANT_EVENTS, AuditEventType, ChallengeRef, FactSet, Purpose

_NONCE_TRIES = 16
_EMPTY_DIGEST = sha256_hex(canonical_json([]))


def _f_facts(facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [f for f in facts or [] if f.get("kind") == "F"]


def facts_digest_of(facts: list[dict[str, Any]]) -> str:
    """CONTRACTS §2.1 facts_digest (F facts only, canonical order)."""
    from executor.facts.compute import facts_digest

    return facts_digest(list(facts or []))


def emit(store: Any, settings: Any, type: str, data: dict[str, Any], *, subject_id: str | None, actor: str,
         facts_digest: str | None = None, hints_digest: str | None = None, log_id: str = "audit") -> int:
    """Append one audit leaf (executor.audit.log.make_event + append); returns its seq. Decision-relevant events
    always carry policy_hash, inputs_digest (= digest of `data`), facts_digest and hints_digest."""
    from executor.audit import log
    from executor.policy.rules import policy_hash

    relevant = AuditEventType(type) in DECISION_RELEVANT_EVENTS
    event = log.make_event(
        type, data, subject_id=subject_id, actor=actor, log_id=log_id,
        policy_hash=policy_hash() if relevant else None,
        inputs_digest=sha256_hex(canonical_json(data)) if relevant else None,
        facts_digest=(facts_digest or _EMPTY_DIGEST) if relevant else facts_digest,
        hints_digest=(hints_digest or _EMPTY_DIGEST) if relevant else hints_digest,
    )
    return log.append(event, store=store, settings=settings)


def _new_nonce() -> str:
    return secrets.token_hex(4).upper()


def _issue(template: str, purpose: str, role: str, params: dict[str, Any], *, subject_id: str, facts_digest: str,
           store: Any, settings: Any, now: datetime) -> ChallengeRef:
    """Render, persist the `nonces` row (put_if_absent, retry on collision) and append the `challenge` leaf."""
    from executor.policy.rules import policy_hash

    prof = render.get_profile(settings.render_profile)
    deployment = settings.deployment_id
    exp = iso(now + timedelta(seconds=settings.challenge_ttl_seconds))
    for _ in range(_NONCE_TRIES):
        nonce = _new_nonce()
        p = dict(params, nonce=nonce, deployment=deployment)
        subject = render.subject_object(deployment=deployment, purpose=purpose, role=role, subject_id=subject_id,
                                        nonce=nonce, params=p, facts_digest=facts_digest,
                                        policy_hash=policy_hash())
        p["subject_hash"] = render.subject_hash(subject)
        text = render.render(template, p, profile=prof.name)
        nonce_secret = secrets.token_hex(16)
        row = {
            "nonce": nonce, "nonce_secret": nonce_secret, "purpose": purpose, "role": role,
            "subject_id": subject_id, "template": template, "params": canonical_json(p).decode("utf-8"),
            "profile": prof.name, "deployment": deployment, "text": text, "text_sha256": render.text_sha256(text),
            "subject_hash": p["subject_hash"], "exp": exp, "used": False, "created_at": iso(now),
        }
        if store.put_if_absent("nonces", row, "nonce"):
            break
    else:
        raise ApiError(ErrorCode.INTERNAL_ERROR, "could not allocate a challenge nonce")
    emit(store, settings, AuditEventType.CHALLENGE.value, {
        "nonce": nonce, "nonce_secret_sha256": hashlib.sha256(nonce_secret.encode("ascii")).hexdigest(),
        "purpose": purpose, "role": role, "subject_id": subject_id, "deployment": deployment, "profile": prof.name,
        "text_sha256": row["text_sha256"], "subject_hash": row["subject_hash"], "exp": exp,
    }, subject_id=subject_id, actor="executor", facts_digest=facts_digest)
    return {
        "nonce": nonce, "purpose": purpose, "role": role, "subject_id": subject_id, "deployment": deployment,
        "profile": prof.name, "exp": exp, "text": text, "text_sha256": row["text_sha256"],
        "subject_hash": row["subject_hash"], "width": prof.width, "lines_per_page": prof.lines_per_page,
        "pages": len(render.render_pages(text, prof.name)), "line_count": len(text.split("\n")), "used": False,
        "created_at": iso(now),
    }


def issue_chg_challenge(change: dict[str, Any], *, role: str, sig_index: int, store: Any, settings: Any,
                        now: datetime) -> ChallengeRef:
    """CHG challenge (clerk 1/2 on entering SIG_CLERK, treasury 2/2 after the clerk signed; same body, new nonce)."""
    facts = _f_facts(change["facts"])
    params = {
        "change_no": change["change_no"], "vendor_name": change["vendor_name"], "vendor_ico": change["vendor_ico"],
        "old_iban": change["old_iban"], "old_since": change["old_since"], "new_iban": change["new_iban"],
        "facts": facts, "role": role, "sig_index": sig_index, "sig_total": 2,
    }
    return _issue("CHG", Purpose.CHG.value, role, params, subject_id=change["change_id"],
                  facts_digest=facts_digest_of(facts), store=store, settings=settings, now=now)


def issue_reject_challenge(change: dict[str, Any], *, role: str = "clerk", store: Any, settings: Any,
                           now: datetime) -> ChallengeRef:
    """CHG_REJECT challenge for a host-initiated reject (the reject happens on the clerk's signature)."""
    params = {
        "change_no": change["change_no"], "vendor_name": change["vendor_name"], "vendor_ico": change["vendor_ico"],
        "new_iban": change["new_iban"], "role": role,
    }
    return _issue("CHG_REJECT", Purpose.CHG_REJECT.value, role, params, subject_id=change["change_id"],
                  facts_digest=facts_digest_of(change["facts"]), store=store, settings=settings, now=now)


def _parse(ts: str | None) -> datetime | None:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else None


def local_change_check(change: dict[str, Any], facts: FactSet, now: datetime) -> tuple[bool, list[str]]:
    """Pure mirror of policy set `change` (I-ATTEST, I-CALLBACK, I-COOLOFF, I-BLOCK). WS-A's Cedar set is
    authoritative; this is used only while executor.policy.decide.may_issue_chg_challenge is unavailable."""
    f_facts = _f_facts(facts["facts"])
    rules: set[str] = set()
    if any(f["severity"] == "BLOCK" for f in f_facts):
        rules.add("I-BLOCK")
    att = next((f for f in f_facts if f["id"] == "F-ATTEST"), None)
    off_path = not change.get("in_network") or change.get("break_glass")
    if not off_path and (att is None or att["severity"] != "INFO"):
        rules.add("I-ATTEST")
    if off_path and (change.get("callback") or {}).get("status") != "confirmed":
        rules.add("I-CALLBACK")
    nb = _parse(change.get("not_before"))
    if nb is None or now < nb:
        rules.add("I-COOLOFF")
    return (not rules, sorted(rules))


def may_issue_chg_challenge(change: dict[str, Any], facts: FactSet, now: datetime) -> tuple[bool, list[str]]:
    """Policy set `change` via executor.policy.decide (Cedar); falls back to local_change_check only while WS-A's
    implementation raises NotImplementedError."""
    from executor.policy import decide
    from executor.policy.rules import policy_material

    try:
        return decide.may_issue_chg_challenge(change, facts, now=now, policy=policy_material())
    except NotImplementedError:
        return local_change_check(change, facts, now)
