"""Payee-change state machine v2. Owner: WS-D. Implements CONTRACTS.md v2 §6.1 (S4, R0).

ALLOWED_TRANSITIONS, INITIAL_STATES and EVENT_TRANSITIONS are contract data; any transition not listed is
forbidden. The v1 transient states are now `change_event` leaves (models.ChangeEventKind), not states.

Collaborators are referenced as module attributes (`_vc.verify_vc`, `_compute.compute`, `portal.*`, `ports.*`) so
tests can substitute them. Every write to `changes` is conditional on the loaded state (optimistic concurrency).
"""
from __future__ import annotations

import copy
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from executor.attest import vc as _vc
from executor.canonical import canonical_json
from executor.change import ports
from executor.config import iso
from executor.errors import HTTP_STATUS, ApiError, ErrorCode
from executor.facts import compute as _compute
from executor.facts.anom import normalize_log as anom_log
from executor.facts import inbox as _inbox
from executor.models import (TERMINAL_STATES, AuditEventType, Change, ChangeEvent, ChangeEventKind, ChangeState,
                             Decision, DeviceAuthenticity, Fact, FactSet)
from executor.store import Op, TxConflict, UpdateIf
from vendor import portal

S = ChangeState
E = ChangeEvent

_NON_TERMINAL = [s for s in ChangeState if s not in TERMINAL_STATES]

# States a change can be created in (the "(create)" rows of §6.1).
INITIAL_STATES: frozenset[ChangeState] = frozenset({S.REJECTED, S.PENDING_ATTEST, S.CALLBACK_PENDING})

ALLOWED_TRANSITIONS: dict[ChangeState, set[ChangeState]] = {
    S.PENDING_ATTEST: {S.COOLING, S.CALLBACK_PENDING},
    S.CALLBACK_PENDING: {S.COOLING},
    S.COOLING: {S.SIG_CLERK},
    S.SIG_CLERK: {S.SIG_TREASURY},
    S.SIG_TREASURY: {S.ACTIVE},
    S.ACTIVE: set(),
    S.REJECTED: set(),
    S.EXPIRED: set(),
}
# Any non-terminal state may go to REJECTED or EXPIRED.
for _s in _NON_TERMINAL:
    ALLOWED_TRANSITIONS[_s] |= {S.REJECTED, S.EXPIRED}

# (state, event) -> destination. Guards are in CONTRACTS §6.1 and implemented by transition().
EVENT_TRANSITIONS: dict[tuple[ChangeState, ChangeEvent], ChangeState] = {
    (S.PENDING_ATTEST, E.VC_RECEIVED): S.COOLING,
    (S.PENDING_ATTEST, E.BREAK_GLASS): S.CALLBACK_PENDING,
    (S.CALLBACK_PENDING, E.CALLBACK_CONFIRM): S.COOLING,
    (S.CALLBACK_PENDING, E.CALLBACK_DENY): S.REJECTED,
    (S.CALLBACK_PENDING, E.CALLBACK_ATTEMPTS_EXCEEDED): S.REJECTED,
    (S.COOLING, E.COOLING_ELAPSED): S.SIG_CLERK,
    (S.SIG_CLERK, E.CLERK_SIGNED): S.SIG_TREASURY,
    (S.SIG_TREASURY, E.TREASURY_SIGNED): S.ACTIVE,
}
for _s in _NON_TERMINAL:
    EVENT_TRANSITIONS[(_s, E.TRIPWIRE_NOT_US)] = S.REJECTED
    EVENT_TRANSITIONS[(_s, E.VC_REVOKED)] = S.REJECTED
    EVENT_TRANSITIONS[(_s, E.CLERK_REJECT_SIGNED)] = S.REJECTED
    EVENT_TRANSITIONS[(_s, E.EXPIRE)] = S.EXPIRED


class ForbiddenTransition(ApiError):
    """Raised when a transition outside ALLOWED_TRANSITIONS / EVENT_TRANSITIONS is attempted (409 state_conflict
    through handler.dispatch, e.g. a callback code for a change that is no longer CALLBACK_PENDING)."""

    def __init__(self, message: str) -> None:
        super().__init__(ErrorCode.STATE_CONFLICT, message)


def is_allowed(src: ChangeState, dst: ChangeState) -> bool:
    """True iff src -> dst is in the transition table."""
    return dst in ALLOWED_TRANSITIONS[src]


def next_state(src: ChangeState, event: ChangeEvent) -> ChangeState:
    """Destination of `event` in state `src` (table lookup only, no guards); raises ForbiddenTransition."""
    try:
        dst = EVENT_TRANSITIONS[(src, event)]
    except KeyError:
        raise ForbiddenTransition(f"{event.value} not allowed in {src.value}") from None
    assert is_allowed(src, dst)
    return dst



# --------------------------------------------------------------------------- guards (CONTRACTS §6.1)

META_KEY = "registry#meta"
_CREATE_EXEMPT = frozenset({"F-ATTEST", "F-CALLBACK"})
_DEFAULT_ACTOR: dict[ChangeEvent, str] = {
    E.VC_RECEIVED: "issuer", E.BREAK_GLASS: "vendor_portal", E.CALLBACK_CONFIRM: "vendor_portal",
    E.CALLBACK_DENY: "vendor_portal", E.CALLBACK_ATTEMPTS_EXCEEDED: "vendor_portal", E.TRIPWIRE_NOT_US: "vendor_portal",
    E.VC_REVOKED: "executor", E.CLERK_REJECT_SIGNED: "host", E.EXPIRE: "executor", E.COOLING_ELAPSED: "executor",
}
_PORTAL_ONLY = frozenset({E.BREAK_GLASS, E.CALLBACK_CONFIRM, E.CALLBACK_DENY, E.TRIPWIRE_NOT_US})
# Events whose caller (executor.handler) names the authenticated actor in payload["actor"].
_PAYLOAD_ACTOR = frozenset({E.TRIPWIRE_NOT_US, E.CLERK_REJECT_SIGNED})


def _parse(ts: str | None) -> datetime | None:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else None


def _f_facts(facts: list[Fact]) -> list[Fact]:
    return [f for f in facts or [] if f.get("kind") == "F"]


def _blocking(facts: list[Fact], exempt: frozenset[str] = frozenset()) -> list[str]:
    return sorted({f["id"] for f in _f_facts(facts) if f["severity"] == "BLOCK" and f["id"] not in exempt})


def _distinct(results: list[dict[str, Any]]) -> int:
    return len({r["issuer_class"] for r in results if r.get("ok") and r.get("issuer_class")})


def _expect(change: Change) -> dict[str, Any]:
    """Optimistic-concurrency condition: the stored row still has what we loaded."""
    return copy.deepcopy({"state": change["state"], "attest_count": change["attest_count"],
                          "callback": change["callback"]})


def _load(store: Any, change_id: str) -> Change:
    row = store.get("changes", {"change_id": change_id})
    if row is None:
        raise ApiError(ErrorCode.NOT_FOUND, f"unknown change {change_id}")
    return row  # type: ignore[return-value]


def _vendor(store: Any, vendor_id: str) -> dict[str, Any]:
    row = store.get("registry", {"vendor_id": vendor_id})
    if row is None:
        raise ApiError(ErrorCode.NOT_FOUND, f"unknown vendor {vendor_id}")
    return row


def _event(change: Change, kind: ChangeEventKind, detail: dict[str, Any], *, store: Any, settings: Any,
           actor: str = "executor") -> None:
    ports.emit(store, settings, AuditEventType.CHANGE_EVENT.value,
               {"change_id": change["change_id"], "event": kind.value, "detail": detail},
               subject_id=change["change_id"], actor=actor, facts_digest=ports.facts_digest_of(change["facts"]))


def _persist(change: Change, *, expect: dict[str, Any], store: Any) -> None:
    body = {k: v for k, v in change.items() if k != "change_id"}
    if not store.update_if("changes", {"change_id": change["change_id"]}, body, expect):
        raise ApiError(ErrorCode.STATE_CONFLICT, "change was modified concurrently", {"state": change["state"]})


def _set_state(change: Change, dst: ChangeState, *, reason: str, actor: str, now: datetime) -> str | None:
    src = change.get("state")
    change["state"] = dst.value
    change["history"].append({"from": src, "to": dst.value, "at": iso(now), "reason": reason[:200], "actor": actor})
    if dst in TERMINAL_STATES:
        change["pending_challenge"] = None
    return src


def _leaf_transition(change: Change, src: str | None, event: ChangeEvent, reason: str, *, actor: str, store: Any,
                     settings: Any) -> None:
    ports.emit(store, settings, AuditEventType.STATE_TRANSITION.value,
               {"change_id": change["change_id"], "from": src, "to": change["state"], "event": event.value,
                "reason": reason[:200]},
               subject_id=change["change_id"], actor=actor, facts_digest=ports.facts_digest_of(change["facts"]))


def _commit(change: Change, dst: ChangeState, event: ChangeEvent, *, reason: str, actor: str,
            expect: dict[str, Any], store: Any, settings: Any, now: datetime) -> Change:
    """Guarded move: next_state() check, history entry, conditional write on the loaded state, state_transition leaf."""
    if next_state(ChangeState(expect["state"]), event) is not dst:
        raise ForbiddenTransition(f"{event.value}: {expect['state']} -> {dst.value}")
    src = _set_state(change, dst, reason=reason, actor=actor, now=now)
    _persist(change, expect=expect, store=store)
    _leaf_transition(change, src, event, reason, actor=actor, store=store, settings=settings)
    return change


# --------------------------------------------------------------------------- facts


def _revoked(settings: Any) -> set[str]:
    """Static revocation list (CONTRACTS §11), re-read on every check so a VC revoked during cooling-off stops counting."""
    return _vc.load_revoked(Path(settings.data_dir) / "vc_status.json")


def _is_revoked(row: dict[str, Any], revoked: set[str]) -> bool:
    return bool(revoked) and (row.get("vc_sha256") in revoked or row.get("issuer_jwt_sha256") in revoked)


def _attest_results(change_id: str, store: Any, revoked: set[str] | None = None) -> list[dict[str, Any]]:
    """AttestResult-shaped rows for F-ATTEST, from the `attestations` table (disclosures are not kept). A row whose
    VC is now on the revocation list is not ok (fail closed)."""
    revoked = revoked or set()
    return [{"ok": bool(r.get("verified")) and not _is_revoked(r, revoked), "issuer_class": r.get("issuer_class"),
             "iss": r.get("iss"), "error": "vc_revoked" if _is_revoked(r, revoked) else r.get("error"),
             "disclosed": {}, "vc_sha256": r.get("vc_sha256", "")}
            for r in store.query("attestations", ("change_id", change_id))]


def compute_change_facts(req: dict[str, Any], vendor: dict[str, Any], *, store: Any, settings: Any, now: datetime,
                         change: dict[str, Any] | None = None,
                         tool_log: list[dict[str, Any]] | None = None) -> FactSet:
    """Build the compute() state for a payee change (CONTRACTS §2.1) and return its FactSet. Before the change
    exists (change=None) F-ATTEST / F-CALLBACK come out BLOCK (ATT 0/3, CALLBACK MISSING). `tool_log`: the agent
    session's tool calls (executor.facts.anom.session_log) for F-ANOM; a caller without one scores an empty log."""
    in_network = bool(vendor.get("in_network"))
    provisional = {"in_network": in_network, "break_glass": False,
                   "callback": {"status": "none" if in_network else "pending", "code_exp": None, "attempts": 0}}
    subject = {"kind": "change", "subject_id": (change or {}).get("change_id", ""), "new_iban": req["new_iban"],
               "email_id": req.get("email_id"), "evidence_ids": list(req.get("evidence_ids") or []),
               "hints": req.get("hints") or []}
    state = {
        "payee": vendor, **_inbox.email_state(req.get("email_id"), store=store),
        "change": change or provisional,
        "attest_results": _attest_results(change["change_id"], store, _revoked(settings)) if change else [],
        "tool_log": anom_log(tool_log), "data_dir": settings.data_dir,
    }
    return _compute.compute(subject, state, now)


_SEV = {"INFO": 0, "WARN": 1, "BLOCK": 2}


def _sticky_anom(previous: list[dict[str, Any]], fs: FactSet) -> FactSet:
    """F-ANOM only escalates (CONTRACTS §2.1): a recompute without the creating session's tool log must never lower
    the F-ANOM the change was created with, so the more severe of the two is kept."""
    old = next((f for f in previous if f.get("id") == "F-ANOM" and f.get("kind") == "F"), None)
    new = next((f for f in fs["facts"] if f.get("id") == "F-ANOM" and f.get("kind") == "F"), None)
    if old is None or (new is not None and _SEV[new["severity"]] >= _SEV[old["severity"]]):
        return fs
    facts = _compute.order_facts([f for f in fs["facts"] if f is not new] + [old])
    return {**fs, "facts": facts, "facts_digest": _compute.facts_digest(facts),
            "max_severity": _compute.max_severity(facts)}


def _recompute(change: Change, *, store: Any, settings: Any, now: datetime) -> FactSet:
    vendor = _vendor(store, change["vendor_id"])
    req = {"vendor_id": change["vendor_id"], "new_iban": change["new_iban"], "email_id": change.get("email_id")}
    fs = compute_change_facts(req, vendor, store=store, settings=settings, now=now, change=change)
    fs = _sticky_anom(change.get("facts") or [], fs)
    hints = [f for f in change.get("facts") or [] if f.get("kind") == "H"]  # request hints are not re-sent: keep them
    change["facts"] = [f for f in fs["facts"] if f.get("kind") == "F"] + hints
    return fs


# --------------------------------------------------------------------------- create


def _old_since(vendor: dict[str, Any]) -> str:
    for h in vendor.get("iban_history") or []:
        if h.get("iban") == vendor["iban"] and h.get("to") is None:
            return str(h["from"])[:10]
    return str(vendor.get("registered_since", ""))[:10]


def _severity_rank(fs: FactSet) -> tuple[int, int]:
    sevs = [f["severity"] for f in _f_facts(fs["facts"])]
    return (sevs.count("BLOCK"), sevs.count("WARN"))


def _facts_for_cited_email(req: dict[str, Any], vendor: dict[str, Any], *, store: Any, settings: Any,
                           now: datetime, tool_log: list[dict[str, Any]] | None = None
                           ) -> tuple[dict[str, Any], FactSet]:
    """(request with the email the change is judged on, its FactSet). The candidates are `email_id` and every inbox
    email named by `evidence_ids` (the tools surface sends only evidence_ids); the WORST FactSet wins (most BLOCK,
    then most WARN; ties keep the earlier candidate), so citing more evidence can only move a change toward deny."""
    cands: list[str | None] = [req["email_id"]] if req.get("email_id") else []
    cands += [e for e in _inbox.resolve_email_ids(req.get("evidence_ids"), store=store, settings=settings)
              if e not in cands]
    best: tuple[dict[str, Any], FactSet] | None = None
    for eid in cands or [None]:
        cand = {**req, "email_id": eid}
        fs = compute_change_facts(cand, vendor, store=store, settings=settings, now=now, tool_log=tool_log)
        if best is None or _severity_rank(fs) > _severity_rank(best[1]):
            best = (cand, fs)
    assert best is not None
    return best


def create(req: dict[str, Any], facts: FactSet, vendor: dict[str, Any], *, store: Any, settings: Any,
           now: datetime, tool_log: list[dict[str, Any]] | None = None) -> Change:
    """POST /changes: initial state REJECTED (any F BLOCK) | PENDING_ATTEST (in_network) | CALLBACK_PENDING;
    tripwire to the registered contact on every create; change_event + state_transition leaves.

    The caller's `facts` are recomputed here with the full store-backed state (inbox email, first-seen), so a
    caller that passed a thinner state can never skip F-DOMAIN / F-DKIM (fail closed). H facts are kept. The email
    judged is the worst of `email_id` and the emails named by `evidence_ids` (_facts_for_cited_email). `tool_log`:
    the requesting agent session's tool calls (anom.session_log), so F-ANOM sees untrusted reads before the request."""
    if req.get("vendor_id", vendor["vendor_id"]) != vendor["vendor_id"]:
        raise ApiError(ErrorCode.INVALID_REQUEST, "vendor_id does not match the registry row")
    if req["new_iban"] == vendor["iban"]:
        raise ApiError(ErrorCode.INVALID_REQUEST, "new_iban is already the active IBAN")
    req, full = _facts_for_cited_email(req, vendor, store=store, settings=settings, now=now, tool_log=tool_log)
    facts = {**full, "facts": [f for f in full["facts"] if f["kind"] == "F"]
             + [f for f in facts["facts"] if f["kind"] == "H"]}
    n = store.increment("counters", {"name": "change_no"}, "value")
    change_id = f"chg_{n}"
    in_network = bool(vendor.get("in_network"))
    hard = _blocking(facts["facts"], _CREATE_EXEMPT)
    if hard:
        dst, reason = S.REJECTED, "BLOCK at create: " + " ".join(hard)
    elif in_network:
        dst, reason = S.PENDING_ATTEST, "in network: 2 of 3 distinct attestations required"
    else:
        dst, reason = S.CALLBACK_PENDING, "off network: callback to the registered phone"
    assert dst in INITIAL_STATES
    change: Change = {
        "change_id": change_id, "change_no": n, "vendor_id": vendor["vendor_id"], "vendor_ico": vendor["ico"],
        "vendor_name": vendor["name"], "old_iban": vendor["iban"], "old_since": _old_since(vendor),
        "new_iban": req["new_iban"], "state": None, "in_network": in_network, "break_glass": False,
        "change_nonce": secrets.token_hex(16), "aud": f"AG1/{settings.deployment_id}/changes/{change_id}",
        "facts": list(facts["facts"]), "attestations": [], "attest_count": 0, "not_before": None,
        "expires_at": iso(now + timedelta(seconds=settings.change_ttl_seconds)),
        "callback": {"status": "none", "code_exp": None, "attempts": 0}, "tripwire_sent_at": None,
        "signatures": [], "pending_challenge": None, "history": [], "email_id": req.get("email_id"),
        "created_at": iso(now),
    }
    _set_state(change, dst, reason=reason, actor="executor", now=now)
    portal.send_tripwire(vendor, change, store=store, settings=settings, now=now)
    change["tripwire_sent_at"] = iso(now)
    cb = None
    if dst is S.CALLBACK_PENDING:
        cb = portal.issue_callback(vendor, change, store=store, settings=settings, now=now)
        change["callback"] = {"status": "pending", "code_exp": cb["code_exp"], "attempts": 0}
    if not store.put_if_absent("changes", change, "change_id"):
        raise ApiError(ErrorCode.STATE_CONFLICT, f"{change_id} already exists")
    _event(change, ChangeEventKind.FACTS_COMPUTED, {"facts_digest": facts["facts_digest"],
                                                    "max_severity": facts["max_severity"], "block": hard},
           store=store, settings=settings)
    _event(change, ChangeEventKind.TRIPWIRE_SENT, {"to": "registered_contact"}, store=store, settings=settings)
    if cb is not None:
        _event(change, ChangeEventKind.CALLBACK_ISSUED, {"code_exp": cb["code_exp"], "channel": "simulated_sms"},
               store=store, settings=settings)
    _leaf_transition(change, None, E.CREATE, reason, actor="executor", store=store, settings=settings)
    return change


def create_decision(change: Change) -> str:
    """Change decision (CONTRACTS §2.2): "deny" when created REJECTED, else "pending" (never a challenge)."""
    return Decision.DENY.value if change["state"] == S.REJECTED.value else Decision.PENDING.value


# --------------------------------------------------------------------------- transition


def _vc_error(code: str | None) -> str:
    if code in HTTP_STATUS:
        return code  # type: ignore[return-value]
    return ErrorCode.ATTESTATION_INSUFFICIENT  # binding_mismatch, vc_revoked, ... (no own ApiError code)


def _attest_sk(n: int) -> str:
    """`attestations` sort key (CONTRACTS §3.1 `vc#<n>`), zero-padded so the natural order is submission order."""
    return f"vc#{n:06d}"


def _record_attestation(change: Change, result: dict[str, Any], vc: str, *, store: Any, settings: Any,
                        now: datetime) -> None:
    """`attestations` row with a salted commitment (commit_nonce private) + `attestation` leaf on the attest log."""
    cid = change["change_id"]
    disclosed = result.get("disclosed") or {}
    commit_nonce = secrets.token_bytes(16)
    body = {"change_id": cid, "issuer_class": result.get("issuer_class"), "iss": result.get("iss"),
            "iban": disclosed.get("iban"), "ico": disclosed.get("ico"), "vc_sha256": result.get("vc_sha256"),
            "verified": bool(result.get("ok"))}
    commitment = hashlib.sha256(canonical_json(body) + commit_nonce).hexdigest()
    row = {"change_id": cid, "issuer_class": result.get("issuer_class"), "iss": result.get("iss"),
           "vc_sha256": result.get("vc_sha256"), "kb_nonce": change["change_nonce"], "verified": bool(result.get("ok")),
           "error": result.get("error"), "commitment": commitment, "commit_nonce": commit_nonce.hex(),
           "issuer_jwt_sha256": hashlib.sha256(vc.split("~", 1)[0].encode("utf-8", "replace")).hexdigest(),
           "created_at": iso(now)}
    n = len(store.query("attestations", ("change_id", cid))) + 1
    while not store.put_if_absent("attestations", dict(row, sk=_attest_sk(n), n=n), "sk"):
        n += 1
    ports.emit(store, settings, AuditEventType.ATTESTATION.value,
               {"change_id": cid, "issuer_class": result.get("issuer_class"), "iss": result.get("iss"),
                "verified": bool(result.get("ok")), "commitment": commitment, "error": result.get("error")},
               subject_id=cid, actor="executor", log_id="attest")
    if result.get("issuer_class"):  # attest_summary.issuer_class is an enum: unpinned VCs stay in the log only
        change["attestations"].append({"issuer_class": result["issuer_class"], "iss": result.get("iss") or "",
                                       "verified": bool(result.get("ok")), "error": result.get("error"),
                                       "verified_at": iso(now)})


def _on_vc(change: Change, payload: dict[str, Any], *, expect: dict[str, Any], actor: str, store: Any,
           settings: Any, now: datetime) -> Change:
    vendor = _vendor(store, change["vendor_id"])
    pins = list(vendor.get("issuer_pins") or [])
    if not vendor.get("in_network") or not pins:
        _event(change, ChangeEventKind.VC_REJECTED, {"error": ErrorCode.BREAK_GLASS_REQUIRED}, store=store,
               settings=settings, actor=actor)
        raise ApiError(ErrorCode.BREAK_GLASS_REQUIRED, "vendor has no pinned issuers: use the callback path")
    vc = payload.get("vc")
    if not isinstance(vc, str) or not vc:
        raise ApiError(ErrorCode.INVALID_REQUEST, "vc is required")
    revoked = _revoked(settings)
    result = dict(_vc.verify_vc(vc, change, pins=pins, now=now, revoked=revoked))
    payload["attest_result"] = {  # AttestResult for the POST /changes/{id}/attestations response
        "ok": bool(result.get("ok")), "issuer_class": result.get("issuer_class"), "iss": result.get("iss"),
        "error": result.get("error"), "disclosed": dict(result.get("disclosed") or {}),
        "vc_sha256": str(result.get("vc_sha256") or "")}
    _record_attestation(change, result, vc, store=store, settings=settings, now=now)
    detail = {"issuer_class": result.get("issuer_class"), "vc_sha256": result.get("vc_sha256"),
              "error": result.get("error")}
    if not result.get("ok"):
        _event(change, ChangeEventKind.VC_REJECTED, detail, store=store, settings=settings, actor=actor)
        _persist(change, expect=expect, store=store)
        raise ApiError(_vc_error(result.get("error")), f"attestation rejected: {result.get('error')}",
                       {"vc_error": result.get("error")})
    _event(change, ChangeEventKind.VC_RECEIVED, detail, store=store, settings=settings, actor=actor)
    fs = _recompute(change, store=store, settings=settings, now=now)
    k = _distinct(_attest_results(change["change_id"], store, revoked))
    change["attest_count"] = k
    if k >= 2 and not _blocking(fs["facts"]):
        nb = now + timedelta(seconds=settings.cooling_seconds)
        change["not_before"] = iso(nb)
        _event(change, ChangeEventKind.COOLING_SCHEDULED, {"not_before": iso(nb),
                                                           "cooling_seconds": settings.cooling_seconds},
               store=store, settings=settings)
        return _commit(change, S.COOLING, E.VC_RECEIVED, reason=f"{k}/3 distinct pinned attestations",
                       actor=actor, expect=expect, store=store, settings=settings, now=now)
    _persist(change, expect=expect, store=store)  # stays PENDING_ATTEST (F-ATTEST BLOCK: no challenge, R0)
    return change


def _on_break_glass(change: Change, payload: dict[str, Any], *, expect: dict[str, Any], actor: str, store: Any,
                    settings: Any, now: datetime) -> Change:
    vendor = _vendor(store, change["vendor_id"])
    reason = str(payload.get("reason") or "")[:200]
    change["break_glass"] = True
    _event(change, ChangeEventKind.BREAK_GLASS, {"reason": reason, "declared_by": payload.get("declared_by")},
           store=store, settings=settings, actor=actor)
    cb = portal.issue_callback(vendor, change, store=store, settings=settings, now=now)
    change["callback"] = {"status": "pending", "code_exp": cb["code_exp"], "attempts": 0}
    _event(change, ChangeEventKind.CALLBACK_ISSUED, {"code_exp": cb["code_exp"], "channel": "simulated_sms"},
           store=store, settings=settings)
    _recompute(change, store=store, settings=settings, now=now)
    return _commit(change, S.CALLBACK_PENDING, E.BREAK_GLASS, reason=f"break-glass: {reason}".strip(), actor=actor,
                   expect=expect, store=store, settings=settings, now=now)


def _on_callback_confirm(change: Change, payload: dict[str, Any], *, expect: dict[str, Any], actor: str, store: Any,
                         settings: Any, now: datetime) -> Change:
    ok, attempts = portal.check_callback_code(change["vendor_ico"], change["change_id"], str(payload.get("code", "")),
                                              store=store, settings=settings, now=now)
    if not ok:
        change["callback"]["attempts"] = min(attempts, portal.MAX_ATTEMPTS)
        if attempts >= portal.MAX_ATTEMPTS:
            change["callback"]["status"] = "denied"
            _event(change, ChangeEventKind.CALLBACK_DENIED, {"reason": "attempts_exceeded", "attempts": attempts},
                   store=store, settings=settings, actor=actor)
            _commit(change, S.REJECTED, E.CALLBACK_ATTEMPTS_EXCEEDED, reason="3 failed callback attempts",
                    actor=actor, expect=expect, store=store, settings=settings, now=now)
        else:
            _persist(change, expect=expect, store=store)
        raise ApiError(ErrorCode.CALLBACK_CODE_INVALID, "wrong or expired callback code", {"attempts": attempts})
    change["callback"] = {"status": "confirmed", "code_exp": change["callback"].get("code_exp"), "attempts": attempts}
    _event(change, ChangeEventKind.CALLBACK_CONFIRMED, {"attempts": attempts}, store=store, settings=settings,
           actor=actor)
    fs = _recompute(change, store=store, settings=settings, now=now)
    if _blocking(fs["facts"]):
        _persist(change, expect=expect, store=store)
        return change
    secs = settings.break_glass_cooling_seconds if change["break_glass"] else settings.cooling_seconds
    change["not_before"] = iso(now + timedelta(seconds=secs))
    _event(change, ChangeEventKind.COOLING_SCHEDULED, {"not_before": change["not_before"], "cooling_seconds": secs},
           store=store, settings=settings)
    return _commit(change, S.COOLING, E.CALLBACK_CONFIRM, reason="callback code confirmed", actor=actor,
                   expect=expect, store=store, settings=settings, now=now)


def _on_callback_deny(change: Change, payload: dict[str, Any], *, expect: dict[str, Any], actor: str, store: Any,
                      settings: Any, now: datetime) -> Change:
    change["callback"]["status"] = "denied"
    _event(change, ChangeEventKind.CALLBACK_DENIED, {"reason": "denied_by_vendor"}, store=store, settings=settings,
           actor=actor)
    return _commit(change, S.REJECTED, E.CALLBACK_DENY, reason="vendor denied the change on callback", actor=actor,
                   expect=expect, store=store, settings=settings, now=now)


def _on_cooling_elapsed(change: Change, payload: dict[str, Any], *, expect: dict[str, Any], actor: str, store: Any,
                        settings: Any, now: datetime) -> Change:
    nb = _parse(change.get("not_before"))
    if nb is None or now < nb:
        raise ApiError(ErrorCode.COOLING_OFF, "cooling-off period not over",
                       {"retry_after_seconds": int((nb - now).total_seconds()) + 1 if nb else 0})
    raise ApiError(ErrorCode.STATE_CONFLICT, "policy set `change` does not allow the CHG challenge yet",
                   {"state": change["state"]})


def _on_expire(change: Change, payload: dict[str, Any], *, expect: dict[str, Any], actor: str, store: Any,
               settings: Any, now: datetime) -> Change:
    raise ApiError(ErrorCode.STATE_CONFLICT, "change has not expired", {"state": change["state"]})


_GUARDS = {
    E.VC_RECEIVED: _on_vc,
    E.BREAK_GLASS: _on_break_glass,
    E.CALLBACK_CONFIRM: _on_callback_confirm,
    E.CALLBACK_DENY: _on_callback_deny,
    E.COOLING_ELAPSED: _on_cooling_elapsed,
    E.EXPIRE: _on_expire,
}


def transition(change_id: str, event: ChangeEvent, *, payload: dict[str, Any] | None = None, store: Any,
               settings: Any, now: datetime, actor: str | None = None) -> Change:
    """Apply one guarded event (CONTRACTS §6.1); appends state_transition (and change_event) leaves.
    Raises ForbiddenTransition / ApiError(state_conflict | attestation_insufficient | ...).
    `actor` (optional) is the authenticated caller role; portal-only events refuse any other role. For
    TRIPWIRE_NOT_US / CLERK_REJECT_SIGNED the handler passes it as payload["actor"]. VC_RECEIVED sets
    payload["attest_result"] (AttestResult) for the response, also when the VC is rejected."""
    event = E(event)
    payload = payload if payload is not None else {}
    if actor is None and event in _PAYLOAD_ACTOR and isinstance(payload.get("actor"), str):
        actor = payload["actor"]
    if actor is not None and event in _PORTAL_ONLY and actor != "vendor_portal":
        raise ApiError(ErrorCode.CALLER_NOT_ALLOWED, f"{event.value} is vendor-portal only")
    actor = actor or _DEFAULT_ACTOR.get(event, "executor")
    change = advance(_load(store, change_id), store=store, settings=settings, now=now)
    state = S(change["state"])
    if event is E.CALLBACK_CONFIRM and state is S.REJECTED and change["callback"]["attempts"] >= portal.MAX_ATTEMPTS:
        raise ApiError(ErrorCode.CALLBACK_ATTEMPTS_EXCEEDED, "callback attempts exhausted; the change is rejected",
                       {"state": state.value})
    if event in (E.CLERK_SIGNED, E.TREASURY_SIGNED):
        raise ApiError(ErrorCode.STATE_CONFLICT, "CHG signatures are applied by on_signature()", {"state": state.value})
    dst = next_state(state, event)
    expect = _expect(change)
    guard = _GUARDS.get(event)
    if guard is not None:
        return guard(change, payload, expect=expect, actor=actor, store=store, settings=settings, now=now)
    if event is E.CLERK_REJECT_SIGNED and not payload.get("reason") and payload.get("nonce"):
        reason = f"clerk signed CHG_REJECT {payload['nonce']}"
    else:
        reason = str(payload.get("reason") or event.value.lower())[:200]
    return _commit(change, dst, event, reason=reason, actor=actor, expect=expect, store=store, settings=settings,
                   now=now)


# --------------------------------------------------------------------------- advance


def _enter_sig_clerk(change: Change, *, expect: dict[str, Any], store: Any, settings: Any,
                     now: datetime) -> Change | None:
    work: Change = copy.deepcopy(change)
    fs = _recompute(work, store=store, settings=settings, now=now)
    allowed, _rules = ports.may_issue_chg_challenge(work, fs, now)
    if not allowed:
        return None
    work["pending_challenge"] = ports.issue_chg_challenge(work, role="clerk", sig_index=1, store=store,
                                                          settings=settings, now=now)
    return _commit(work, S.SIG_CLERK, E.COOLING_ELAPSED, reason="cooling-off elapsed; clerk challenge issued",
                   actor="executor", expect=expect, store=store, settings=settings, now=now)


def advance(change: Change, *, store: Any, settings: Any, now: datetime) -> Change:
    """Lazy advance on read: EXPIRE when now >= expires_at; VC_REVOKED when an accepted VC is now revoked;
    COOLING_ELAPSED when now >= not_before (policy set `change` must allow; issues the clerk CHG challenge)."""
    if S(change["state"]) in TERMINAL_STATES:
        return change
    expect = _expect(change)
    try:
        if now >= _parse(change["expires_at"]):  # type: ignore[operator]
            return _commit(change, S.EXPIRED, E.EXPIRE, reason="change TTL elapsed", actor="executor",
                           expect=expect, store=store, settings=settings, now=now)
        revoked = _revoked(settings)
        rows = store.query("attestations", ("change_id", change["change_id"])) if revoked else []
        if any(r.get("verified") and _is_revoked(r, revoked) for r in rows):
            return _commit(change, S.REJECTED, E.VC_REVOKED, reason="an accepted attestation was revoked",
                           actor="executor", expect=expect, store=store, settings=settings, now=now)
        nb = _parse(change.get("not_before"))
        if change["state"] == S.COOLING.value and nb is not None and now >= nb:
            moved = _enter_sig_clerk(change, expect=expect, store=store, settings=settings, now=now)
            if moved is not None:
                return moved
    except ApiError as e:
        if e.code != ErrorCode.STATE_CONFLICT:
            raise
        return _load(store, change["change_id"])  # somebody else advanced it first
    return change


# --------------------------------------------------------------------------- signatures

# Policy-set `change` rule -> 403 code, most severe first (CONTRACTS §4.4).
_RECHECK_ERRORS = (("I-BLOCK", ErrorCode.rule_violation("I-BLOCK")), ("I-ATTEST", ErrorCode.ATTESTATION_INSUFFICIENT),
                   ("I-CALLBACK", ErrorCode.MISSING_CALLBACK_ATTESTATION), ("I-COOLOFF", ErrorCode.COOLING_OFF))


def _recheck(change: Change, *, store: Any, settings: Any, now: datetime) -> None:
    """R0 at every CHG step: recompute the facts and re-run policy set `change` before the treasury challenge is
    issued and before ACTIVE (a snapshot update or a revocation during cooling-off must still stop the change). The
    stored facts (the signed body) are left unchanged."""
    work: Change = copy.deepcopy(change)
    fs = _recompute(work, store=store, settings=settings, now=now)
    allowed, rules = ports.may_issue_chg_challenge(work, fs, now)
    if allowed:
        return
    code = next((c for rid, c in _RECHECK_ERRORS if rid in rules), ErrorCode.rule_violation("I-BLOCK"))
    raise ApiError(code, "policy set `change` no longer allows this change", {"rule_ids": sorted(rules)})


def _bic_for(iban: str, settings: Any) -> str | None:
    from executor import render
    from executor.facts import _util

    n = render.BANK_CODE_LEN.get(iban[:2])
    if n is None:
        return None
    try:
        codes, _sha = _util.load_json(Path(settings.data_dir) / "bank_codes.json")
    except FileNotFoundError:
        return None
    bic = ((codes.get(iban[:2]) or {}).get(iban[4:4 + n]) or {}).get("bic")
    return bic if isinstance(bic, str) and bic else None


def _activate(change: Change, *, expect: dict[str, Any], store: Any, settings: Any, now: datetime) -> Change:
    """SIG_TREASURY -> ACTIVE and the registry update in ONE store.transact (CONTRACTS §6.1)."""
    vendor = _vendor(store, change["vendor_id"])
    if vendor["iban"] != change["old_iban"]:
        raise ApiError(ErrorCode.STATE_CONFLICT, "registry IBAN changed since the request", {"state": change["state"]})
    # Full ISO timestamp, never a bare date: a mandate signed earlier the same day pinned a registry snapshot that
    # did not hold this IBAN, and a day-granular `from` would sort before its created_at (I-REGISTRY fail-open).
    at = iso(now)
    history = [dict(h) for h in vendor.get("iban_history") or []]
    for h in history:
        if h.get("iban") == vendor["iban"] and h.get("to") is None:
            h["to"] = at
    history.append({"iban": change["new_iban"], "from": at, "to": None, "change_id": change["change_id"]})
    meta = store.get("registry", {"vendor_id": META_KEY})
    version = int((meta or {}).get("registry_version", 0))
    active = [[r["vendor_id"], change["new_iban"] if r["vendor_id"] == vendor["vendor_id"] else r["iban"]]
              for r in store.scan("registry") if r["vendor_id"] != META_KEY and r.get("iban")
              and r.get("status", "ACTIVE") == "ACTIVE"]  # same pairs as policy.mandate.registry_snapshot
    registry_hash = hashlib.sha256(canonical_json(sorted(active))).hexdigest()
    reason = "dual control complete: registry updated"
    reg_set: dict[str, Any] = {"iban": change["new_iban"], "iban_history": history}
    bic = _bic_for(change["new_iban"], settings)
    if bic is not None:
        reg_set["bic"] = bic  # the old bank's BIC must not follow the new IBAN
    next_state(S(expect["state"]), E.TREASURY_SIGNED)
    src = _set_state(change, S.ACTIVE, reason=reason, actor="host", now=now)
    ops: list[Op] = [
        UpdateIf("changes", {"change_id": change["change_id"]},
                 {k: v for k, v in change.items() if k != "change_id"}, expect),
        UpdateIf("registry", {"vendor_id": vendor["vendor_id"]}, reg_set, {"iban": change["old_iban"]}),
        UpdateIf("registry", {"vendor_id": META_KEY}, {"registry_version": version + 1, "registry_hash": registry_hash},
                 {"registry_version": version} if meta else {}),
    ]
    try:
        ok = store.transact(ops, client_request_token=f"activate_{change['change_id']}")
    except TxConflict:
        ok = False
    if not ok:
        raise ApiError(ErrorCode.STATE_CONFLICT, "activation transaction failed", {"state": expect["state"]})
    _leaf_transition(change, src, E.TREASURY_SIGNED, reason, actor="host", store=store, settings=settings)
    return change


def on_signature(change: Change, *, role: str, signer_address: str, nonce: str, store: Any, settings: Any,
                 now: datetime, on_accept: Callable[[], None] | None = None) -> Change:
    """Guards for CHG signatures (§6.1): attestation_insufficient / missing_callback_attestation /
    cooling_off / sigs_insufficient / emulator_not_allowed; SIG_CLERK -> SIG_TREASURY -> ACTIVE.
    The caller (POST /signatures, §4.3) has already verified the signature, the enrolment and consumed the nonce.
    `on_accept` (the caller's accepted `signature` leaf) runs once every guard and the R0 re-check passed and before
    the state_transition leaf, so the log shows the signature before its effect (§7.5: ACTIVE needs earlier
    accepted clerk + treasury CHG signatures)."""
    change = advance(_load(store, change["change_id"]), store=store, settings=settings, now=now)
    state = S(change["state"])
    if state is S.PENDING_ATTEST:
        raise ApiError(ErrorCode.ATTESTATION_INSUFFICIENT,
                       f"{change['vendor_name']} {change['attest_count']}/3 attestations for new IBAN")
    if state is S.CALLBACK_PENDING:
        raise ApiError(ErrorCode.MISSING_CALLBACK_ATTESTATION, "callback not confirmed")
    if state is S.COOLING:
        nb = _parse(change.get("not_before"))
        wait = int((nb - now).total_seconds()) + 1 if nb and nb > now else 0
        raise ApiError(ErrorCode.COOLING_OFF, "cooling-off period not over", {"retry_after_seconds": wait})
    if state not in (S.SIG_CLERK, S.SIG_TREASURY):
        raise ApiError(ErrorCode.STATE_CONFLICT, f"change is {state.value}", {"state": state.value})
    expected_role = "clerk" if state is S.SIG_CLERK else "treasury"
    if role != expected_role:
        raise ApiError(ErrorCode.SIGS_INSUFFICIENT, f"{role} cannot sign in {state.value}")
    pending = change.get("pending_challenge") or {}
    if nonce != pending.get("nonce"):
        raise ApiError(ErrorCode.STATE_CONFLICT, "not the pending challenge", {"state": state.value})
    addr = signer_address.lower()
    expect = _expect(change)
    sig = {"role": role, "address": addr, "nonce": nonce, "signed_at": iso(now)}
    if state is S.SIG_CLERK:
        _recheck(change, store=store, settings=settings, now=now)
        if on_accept is not None:
            on_accept()
        change["signatures"].append(sig)
        change["pending_challenge"] = ports.issue_chg_challenge(change, role="treasury", sig_index=2, store=store,
                                                                settings=settings, now=now)
        return _commit(change, S.SIG_TREASURY, E.CLERK_SIGNED, reason="clerk signed 1/2", actor="host",
                       expect=expect, store=store, settings=settings, now=now)
    if any(s["address"] == addr for s in change["signatures"]):
        raise ApiError(ErrorCode.SIGS_INSUFFICIENT, "treasury address must differ from the clerk's")
    if settings.demo_profile == "prod":
        signer = store.get("enrolled_signers", {"address": addr}) or {}
        if signer.get("device") != DeviceAuthenticity.GENUINE.value:
            raise ApiError(ErrorCode.EMULATOR_NOT_ALLOWED, "prod profile requires a GENUINE treasury device")
    _recheck(change, store=store, settings=settings, now=now)
    if _vendor(store, change["vendor_id"])["iban"] != change["old_iban"]:  # before on_accept: no "accepted" leaf
        raise ApiError(ErrorCode.STATE_CONFLICT, "registry IBAN changed since the request", {"state": state.value})
    if on_accept is not None:
        on_accept()
    change["signatures"].append(sig)
    change["pending_challenge"] = None
    return _activate(change, expect=expect, store=store, settings=settings, now=now)
