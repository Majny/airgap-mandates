"""Lambda entry point + single router. Implements CONTRACTS.md §4 (all endpoints), §4.3 order, §4.4 error mapping.

dispatch() is the one entry point for Lambda (API Gateway REST v1 or HTTP v2 payloads), the local FastAPI app,
the bench and tests. Endpoints owned by other workstreams are thin delegations to their frozen interfaces.

Caller identity: on AWS the IAM principal (role) mapped by principal_from_arn(); in memory/moto the trusted
`principal` argument. principal=None (local `make dev` only) skips the caller checks; the agent principal may only
call /tools/* (local mirror of the IAM Deny, S7).

Owner: WS-A.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from executor import config, oplog
from executor.config import Settings, iso
from executor.errors import ApiError, ErrorCode
from executor.models import ChangeEvent, MandateStatus, ProposalStatus
from executor.policy import challenge as chal
from executor.policy import decide as decide_mod
from executor.policy import mandate as mandates
from executor.policy import rules
from executor.store import Store, get_store, shims


class Body(bytes):
    """Non-JSON response body with its content type."""

    content_type = "text/plain; charset=utf-8"

    def __new__(cls, data: bytes | str, content_type: str = "text/plain; charset=utf-8") -> "Body":
        obj = super().__new__(cls, data.encode() if isinstance(data, str) else data)
        obj.content_type = content_type
        return obj


@dataclass
class Context:
    settings: Settings
    store: Store


_CTX: Context | None = None


def configure(settings: Settings | None = None, store: Store | None = None) -> Context:
    """(Re)build the process-wide context (tests, app factory)."""
    global _CTX
    settings = settings or Settings.from_env()
    _CTX = Context(settings, store or get_store(settings))
    return _CTX


def get_context() -> Context:
    return _CTX or configure()


# ------------------------------------------------------------------ helpers

_SCHEMA_DIR = Path(__file__).resolve().parents[1] / "contracts" / "schemas"
_VALIDATORS: dict[str, Any] = {}


def _strict_validator():
    """Draft 2020-12 with `pattern` anchored ECMA-style: Python's `$` also matches before a trailing newline, so
    "CZ65...\\n" would pass `^...$` and dodge the "already the active IBAN" guard (red-team F3)."""
    import re

    import jsonschema

    def pattern(validator, patrn, instance, schema):
        if validator.is_type(instance, "string"):
            strict = patrn[:-1] + r"\Z" if patrn.endswith("$") and not patrn.endswith(r"\$") else patrn
            if not re.search(strict, instance):
                yield jsonschema.ValidationError(f"{instance!r} does not match {patrn!r}")

    return jsonschema.validators.extend(jsonschema.Draft202012Validator, {"pattern": pattern})


def validate(body: Any, schema_name: str) -> dict[str, Any]:
    """jsonschema validation against contracts/schemas/<schema_name>.json -> 400 invalid_request."""
    if schema_name not in _VALIDATORS:
        from referencing import Registry
        from referencing.jsonschema import DRAFT202012

        res = []
        for p in _SCHEMA_DIR.glob("*.json"):
            if p.name != "endpoints.json":
                doc = json.loads(p.read_text())
                doc.pop("$schema", None)  # else following a $ref switches back to the stock (non-strict) validator
                res.append((doc["$id"], DRAFT202012.create_resource(doc)))
        _VALIDATORS[schema_name] = _strict_validator()(
            {"$ref": f"https://airgap.local/schemas/{schema_name}.json"}, registry=Registry().with_resources(res))
    errs = sorted(_VALIDATORS[schema_name].iter_errors(body), key=lambda e: list(e.path))
    if errs:
        e = errs[0]
        raise ApiError(ErrorCode.INVALID_REQUEST, f"{'/'.join(map(str, e.path)) or 'body'}: {e.message}"[:300])
    return body


_INTERNAL_KEYS = ("gsi1pk", "gsi1sk")


def strip(item: dict[str, Any] | None) -> dict[str, Any] | None:
    return None if item is None else {k: v for k, v in item.items() if k not in _INTERNAL_KEYS}


def _now(ctx: Context) -> datetime:
    return config.now(ctx.settings)


def _not_found(what: str) -> ApiError:
    return ApiError(ErrorCode.NOT_FOUND, f"{what} not found")


def _sig_leaf(ctx: Context, row: dict[str, Any], *, sig: str, signer: str | None, accepted: bool,
              error: str | None) -> None:
    data = {"nonce": row["nonce"], "purpose": row["purpose"], "role": row["role"], "signer_address": signer,
            "text_sha256": row["text_sha256"], "sig": sig, "accepted": accepted, "error": error}
    subj = json.loads(row["subject"])
    shims.append(shims.make_event("signature", data, subject_id=row["subject_id"], actor="executor",
                                  settings=ctx.settings, policy_hash=subj.get("policy_hash"),
                                  inputs_digest=shims.digest(subj), facts_digest=subj.get("facts_digest")
                                  or shims.digest([]), hints_digest=shims.digest([])),
                 store=ctx.store, settings=ctx.settings)


# ------------------------------------------------------------------ mandates

def post_mandates(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    m, ch = mandates.create_mandate(body or {}, store=ctx.store, settings=ctx.settings)
    return 201, {"mandate": m, "challenge": ch}


def get_mandate_active(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    m = mandates.get_active_mandate(store=ctx.store, settings=ctx.settings)
    if m is None:
        raise ApiError(ErrorCode.NO_MANDATE, "no ACTIVE mandate")
    return 200, m


def get_mandate(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    m = ctx.store.get("mandates", {"mandate_id": p["mandate_id"]})
    if m is None:
        raise _not_found(f"mandate {p['mandate_id']}")
    return 200, mandates.public(m)


# ------------------------------------------------------------------ proposals

def _reg_hit(ctx: Context, payee: dict | None, mandate: dict | None) -> bool:
    """Payee inside the registry snapshot pinned by the mandate (I-REGISTRY)."""
    if payee is None or not payee.get("iban"):
        return False
    if mandate is None:
        return True
    snap = mandates.registry_snapshot(ctx.store)
    if snap["hash"] == mandate["payee_registry_hash"]:
        return True
    # registry moved since the mandate: the payee's current IBAN must have become ACTIVE strictly before the mandate
    # was created (full timestamps: a change activated later the same day is outside the pinned snapshot)
    for h in payee.get("iban_history", []):
        if h.get("iban") == payee["iban"] and h.get("to") is None:
            return h.get("change_id") is None or ("from" in h and str(h["from"]) < mandate["created_at"])
    return False


def proposal_state(ctx: Context, vendor_id: str, now: datetime, *, exclude: str | None = None) -> dict[str, Any]:
    """decide() state: {mandate, payee, proposals, history, now, reg_hit}; all JSON-able."""
    st = ctx.store
    payee = st.get("registry", {"vendor_id": vendor_id})
    mandate = mandates.get_active_mandate(store=st, settings=ctx.settings)
    props = [strip(x) for x in st.query("proposals", ("gsi1pk", f"vendor#{vendor_id}"), index="gsi1")
             if x["proposal_id"] != exclude]
    props = [{k: x[k] for k in ("proposal_id", "status", "invoice")} for x in props]
    history = [{k: x[k] for k in ("tx_id", "vendor_id", "amount_minor", "executed_at")}
               for x in st.query("ledger", ("vendor_id", vendor_id), index="by_vendor")]
    return {"mandate": mandate, "payee": payee, "proposals": props, "history": history, "now": iso(now),
            "reg_hit": _reg_hit(ctx, payee, mandate)}


def _session_log(ctx: Context, body: dict, action: str, now: datetime) -> list | None:
    """FACTS-2: the agent session's own tool-call log (+ the in-flight action) for F-ANOM, when the tools λ forwarded
    session_id/step; None otherwise (F-ANOM then scores an empty log)."""
    if not body.get("session_id"):
        return None
    from executor.facts import anom

    return anom.session_log(body["session_id"], store=ctx.store, action=action, step=body.get("step"), now=now)


def _evaluate(ctx: Context, pid: str, invoice: dict, hints: list, now: datetime, *, exclude: str | None = None,
              tool_log: list | None = None):
    state = proposal_state(ctx, invoice["vendor_id"], now, exclude=exclude)
    subject = {"proposal_id": pid, "invoice": invoice}
    extra: dict[str, Any] = {}
    if invoice.get("email_id"):
        from executor.facts import inbox

        extra = inbox.email_state(invoice["email_id"], store=ctx.store, settings=ctx.settings)
    facts = shims.compute_facts({"kind": "proposal", "subject_id": pid, "proposal_id": pid, "invoice": invoice,
                                 "hints": hints, "email_id": invoice.get("email_id")},
                                {**state, **extra, "snapshots": None, "tool_log": tool_log, "change": None,
                                 "data_dir": ctx.settings.data_dir}, now)
    policy = rules.policy_material()
    dec = decide_mod.decide(subject, facts, state, policy)
    digests = {"policy_hash": dec["policy_hash"],
               "inputs_digest": decide_mod.inputs_digest(subject, facts, state),
               "facts_digest": facts["facts_digest"], "hints_digest": shims.digest(hints)}
    return state, subject, facts, dec, digests


def _log(ctx: Context, etype: str, data: dict, subject_id: str, digests: dict, actor: str = "executor") -> int:
    return shims.append(shims.make_event(etype, data, subject_id=subject_id, actor=actor, settings=ctx.settings,
                                         **digests), store=ctx.store, settings=ctx.settings)


def _pay_params(proposal: dict, payee: dict, facts: dict) -> dict[str, Any]:
    inv = proposal["invoice"]
    return {"proposal_no": proposal["proposal_no"], "payee_name": payee["name"], "iban": payee["iban"],
            "amount_minor": inv["amount_minor"], "currency": inv["currency"], "vs": inv.get("vs"),
            "facts": [f for f in facts["facts"] if f["kind"] == "F"], "sig_index": 1, "sig_total": 1}


def _submit_rail(ctx: Context, tx: dict) -> dict:
    """Rail call only after commit (§3.2). A rail failure never undoes the execution; recovery re-submits."""
    from executor.rail import submit

    try:
        r = submit.submit(tx, store=ctx.store, settings=ctx.settings)
        return {**tx, "rail": {"status": r["status"] if r["status"] != "DUPL" else tx["rail"]["status"],
                               "xml_c14n_sha256": r["xml_c14n_sha256"]}}
    except Exception as e:  # noqa: BLE001 - committed; recover_unsubmitted() picks it up
        oplog.rail_failed(e, tx)
        return tx


def post_proposals(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    body = validate(body, "proposal_create.request")
    inv, hints = body["invoice"], body.get("hints", [])
    st, now = ctx.store, _now(ctx)
    payee = st.get("registry", {"vendor_id": inv["vendor_id"]})
    if payee is None:
        raise _not_found(f"vendor {inv['vendor_id']}")
    no = st.increment("counters", {"name": "proposal_no"}, "value")
    pid = f"prp_{no}"
    state, subject, facts, dec, dg = _evaluate(ctx, pid, inv, hints, now,
                                               tool_log=_session_log(ctx, body, "payment.propose", now))
    _log(ctx, "proposal", {"proposal_id": pid, "invoice": inv, "hints": hints}, pid, dg, actor="tools")
    _log(ctx, "facts", {"subject_id": pid, "facts": facts["facts"], "snapshots": facts["snapshots"]}, pid, dg)
    _log(ctx, "decision", {"subject_id": pid, "decision": dec["decision"], "rule_ids": dec["rule_ids"],
                           "mandate_id": dec["mandate_id"],
                           "inputs": decide_mod.decide_inputs(subject, facts, state)}, pid, dg)
    row: dict[str, Any] = {"proposal_id": pid, "proposal_no": no, "vendor_id": inv["vendor_id"], "invoice": inv,
                           "hints": hints, "facts": facts["facts"], "decision": dict(dec), "challenge_nonce": None,
                           "tx_id": None, "created_at": iso(now), "gsi1pk": f"vendor#{inv['vendor_id']}",
                           "gsi1sk": iso(now)}
    tx = None
    if dec["decision"] == "allow":
        from executor.bank import ledger

        m = state["mandate"]
        tx = ledger.execute({"proposal_id": pid, "vendor_id": inv["vendor_id"], "invoice": inv,
                             "iban": payee["iban"], "creditor_name": payee["name"]},
                            {"kind": "mandate", "mandate_id": m["mandate_id"]}, store=st, settings=ctx.settings,
                            mandate=m, leaf_extra=dg, proposal_set={k: v for k, v in row.items() if k != "tx_id"
                                                                    and k != "proposal_id"})
        row.update(status=ProposalStatus.EXECUTED.value, tx_id=tx["tx_id"])
        tx = _submit_rail(ctx, tx)
    elif dec["decision"] == "deny":
        row["status"] = ProposalStatus.DENIED.value
        st.put("proposals", row)
    else:
        ch = chal.issue_challenge(purpose="PAY", role="clerk", subject_id=pid,
                                  params=_pay_params(row, payee, facts), facts_digest=facts["facts_digest"],
                                  policy_hash=dec["policy_hash"], hints_digest=dg["hints_digest"],
                                  inputs_digest=dg["inputs_digest"], store=st, settings=ctx.settings, now=now)
        row["decision"]["challenge"] = ch
        row.update(status=ProposalStatus.PENDING_SIG.value, challenge_nonce=ch["nonce"])
        st.put("proposals", row)
    out = strip(row)
    return 201, {"proposal": out, "decision": out["decision"], "tx": tx}


def get_proposals(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    if q.get("vendor_id"):
        rows = ctx.store.query("proposals", ("gsi1pk", f"vendor#{q['vendor_id']}"), index="gsi1", reverse=True)
    else:
        rows = sorted(ctx.store.scan("proposals"), key=lambda r: r["proposal_no"], reverse=True)
    if q.get("status"):
        rows = [r for r in rows if r["status"] == q["status"]]
    if q.get("limit"):
        rows = rows[: int(q["limit"])]
    return 200, {"proposals": [strip(r) for r in rows]}


def get_proposal(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    r = ctx.store.get("proposals", {"proposal_id": p["proposal_id"]})
    if r is None:
        raise _not_found(f"proposal {p['proposal_id']}")
    return 200, strip(r)


# ------------------------------------------------------------------ changes (FSM owned by WS-D)

def _machine():
    from executor.change import machine

    return machine


def _change_or_404(ctx: Context, cid: str) -> dict:
    c = ctx.store.get("changes", {"change_id": cid})
    if c is None:
        raise _not_found(f"change {cid}")
    return c


def _change_out(c: dict) -> dict:
    return {k: v for k, v in c.items() if k not in _INTERNAL_KEYS + ("change_nonce_secret",)}


def post_changes(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    body = validate(body, "change_create.request")
    st, now = ctx.store, _now(ctx)
    vendor = st.get("registry", {"vendor_id": body["vendor_id"]})
    if vendor is None:
        raise _not_found(f"vendor {body['vendor_id']}")
    tool_log = _session_log(ctx, body, "payee.request_change", now)
    req = {k: v for k, v in body.items() if k not in ("session_id", "step")}
    facts = shims.compute_facts({"kind": "change", **req}, {"payee": vendor, "mandate": None, "history": [],
                                                            "snapshots": None, "tool_log": tool_log, "change": None,
                                                            "data_dir": ctx.settings.data_dir}, now)
    import inspect

    machine = _machine()
    kw = {"tool_log": tool_log} if "tool_log" in inspect.signature(machine.create).parameters else {}
    c = machine.create(req, facts, vendor, store=st, settings=ctx.settings, now=now, **kw)
    c = _change_out(c)
    cf = c.get("facts") or facts["facts"]  # the FSM's own FactSet is authoritative for the change
    f_only = [f for f in cf if f["kind"] == "F"]
    rule_ids = sorted({f["id"] for f in f_only if f["severity"] == "BLOCK" and f["id"] not in ("F-ATTEST", "F-CALLBACK")})
    dec = {"decision": "deny" if c["state"] == "REJECTED" else "pending", "rule_ids": rule_ids,
           "facts": cf, "facts_digest": shims.digest(f_only), "mandate_id": None,
           "policy_hash": rules.policy_hash()}
    return 201, {"change": c, "decision": dec}


def get_changes(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    m, now = _machine(), _now(ctx)
    rows = sorted(ctx.store.scan("changes"), key=lambda r: r["change_no"], reverse=True)
    return 200, {"changes": [_change_out(m.advance(c, store=ctx.store, settings=ctx.settings, now=now))
                             for c in rows]}


def get_change(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    c = _change_or_404(ctx, p["change_id"])
    return 200, _change_out(_machine().advance(c, store=ctx.store, settings=ctx.settings, now=_now(ctx)))


REJECT_LIMIT, REJECT_WINDOW_S = 5, 600


def post_change_reject(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    body = validate(body or {}, "change_reject.request")
    st, now, cid = ctx.store, _now(ctx), p["change_id"]
    c = _machine().advance(_change_or_404(ctx, cid), store=st, settings=ctx.settings, now=now)  # lazy EXPIRE first
    window = int(now.timestamp()) // REJECT_WINDOW_S
    if st.increment("counters", {"name": f"reject#{cid}#{window}"}, "value") > REJECT_LIMIT:
        raise ApiError(ErrorCode.RATE_LIMITED, "too many reject requests", {"retry_after_seconds": REJECT_WINDOW_S})
    if c["state"] in ("ACTIVE", "REJECTED", "EXPIRED"):
        raise ApiError(ErrorCode.STATE_CONFLICT, f"change is {c['state']}", {"state": c["state"]})
    if principal == "vendor_portal":
        c = _machine().transition(cid, ChangeEvent.TRIPWIRE_NOT_US, payload={"reason": body["reason"],
                                                                           "actor": "vendor_portal"},
                                  store=st, settings=ctx.settings, now=now)
        return 200, {"change": _change_out(c)}
    if principal not in (None, "host"):
        raise ApiError(ErrorCode.CALLER_NOT_ALLOWED, "reject is host (signed) or vendor portal only")
    ch = chal.issue_challenge(purpose="CHG_REJECT", role="clerk", subject_id=cid,
                              params={"change_no": c["change_no"], "vendor_name": c["vendor_name"],
                                      "vendor_ico": c["vendor_ico"], "new_iban": c["new_iban"]},
                              facts_digest=None, store=st, settings=ctx.settings, now=now)
    st.update_if("nonces", {"nonce": ch["nonce"]}, {"reject_reason": body["reason"]}, {"used": False})
    return 200, {"change": _change_out(c), "challenge": ch}


def post_callback(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    body = validate(body, "callback_submit.request")
    _change_or_404(ctx, p["change_id"])
    ev = ChangeEvent.CALLBACK_CONFIRM if body["outcome"] == "confirm" else ChangeEvent.CALLBACK_DENY
    c = _machine().transition(p["change_id"], ev, payload=body, store=ctx.store, settings=ctx.settings,
                              now=_now(ctx))
    return 200, _change_out(c)


def post_vc(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    body = validate(body, "vc_submit.request")
    _change_or_404(ctx, p["change_id"])
    payload = dict(body)  # WS-D sets payload["attest_result"] (AttestResult) for the response
    c = _machine().transition(p["change_id"], ChangeEvent.VC_RECEIVED, payload=payload, store=ctx.store,
                              settings=ctx.settings, now=_now(ctx), actor=principal or "issuer")
    return 200, {"change": _change_out(c), "attest": payload.get("attest_result")}


def post_break_glass(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    body = validate(body, "break_glass.request")
    _change_or_404(ctx, p["change_id"])
    c = _machine().transition(p["change_id"], ChangeEvent.BREAK_GLASS, payload=body, store=ctx.store,
                              settings=ctx.settings, now=_now(ctx), actor=principal or "vendor_portal")
    return 200, _change_out(c)


# ------------------------------------------------------------------ attestations (hardware issuer profile, stretch)

def post_attestations(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    from executor.attest import attestation

    body = validate(body, "attestation_create.request")
    if "propose" in body:
        att, challenges = attestation.propose(body["propose"], store=ctx.store, settings=ctx.settings)
    else:
        att, challenges = attestation.revoke(body["revoke"]["ico"], body["revoke"]["revokes_v"],
                                             store=ctx.store, settings=ctx.settings), []
    return 201, {"attestation": att, "challenges": challenges}


def get_attestations(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    rows = ctx.store.query("vendor_policies", ("ico", p["ico"]))
    if not rows:
        raise _not_found(f"attestations for {p['ico']}")
    return 200, {"ico": p["ico"], "attestations": rows}


# ------------------------------------------------------------------ challenges + signatures (§4.3)

def get_challenge(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    row = chal.load(p["nonce"], store=ctx.store)
    if row is None:
        raise _not_found(f"challenge {p['nonce']}")
    return 200, chal.challenge_ref(row, full=True)


def _enrolled(ctx: Context, address: str, role: str) -> dict | None:
    """Active row for the role whose enroll_seq points at its own enroll leaf ("enrolled before used", online)."""
    from executor.store import signers

    return signers.enrolled(ctx.store, address, role)


def post_signatures(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    body = validate(body, "signature_submit.request")
    st, settings, now = ctx.store, ctx.settings, _now(ctx)
    sig = body["sig"]
    # 1. load
    row = chal.load(body["nonce"], store=st)
    if row is None:
        raise _not_found(f"challenge {body['nonce']}")
    # 2. role
    if body["role"] != row["role"]:
        raise ApiError(ErrorCode.UNKNOWN_SIGNER, "role does not match the challenge")
    # 3. re-render from stored template/params/profile
    text, sh = chal.rerender(row)
    if text != row["text"] or sh != row["subject_hash"]:
        raise ApiError(ErrorCode.INTERNAL_ERROR, "stored challenge does not re-render (fail closed)")

    def reject(code: str, msg: str, signer: str | None = None, details: dict | None = None) -> ApiError:
        _sig_leaf(ctx, row, sig=sig, signer=signer, accepted=False, error=code)
        return ApiError(code, msg, details)

    # 4. displayed_text (diagnostic, nonce not consumed)
    if body.get("displayed_text") is not None and body["displayed_text"] != text:
        raise reject(ErrorCode.RENDER_MISMATCH, "displayed text differs from executor render",
                     details={"expected_sha256": row["text_sha256"]})
    # 5. recover
    try:
        signer = shims.verify_eip191(text, sig)
    except ValueError:
        raise reject(ErrorCode.BAD_SIGNATURE, "signature recovery failed") from None
    # 6. enrolled for role
    purpose = row["purpose"]
    if purpose == "VENDOR_ATTEST":
        enrolled = {"device": "GENUINE"}  # vendor_policies check is done by WS-D attestation.on_signature
    else:
        enrolled = _enrolled(ctx, signer, row["role"])
        if enrolled is None:
            raise reject(ErrorCode.UNKNOWN_SIGNER, f"{signer} is not enrolled as {row['role']}", signer)
    # 6b. distinct second signer, GENUINE treasury in prod
    if row["role"] == "treasury":
        first: list[str] = []
        if purpose == "MANDATE":
            m = st.get("mandates", {"mandate_id": row["subject_id"]}) or {}
            first = [s["address"] for s in m.get("signers", [])]
        elif purpose == "CHG":
            c = st.get("changes", {"change_id": row["subject_id"]}) or {}
            first = [s["address"] for s in c.get("signatures", [])]
        if not first or signer in first:
            raise reject(ErrorCode.SIGS_INSUFFICIENT, "treasury must follow a different clerk key", signer)
        if settings.demo_profile == "prod" and enrolled.get("device") != "GENUINE":
            raise reject(ErrorCode.EMULATOR_NOT_ALLOWED, "prod profile refuses EMULATOR treasury keys", signer)
    # 7. expiry
    if now >= datetime.fromisoformat(row["exp"].replace("Z", "+00:00")):
        raise reject(ErrorCode.EXPIRED, f"challenge {row['nonce']} expired", signer)
    # 8. consume (conditional)
    if not st.update_if("nonces", {"nonce": row["nonce"]}, {"used": True, "used_at": iso(now), "used_by": signer},
                        {"used": False}):
        raise reject(ErrorCode.NONCE_REUSED, f"challenge {row['nonce']} already used", signer)
    # 9-10. purpose guards + effect
    try:
        out = _apply_signature(ctx, row, signer, sig, now)
    except ApiError as e:
        _sig_leaf(ctx, row, sig=sig, signer=signer, accepted=False, error=e.code)
        st.update_if("nonces", {"nonce": row["nonce"]}, {"result": e.code}, {"used": True})
        raise
    st.update_if("nonces", {"nonce": row["nonce"]}, {"result": out["effect"]["type"]}, {"used": True})
    return 200, {"nonce": row["nonce"], "purpose": purpose, "subject_id": row["subject_id"],
                 "signer_address": signer, **out}


def _apply_signature(ctx: Context, row: dict, signer: str, sig: str, now: datetime) -> dict[str, Any]:
    st, settings, purpose = ctx.store, ctx.settings, row["purpose"]
    sig_leaf = lambda: _sig_leaf(ctx, row, sig=sig, signer=signer, accepted=True, error=None)  # noqa: E731
    if purpose == "MANDATE":
        m, nxt = mandates.on_mandate_signature(row["subject_id"], row["role"], signer, row["nonce"], store=st,
                                               settings=settings)
        sig_leaf()
        eff = "mandate_activated" if m["status"] == MandateStatus.ACTIVE.value else "mandate_signed"
        out: dict[str, Any] = {"effect": {"type": eff, "state": m["status"]}, "mandate": m}
        if nxt:
            out["challenge"] = nxt
        return out
    if purpose == "PAY":
        return _apply_pay(ctx, row, signer, now, sig_leaf)
    if purpose == "CHG":
        c = _change_or_404(ctx, row["subject_id"])
        # the accepted signature leaf must precede the state_transition leaf it causes (verify_audit ordering)
        c = _machine().on_signature(c, role=row["role"], signer_address=signer, nonce=row["nonce"], store=st,
                                    settings=settings, now=now, on_accept=sig_leaf)
        out = {"effect": {"type": "change_advanced", "state": c["state"]}, "change": _change_out(c)}
        if c.get("pending_challenge") and c["state"] == "SIG_TREASURY":
            out["challenge"] = c["pending_challenge"]
        return out
    if purpose == "CHG_REJECT":
        c = _machine().transition(row["subject_id"], ChangeEvent.CLERK_REJECT_SIGNED,
                                  payload={"actor": "host", "signer_address": signer, "nonce": row["nonce"],
                                           "reason": row.get("reject_reason", "")},
                                  store=st, settings=settings, now=now)
        sig_leaf()
        return {"effect": {"type": "change_rejected", "state": c["state"]}, "change": _change_out(c)}
    if purpose == "VENDOR_ATTEST":
        from executor.attest import attestation

        ico, v = row["subject_id"].split("#", 1) if "#" in row["subject_id"] else (row["subject_id"], "0")
        att = attestation.on_signature(ico, int(v), row["role"], signer, "", row["nonce"], store=st,
                                       settings=settings)
        sig_leaf()
        eff = "attestation_published" if att.get("status") == "PUBLISHED" else "attestation_signed"
        return {"effect": {"type": eff, "state": att.get("status")}, "attestation": att}
    raise ApiError(ErrorCode.STATE_CONFLICT, f"{purpose} signatures are handled by tools/enroll.py")


def _apply_pay(ctx: Context, row: dict, signer: str, now: datetime, sig_leaf: Callable[[], None]) -> dict:
    from executor.bank import ledger

    st, pid = ctx.store, row["subject_id"]
    prop = st.get("proposals", {"proposal_id": pid})
    if prop is None or prop["status"] != ProposalStatus.PENDING_SIG.value or prop["challenge_nonce"] != row["nonce"]:
        raise ApiError(ErrorCode.STATE_CONFLICT, "proposal is not awaiting this signature")
    inv = prop["invoice"]
    payee = st.get("registry", {"vendor_id": inv["vendor_id"]})
    signed = json.loads(row["params"])
    # the payee IBAN the human saw must still be the registry IBAN
    if payee is None or payee.get("iban") != signed["iban"]:
        raise ApiError(ErrorCode.rule_violation("I-PAYEE"), "payee IBAN changed since the challenge")
    # 9. re-run decide(): hard rules must still pass
    state, subject, facts, dec, dg = _evaluate(ctx, pid, inv, prop["hints"], now, exclude=pid)
    _log(ctx, "decision", {"subject_id": pid, "decision": dec["decision"], "rule_ids": dec["rule_ids"],
                           "mandate_id": dec["mandate_id"], "recheck": True,
                           "inputs": decide_mod.decide_inputs(subject, facts, state)}, pid, dg)
    if dec["decision"] == "deny":
        st.update_if("proposals", {"proposal_id": pid}, {"status": ProposalStatus.REJECTED.value},
                     {"status": ProposalStatus.PENDING_SIG.value})
        raise ApiError(ErrorCode.rule_violation((dec["rule_ids"] or ["I-BLOCK"])[0]),
                       f"step-up re-check denied: {', '.join(dec['rule_ids'])}")
    sig_leaf()
    tx = ledger.execute({"proposal_id": pid, "vendor_id": inv["vendor_id"], "invoice": inv, "iban": payee["iban"],
                         "creditor_name": payee["name"]},
                        {"kind": "stepup", "nonce": row["nonce"], "signer_address": signer}, store=st,
                        settings=ctx.settings, mandate=None, leaf_extra=dg)
    tx = _submit_rail(ctx, tx)
    prop = strip(st.get("proposals", {"proposal_id": pid}))
    return {"effect": {"type": "payment_executed", "tx_id": tx["tx_id"]}, "proposal": prop, "tx": tx}


# ------------------------------------------------------------------ ledger, vendors, rail export

_VENDOR_KEYS = ("vendor_id", "ico", "name", "domain", "iban", "bic", "country", "phone", "contact_email",
                "registered_since", "in_network", "issuer_pins", "iban_history", "updated_at")


def _vendor_out(v: dict) -> dict:
    return {k: v[k] for k in _VENDOR_KEYS if k in v}


def get_vendors(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    rows = [r for r in ctx.store.scan("registry") if r["vendor_id"] != mandates.REGISTRY_META["vendor_id"]]
    return 200, {"vendors": [_vendor_out(r) for r in sorted(rows, key=lambda r: r["vendor_id"])]}


def get_vendor(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    v = ctx.store.get("registry", {"vendor_id": p["vendor_id"]})
    if v is None or p["vendor_id"] == mandates.REGISTRY_META["vendor_id"]:
        raise _not_found(f"vendor {p['vendor_id']}")
    return 200, _vendor_out(v)


def get_ledger(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    if q.get("vendor_id"):
        rows = ctx.store.query("ledger", ("vendor_id", q["vendor_id"]), index="by_vendor")
    else:
        rows = sorted(ctx.store.scan("ledger"), key=lambda r: r["executed_at"])
    return 200, {"txs": rows}


def get_pain001(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    from executor.rail import submit

    return 200, submit.pain001_export(p["tx_id"], store=ctx.store, settings=ctx.settings)


# ------------------------------------------------------------------ audit, receipts, checkpoint, witness (WS-B)

def get_audit_export(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    from executor.audit import log

    return 200, log.export(q.get("log_id", "audit"), int(q.get("from_seq", 0)), redact=q.get("redact") == "1",
                           store=ctx.store, settings=ctx.settings)


def get_receipt(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    from executor.audit import receipt

    if ctx.store.get("ledger", {"tx_id": p["tx_id"]}) is None:
        raise _not_found(f"tx {p['tx_id']}")
    return 200, receipt.receipt(p["tx_id"], store=ctx.store, settings=ctx.settings)


def get_checkpoint(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    rows = ctx.store.query("checkpoints", ("log_id", q.get("log_id", "audit")), reverse=True, limit=1)
    if not rows:
        raise _not_found("checkpoint")
    return 200, Body(rows[0]["note"])


def post_cosignature(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    """Row 22b: the W2 relay uploads W2's cosignature line(s); WS-B verifies against AIRGAP_W2_VKEY and appends."""
    from executor.audit import checkpoint

    try:
        size = int(q.get("size", ""))
    except ValueError:
        raise ApiError(ErrorCode.INVALID_REQUEST, "size must be an integer") from None
    raw = body if isinstance(body, (bytes, str)) else b""
    fn = getattr(checkpoint, "add_cosignature", None)
    if fn is None:
        raise NotImplementedError("checkpoint.add_cosignature (WS-B)")
    status, ctype, out = fn(q.get("log_id", "audit"), size, raw.encode() if isinstance(raw, str) else raw,
                            store=ctx.store, settings=ctx.settings)
    return status, Body(out, ctype)


def post_witness(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    from witness import witness

    raw = body if isinstance(body, (bytes, str)) else b""
    status, ctype, out = witness.add_checkpoint(raw.encode() if isinstance(raw, str) else raw, store=ctx.store,
                                                settings=ctx.settings)
    return status, Body(out, ctype)


# ------------------------------------------------------------------ tools, egress (WS-E), inbox

def _log_bad_tool_request(ctx: Context, name: str, body: Any) -> None:
    """A malformed tool call is still an agent action: log a tool_call leaf (result error, T-BAD-REQUEST) so an
    escalation attempt with a bad body is visible in the audit log. Leaf only: no tool_calls row (its key is the
    step, which is not trustworthy here). Values are coerced so the leaf stays canonical (no floats)."""
    b = body if isinstance(body, dict) else {}
    sid = b.get("session_id") if isinstance(b.get("session_id"), str) else None
    step = b.get("step")
    step = step if isinstance(step, int) and not isinstance(step, bool) else None
    raw = json.dumps(b.get("args"), sort_keys=True, default=repr).encode() if b else repr(body).encode()
    data = {"session_id": sid[:128] if sid else None, "step": step, "tool": name[:64],
            "args_sha256": hashlib.sha256(raw).hexdigest(), "result": "error", "rule_ids": ["T-BAD-REQUEST"],
            "untrusted_read": False}
    shims.append(shims.make_event("tool_call", data, subject_id=data["session_id"], actor="tools",
                                  settings=ctx.settings), store=ctx.store, settings=ctx.settings)


def post_tool(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    from executor.tools import handler as tools

    try:
        body = validate(body, "tool_call.request")
    except ApiError:
        _log_bad_tool_request(ctx, p["name"], body)
        raise
    return 200, tools.call_tool(p["name"], body, store=ctx.store, settings=ctx.settings)


def post_egress(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    from executor.egress import gateway

    body = validate(body, "egress.request")
    return 200, gateway.handle_egress(body, store=ctx.store, settings=ctx.settings)


def post_ingest(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    from executor.facts import dkim

    body = validate(body, "ingest.request")
    fn = getattr(dkim, "ingest", None)
    if fn is None:
        raise NotImplementedError("ingest (WS-D)")
    return 201, fn(body, store=ctx.store, settings=ctx.settings)


def get_inbox(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    rows = sorted(ctx.store.scan("inbox"), key=lambda r: r["received_at"], reverse=True)
    keys = ("email_id", "from_addr", "from_domain", "subject", "received_at")
    return 200, {"emails": [{k: r[k] for k in keys} for r in rows]}


def get_inbox_raw(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    r = ctx.store.get("inbox", {"email_id": p["email_id"]})
    if r is None:
        raise _not_found(f"email {p['email_id']}")
    if r.get("raw_b64"):  # memory/moto: ingest may keep the raw message inline
        return 200, Body(base64.b64decode(r["raw_b64"]), "message/rfc822")
    import boto3

    obj = boto3.client("s3", region_name=ctx.settings.aws_region).get_object(
        Bucket=ctx.settings.inbox_bucket, Key=r["s3_key"])
    return 200, Body(obj["Body"].read(), "message/rfc822")


# ------------------------------------------------------------------ health

def code_sha256() -> str:
    """Code identity in the checkpoint `code` line and /health (WS-B owns the derivation)."""
    from executor.audit import checkpoint

    return checkpoint.code_sha256()


def get_health(ctx: Context, p: dict, q: dict, body: Any, principal: str | None):
    import os

    s = ctx.settings
    try:
        from executor.audit import checkpoint, kms

        key_id = checkpoint.key_id(config.log_origin(s), kms.public_key(settings=s)).hex()
        vk = checkpoint.vkeys(s)
    except Exception:  # noqa: BLE001 - log key not configured
        key_id, vk = "", {}
    return 200, {"status": "ok", "backend": s.backend, "deployment": s.deployment_id, "demo_profile": s.demo_profile,
                 "policy_hash": rules.policy_hash(), "render_profile": s.render_profile,
                 "code_sha256": code_sha256(), "log_origin": config.log_origin(s), "log_pubkey_id": key_id,
                 "log_vkey": vk.get("log"), "w1_vkey": vk.get("w1"), "w2_vkey": os.environ.get("AIRGAP_W2_VKEY"),
                 "git_rev": os.environ.get("AIRGAP_GIT_REV") or None}


# ------------------------------------------------------------------ routing

ANY = None
Handler = Callable[[Context, dict, dict, Any, "str | None"], tuple[int, Any]]
ROUTES: list[tuple[str, re.Pattern[str], Handler, frozenset[str] | None]] = []


def _route(method: str, pattern: str, fn: Handler, callers: set[str] | None = ANY) -> None:
    rx = re.compile("^" + re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", pattern) + "$")
    ROUTES.append((method, rx, fn, frozenset(callers) if callers else None))


_route("POST", "/mandates", post_mandates, {"host"})
_route("GET", "/mandates/active", get_mandate_active)
_route("GET", "/mandates/{mandate_id}", get_mandate)
_route("POST", "/proposals", post_proposals, {"tools"})
_route("GET", "/proposals", get_proposals)
_route("GET", "/proposals/{proposal_id}", get_proposal)
_route("POST", "/changes", post_changes, {"tools"})
_route("GET", "/changes", get_changes)
_route("GET", "/changes/{change_id}", get_change)
_route("POST", "/changes/{change_id}/reject", post_change_reject, {"host", "vendor_portal"})
_route("GET", "/challenges/{nonce}", get_challenge, {"host", "vendor_portal"})
_route("POST", "/signatures", post_signatures, {"host", "vendor_portal"})
_route("POST", "/callbacks/{change_id}", post_callback, {"vendor_portal"})
_route("POST", "/changes/{change_id}/attestations", post_vc, {"issuer", "vendor_portal"})
_route("POST", "/changes/{change_id}/break-glass", post_break_glass, {"vendor_portal"})
_route("POST", "/attestations", post_attestations, {"vendor_portal"})
_route("GET", "/attestations/{ico}", get_attestations)
_route("POST", "/egress", post_egress, {"tools"})
_route("POST", "/tools/{name}", post_tool, {"agent", "tools"})
_route("GET", "/audit/export", get_audit_export, {"auditor", "host"})
_route("GET", "/receipts/{tx_id}", get_receipt)
_route("GET", "/checkpoint", get_checkpoint)
_route("POST", "/checkpoint/cosignature", post_cosignature, {"relay"})
_route("POST", "/witness/add-checkpoint", post_witness, {"checkpointer"})
_route("GET", "/export/pain001/{tx_id}", get_pain001, {"auditor", "host"})
_route("GET", "/vendors", get_vendors)
_route("GET", "/vendors/{vendor_id}", get_vendor)
_route("GET", "/ledger", get_ledger)
_route("POST", "/ingest", post_ingest, {"ingest"})
_route("GET", "/inbox", get_inbox, {"tools", "host"})
_route("GET", "/inbox/{email_id}/raw", get_inbox_raw, {"tools", "host"})
_route("GET", "/health", get_health)


def dispatch(method: str, path: str, query: dict[str, str] | None = None, body: dict[str, Any] | None = None,
             headers: dict[str, str] | None = None, *, principal: str | None = None,
             ctx: Context | None = None) -> tuple[int, dict[str, Any] | bytes]:
    """Route a request to the endpoint implementation; ApiError -> (status, error body). Used by Lambda, FastAPI app, bench and tests.
    Every request runs in an executor.oplog scope: refusals and failures get one explained ops-log line, a 500 its
    traceback and an error_id (also in the response `details`)."""
    try:
        scope = (ctx or get_context()).store
    except Exception:  # noqa: BLE001 - _dispatch reports a missing context itself
        scope = None
    token = oplog.begin(method, path, principal, scope)
    status: int = 500
    out: Any = None
    try:
        status, out = _dispatch(method, path, query, body, principal=principal, ctx=ctx)
        return status, out
    finally:
        oplog.end(token, status, out)


def _internal(e: BaseException, message: str, method: str, path: str, principal: str | None) -> dict[str, Any]:
    """500 body with the error_id under which the traceback was logged (schema common.json#/$defs/error details)."""
    return ApiError(ErrorCode.INTERNAL_ERROR, message,
                    {"error_id": oplog.internal_error(e, method, path, principal)}).to_body()


def _dispatch(method: str, path: str, query: dict[str, str] | None, body: dict[str, Any] | None, *,
              principal: str | None, ctx: Context | None) -> tuple[int, dict[str, Any] | bytes]:
    ctx = ctx or get_context()
    method = method.upper()
    if "?" in path:  # in-process callers may pass "/ledger?vendor_id=..." like an HTTP client would
        from urllib.parse import parse_qsl

        path, qs = path.split("?", 1)
        query = {**dict(parse_qsl(qs)), **(query or {})}
    path = "/" + path.strip("/") if path != "/" else path
    matched_path = False
    for m, rx, fn, callers in ROUTES:
        mt = rx.match(path)
        if not mt:
            continue
        matched_path = True
        if m != method:
            continue
        try:
            if principal == "agent" and not path.startswith("/tools/"):
                raise ApiError(ErrorCode.CALLER_NOT_ALLOWED, "the agent role may only call /tools/*")
            if principal is not None and callers is not None and principal not in callers:
                raise ApiError(ErrorCode.CALLER_NOT_ALLOWED, f"{principal} may not call {method} {path}")
            return fn(ctx, mt.groupdict(), dict(query or {}), body, principal)
        except ApiError as e:
            return e.status, e.to_body()
        except NotImplementedError as e:
            return 500, _internal(e, f"not implemented yet: {e}", method, path, principal)
        except Exception as e:  # noqa: BLE001 - fail closed, no effect beyond what committed
            return 500, _internal(e, f"{type(e).__name__}", method, path, principal)
    if matched_path:
        return 404, ApiError(ErrorCode.NOT_FOUND, f"no {method} on {path}").to_body()
    return 404, ApiError(ErrorCode.NOT_FOUND, f"unknown path {path}").to_body()


# ------------------------------------------------------------------ Lambda adapter

ROLE_PRINCIPALS = ("relay", "vendor-portal", "vendor_portal", "checkpointer", "auditor", "ingest", "issuer", "agent",
                   "tools", "host")


def principal_from_arn(arn: str | None) -> str | None:
    """arn:aws:sts::<acct>:assumed-role/airgap-<name>[-...]/<session> -> principal name (unknown -> 'unknown')."""
    if not arn:
        return "unknown"
    m = re.search(r":assumed-role/([^/]+)/", arn) or re.search(r":role/([^/]+)$", arn)
    role = (m.group(1) if m else arn).lower()
    for name in ROLE_PRINCIPALS:
        if name in role:
            return name.replace("-", "_")
    return "unknown"


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """API Gateway adapter around dispatch(): REST API v1 (private API, IAM auth) and HTTP API v2 payloads."""
    rc = event.get("requestContext", {})
    if "http" in rc:  # v2
        method, path = rc["http"]["method"], event.get("rawPath", "/")
        arn = (rc.get("authorizer", {}).get("iam", {}) or {}).get("userArn")
    else:  # v1
        method, path = event.get("httpMethod", "GET"), event.get("path", "/")
        arn = (rc.get("identity", {}) or {}).get("userArn")
    stage = rc.get("stage")
    if stage and path.startswith(f"/{stage}/"):
        path = path[len(stage) + 1:]
    raw = event.get("body")
    if raw and event.get("isBase64Encoded"):
        raw = base64.b64decode(raw)
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    body: Any = None
    if raw:
        if "json" in headers.get("content-type", "application/json"):
            try:
                body = json.loads(raw)
            except ValueError:
                return _lambda_resp(400, ApiError(ErrorCode.INVALID_REQUEST, "body is not JSON").to_body())
        else:
            body = raw
    status, out = dispatch(method, path, event.get("queryStringParameters") or {}, body, headers,
                           principal=principal_from_arn(arn))
    return _lambda_resp(status, out)


def _lambda_resp(status: int, out: Any) -> dict[str, Any]:
    if isinstance(out, bytes):
        ctype = getattr(out, "content_type", "application/octet-stream")
        try:
            return {"statusCode": status, "headers": {"content-type": ctype}, "body": out.decode("utf-8")}
        except UnicodeDecodeError:
            return {"statusCode": status, "headers": {"content-type": ctype}, "isBase64Encoded": True,
                    "body": base64.b64encode(out).decode()}
    return {"statusCode": status, "headers": {"content-type": "application/json"}, "body": json.dumps(out)}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
