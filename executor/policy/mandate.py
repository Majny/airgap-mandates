"""Mandate lifecycle (2/2 above the dual threshold). CONTRACTS.md v2 §4.2, §3.2. Owner: WS-A."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from executor.canonical import canonical_json, sha256_hex
from executor.config import iso, now as clock
from executor.errors import ApiError, ErrorCode
from executor.models import MandateStatus, VopCode
from executor.policy import rules
from executor.policy.challenge import issue_challenge
from executor.store import AnyOf, shims

REGISTRY_META = {"vendor_id": "registry#meta"}
MAX_VALIDITY = timedelta(days=7)


def _dt(v: str) -> datetime:
    dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp without timezone")
    return dt.astimezone(timezone.utc)


def registry_snapshot(store: Any) -> dict[str, Any]:
    """Current payee registry: version (registry#meta), payee_registry_hash over ACTIVE [vendor_id, iban] pairs."""
    rows = [r for r in store.scan("registry") if r["vendor_id"] != REGISTRY_META["vendor_id"] and r.get("iban")
            and r.get("status", "ACTIVE") == "ACTIVE"]
    pairs = sorted([r["vendor_id"], r["iban"]] for r in rows)
    meta = store.get("registry", REGISTRY_META) or {}
    return {"version": int(meta.get("registry_version", 0)), "hash": sha256_hex(canonical_json(pairs)),
            "count": len(pairs), "pairs": pairs}


def _invalid(msg: str) -> ApiError:
    return ApiError(ErrorCode.INVALID_REQUEST, msg)


def validate_form(form: dict[str, Any], now: datetime) -> dict[str, Any]:
    allowed = {"max_per_payment_minor", "max_total_minor", "max_count", "payee_scope", "valid_from", "valid_until",
               "currency", "require_vop", "max_anom"}
    if not isinstance(form, dict) or set(form) - allowed:
        raise _invalid(f"unknown fields: {sorted(set(form or {}) - allowed)}")

    def pos_int(name: str, lo: int, hi: int | None = None) -> int:
        v = form.get(name)
        if not isinstance(v, int) or isinstance(v, bool) or v < lo or (hi is not None and v > hi):
            raise _invalid(f"{name} must be an integer in [{lo}, {hi if hi is not None else 'inf'}]")
        return v

    per = pos_int("max_per_payment_minor", 1)
    total = pos_int("max_total_minor", 1)
    if total < per:
        raise _invalid("max_total_minor must be >= max_per_payment_minor")
    count = pos_int("max_count", 1, 1000)
    if form.get("payee_scope") != "existing_only":
        raise _invalid("payee_scope must be existing_only")
    if form.get("currency") != "CZK":
        raise _invalid("currency must be CZK")
    try:
        valid_from = _dt(form["valid_from"]) if form.get("valid_from") else now
        valid_until = _dt(form["valid_until"])
    except (KeyError, TypeError, ValueError):
        raise _invalid("valid_from / valid_until must be ISO 8601 UTC timestamps") from None
    if not (valid_until > now and valid_until <= now + MAX_VALIDITY and valid_until > valid_from):
        raise _invalid("valid_until must be > now, > valid_from and <= now + 7 days")
    require_vop = form.get("require_vop", ["MTCH"])
    codes = {c.value for c in VopCode}
    if not isinstance(require_vop, list) or not require_vop or any(c not in codes for c in require_vop):
        raise _invalid(f"require_vop must be a non-empty subset of {sorted(codes)}")
    max_anom = form.get("max_anom", rules.PARAMS["I-ANOM"]["default_max_anom"])
    if not isinstance(max_anom, int) or isinstance(max_anom, bool) or not 0 <= max_anom <= 100:
        raise _invalid("max_anom must be an integer 0..100")
    return {"max_per_payment_minor": per, "max_total_minor": total, "max_count": count,
            "payee_scope": "existing_only", "valid_from": iso(valid_from), "valid_until": iso(valid_until),
            "currency": "CZK", "require_vop": sorted(set(require_vop)), "max_anom": max_anom}


def _render_params(m: dict[str, Any], *, payee_count: int, sig_index: int) -> dict[str, Any]:
    return {"mandate_no": m["mandate_no"], "max_per_payment_minor": m["max_per_payment_minor"],
            "max_total_minor": m["max_total_minor"], "max_count": m["max_count"], "payee_scope": m["payee_scope"],
            "valid_from": m["valid_from"], "valid_until": m["valid_until"], "currency": m["currency"],
            "require_vop": m["require_vop"], "payee_count": payee_count,
            "payee_registry_version": m["payee_registry_version"], "policy_hash": m["policy_hash"],
            "sig_index": sig_index, "sig_total": m["sig_required"]}


def _challenge(m: dict[str, Any], role: str, sig_index: int, *, store: Any, settings: Any, now: datetime) -> Any:
    params = _render_params(m, payee_count=int(m.get("payee_count", 0)), sig_index=sig_index)
    return issue_challenge(purpose="MANDATE", role=role, subject_id=m["mandate_id"], params=params,
                           facts_digest=None, policy_hash=m["policy_hash"], store=store, settings=settings, now=now)


def public(m: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in m.items() if k not in ("payee_count",)}


def create_mandate(form: dict[str, Any], *, store: Any, settings: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate form, pin registry version/hash, sig_required = 2 if max_total_minor > dual threshold;
    allocate mandate_no; create MANDATE challenge (clerk, ROLE CLERK 1/n) -> (mandate PENDING_SIG_CLERK, challenge)."""
    now = clock(settings)
    f = validate_form(form, now)
    reg = registry_snapshot(store)
    no = store.increment("counters", {"name": "mandate_no"}, "value")
    m: dict[str, Any] = {
        "mandate_id": f"mnd_{no}", "mandate_no": no, "status": MandateStatus.PENDING_SIG_CLERK.value, **f,
        "payee_registry_version": reg["version"], "payee_registry_hash": reg["hash"], "payee_count": reg["count"],
        "policy_hash": rules.policy_hash(),
        "sig_required": 2 if f["max_total_minor"] > settings.mandate_dual_threshold_minor else 1,
        "signers": [], "spent_minor": 0, "count": 0, "challenge_nonce": "", "created_at": iso(now),
        "activated_at": None,
    }
    ch = _challenge(m, "clerk", 1, store=store, settings=settings, now=now)
    m["challenge_nonce"] = ch["nonce"]
    store.put("mandates", m)
    return public(m), ch


def on_mandate_signature(mandate_id: str, role: str, signer_address: str, nonce: str, *, store: Any,
                         settings: Any) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """PENDING_SIG_CLERK -> (PENDING_SIG_TREASURY + treasury challenge | ACTIVE); treasury address != clerk;
    activation supersedes the previous ACTIVE mandate; mandate_signed leaf. Returns (mandate, next challenge)."""
    now = clock(settings)
    m = store.get("mandates", {"mandate_id": mandate_id})
    if m is None:
        raise ApiError(ErrorCode.NOT_FOUND, f"mandate {mandate_id} not found")
    if m["challenge_nonce"] != nonce:
        raise ApiError(ErrorCode.STATE_CONFLICT, "challenge is not the mandate's current challenge")
    status = m["status"]
    expected_role = {"PENDING_SIG_CLERK": "clerk", "PENDING_SIG_TREASURY": "treasury"}.get(status)
    if expected_role is None:
        raise ApiError(ErrorCode.STATE_CONFLICT, f"mandate is {status}")
    if role != expected_role:
        raise ApiError(ErrorCode.SIGS_INSUFFICIENT, f"{role} cannot sign in {status}")
    if any(s["address"] == signer_address for s in m["signers"]):
        raise ApiError(ErrorCode.SIGS_INSUFFICIENT, "the same key cannot sign twice")
    signers = m["signers"] + [{"role": role, "address": signer_address, "nonce": nonce, "signed_at": iso(now)}]
    sig_index = len(signers)
    nxt: dict[str, Any] | None = None
    if sig_index < m["sig_required"]:
        new_status = MandateStatus.PENDING_SIG_TREASURY.value
        nxt = _challenge(m, "treasury", sig_index + 1, store=store, settings=settings, now=now)
        upd = {"status": new_status, "signers": signers, "challenge_nonce": nxt["nonce"]}
    else:
        new_status = MandateStatus.ACTIVE.value
        upd = {"status": new_status, "signers": signers, "activated_at": iso(now)}
    if not store.update_if("mandates", {"mandate_id": mandate_id}, upd, {"status": status, "challenge_nonce": nonce}):
        raise ApiError(ErrorCode.STATE_CONFLICT, "mandate changed concurrently")
    if new_status == MandateStatus.ACTIVE.value:
        for old in store.query("mandates", ("status", "ACTIVE"), index="by_status"):
            if old["mandate_id"] != mandate_id:
                store.update_if("mandates", {"mandate_id": old["mandate_id"]},
                                {"status": MandateStatus.SUPERSEDED.value}, {"status": AnyOf("ACTIVE")})
    m = {**m, **upd}
    fields = {k: m[k] for k in ("max_per_payment_minor", "max_total_minor", "max_count", "payee_scope", "valid_from",
                                "valid_until", "currency", "require_vop", "max_anom", "payee_registry_version",
                                "payee_registry_hash", "policy_hash")}
    data = {"mandate_id": mandate_id, "mandate_no": m["mandate_no"], "signer_address": signer_address, "role": role,
            "nonce": nonce, "sig_index": sig_index, "sig_total": m["sig_required"], "status": new_status,
            "fields": fields}
    shims.append(shims.make_event("mandate_signed", data, subject_id=mandate_id, actor="executor",
                                  settings=settings), store=store, settings=settings)
    return public(m), nxt


def get_active_mandate(*, store: Any, settings: Any) -> dict[str, Any] | None:
    """The single ACTIVE, unexpired mandate (newest by mandate_no), or None. A stale policy_hash is left to
    decide() so that it surfaces as I-MANDATE."""
    now = clock(settings)
    rows = store.query("mandates", ("status", "ACTIVE"), index="by_status", reverse=True)
    for m in rows:
        if _dt(m["valid_until"]) > now:
            return public(m)
    return None
