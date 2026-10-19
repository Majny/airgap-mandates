"""SD-JWT VC + KB-JWT verifier for payee-binding attestations. CONTRACTS.md v2 §11 (S4). Owner: WS-D.

Never raises on bad input: every failure is an AttestResult with ok=False and an error code. Contract codes
(§4.4) are used where they exist; the remaining verifier codes map to `attestation_insufficient` via API_ERROR.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from executor.attest.sdjwt import (
    KB_TYP,
    SD_ALG,
    VC_TYPS,
    SdJwtError,
    disclosure_digest,
    es256_verify,
    jws_parse,
    key_from_jwk,
    parse_disclosure,
    sd_hash,
    split_presentation,
    thumbprint,
)
from executor.attest.trust import ISSUER_CLASSES
from executor.facts._util import data_dir
from executor.models import AttestResult

VCT = "urn:airgap:payee-binding:v1"
BOUND_FIELDS = ("change_id", "aud", "change_nonce", "new_iban", "vendor_ico")
KB_MAX_AGE_S = 15 * 60
MAX_SKEW_S = 60

BREAK_GLASS_REQUIRED = "break_glass_required"
ISSUER_NOT_PINNED = "issuer_not_pinned"
KB_JWT_INVALID = "kb_jwt_invalid"
VC_INVALID = "vc_invalid"  # malformed, bad issuer signature, wrong vct, expired, tampered disclosure
BINDING_MISMATCH = "binding_mismatch"  # disclosed iban/ico differ from the change (or registry + foreign IBAN)
VC_REVOKED = "vc_revoked"

# AttestResult.error -> CONTRACTS §4.4 API error code (for the FSM's ApiError).
API_ERROR = {
    BREAK_GLASS_REQUIRED: BREAK_GLASS_REQUIRED,
    ISSUER_NOT_PINNED: ISSUER_NOT_PINNED,
    KB_JWT_INVALID: KB_JWT_INVALID,
    VC_INVALID: "attestation_insufficient",
    BINDING_MISMATCH: "attestation_insufficient",
    VC_REVOKED: "attestation_insufficient",
}


class _Fail(Exception):
    def __init__(self, code: str, issuer_class: str | None = None, iss: str | None = None):
        super().__init__(code)
        self.code, self.issuer_class, self.iss = code, issuer_class, iss


def load_revoked(path: str | Path | None = None) -> set[str]:
    """Revoked sha256 hex values from data/vc_status.json `{"revoked": [...]}`: either a presentation's vc_sha256 or
    the sha256 of the issuer JWT (revokes every presentation of that credential). Missing file -> empty."""
    p = Path(path) if path else data_dir() / "vc_status.json"
    try:
        revoked = json.loads(p.read_text()).get("revoked") or []
    except FileNotFoundError:
        return set()
    if not isinstance(revoked, list) or not all(isinstance(h, str) for h in revoked):
        raise ValueError("vc_status.json: revoked must be a list of sha256 hex strings")
    return set(revoked)


def _int(v: Any) -> int:
    if type(v) is not int:
        raise SdJwtError("time claim must be an integer")
    return v


def _issuer(jwt: str, pins: list[dict[str, Any]], now_s: int) -> tuple[dict[str, Any], dict[str, Any]]:
    """Pin lookup + issuer signature + vct/time checks. Returns (payload, matching pin)."""
    try:
        header, payload, signing_input, sig = jws_parse(jwt)
        if header.get("typ") not in VC_TYPS:
            raise SdJwtError("bad typ")
        jwk = header.get("jwk")
        pub = key_from_jwk(jwk)
        tp = thumbprint(jwk)
    except (SdJwtError, KeyError, TypeError) as e:
        raise _Fail(VC_INVALID) from e
    if "kid" in header and header["kid"] != tp:
        raise _Fail(VC_INVALID)
    pin = next((p for p in pins if isinstance(p, dict) and p.get("jwk_thumbprint") == tp), None)
    if pin is None or pin.get("issuer_class") not in ISSUER_CLASSES or not isinstance(pin.get("iss"), str):
        raise _Fail(ISSUER_NOT_PINNED)  # never echo the unverified `iss` claim into the result / audit leaf
    cls, iss = pin.get("issuer_class"), pin.get("iss")
    if not es256_verify(pub, signing_input, sig):
        raise _Fail(VC_INVALID, cls, iss)
    try:
        iat, exp = _int(payload.get("iat")), _int(payload.get("exp"))
    except SdJwtError as e:
        raise _Fail(VC_INVALID, cls, iss) from e
    if (payload.get("vct") != VCT or payload.get("iss") != iss or payload.get("_sd_alg") != SD_ALG
            or iat > now_s + MAX_SKEW_S or exp <= now_s or exp <= iat):
        raise _Fail(VC_INVALID, cls, iss)
    return payload, pin


def _disclosed(payload: dict[str, Any], disclosures: list[str], cls: str, iss: str) -> dict[str, str]:
    sd = payload.get("_sd")
    if not isinstance(sd, list) or len(set(disclosures)) != len(disclosures):
        raise _Fail(VC_INVALID, cls, iss)
    out: dict[str, str] = {}
    try:
        for d in disclosures:
            if disclosure_digest(d) not in sd:
                raise SdJwtError("disclosure not in _sd")
            name, value = parse_disclosure(d)
            if name in out or name in payload or not isinstance(value, str):
                raise SdJwtError("duplicate / conflicting / non-string claim")
            out[name] = value
    except SdJwtError as e:
        raise _Fail(VC_INVALID, cls, iss) from e
    return out


def _kb(kb: str, payload: dict[str, Any], jwt: str, disclosures: list[str], change: dict[str, Any],
        now_s: int, cls: str, iss: str) -> None:
    try:
        header, claims, signing_input, sig = jws_parse(kb)
        cnf = payload.get("cnf")
        holder = key_from_jwk(cnf.get("jwk") if isinstance(cnf, dict) else None)
        iat = _int(claims.get("iat"))
    except SdJwtError as e:
        raise _Fail(KB_JWT_INVALID, cls, iss) from e
    if (header.get("typ") != KB_TYP or not es256_verify(holder, signing_input, sig)
            or claims.get("aud") != change.get("aud") or claims.get("nonce") != change.get("change_nonce")
            or not (now_s - KB_MAX_AGE_S <= iat <= now_s + MAX_SKEW_S)
            or claims.get("sd_hash") != sd_hash(jwt, disclosures)):
        raise _Fail(KB_JWT_INVALID, cls, iss)


def verify_vc(vc: str, change: dict[str, Any], *, pins: list[dict[str, Any]], now: datetime,
              revoked: Iterable[str] | None = None) -> AttestResult:
    """Verify issuer signature against the pinned trust list (class from the pin, never from the VC), disclosures,
    KB-JWT (aud = change.aud, nonce = change.change_nonce, iat <= 15 min), disclosed iban == change.new_iban and
    ico == change.vendor_ico, not revoked (`revoked` None -> data/vc_status.json).
    Errors: break_glass_required | issuer_not_pinned | vc_invalid | kb_jwt_invalid | binding_mismatch | vc_revoked."""
    vc_bytes = vc.encode("utf-8", "replace") if isinstance(vc, str) else b""
    vc_sha = hashlib.sha256(vc_bytes).hexdigest()
    disclosed: dict[str, str] = {}
    res: AttestResult = {"ok": False, "issuer_class": None, "iss": None, "error": None, "disclosed": disclosed,
                         "vc_sha256": vc_sha}
    try:
        if not pins:
            raise _Fail(BREAK_GLASS_REQUIRED)
        if not all(isinstance(change.get(f), str) and change.get(f) for f in BOUND_FIELDS):
            raise _Fail(BINDING_MISMATCH)  # fail closed: nothing to bind to (None == None must never match)
        now_s = int((now if now.tzinfo else now.replace(tzinfo=UTC)).timestamp())
        try:
            jwt, disclosures, kb = split_presentation(vc)
        except SdJwtError as e:
            raise _Fail(VC_INVALID) from e
        payload, pin = _issuer(jwt, pins, now_s)
        cls, iss = pin["issuer_class"], pin["iss"]
        res["issuer_class"], res["iss"] = cls, iss
        disclosed.update(_disclosed(payload, disclosures, cls, iss))
        if payload.get("change_id") != change.get("change_id"):
            raise _Fail(BINDING_MISMATCH, cls, iss)
        _kb(kb, payload, jwt, disclosures, change, now_s, cls, iss)
        if disclosed.get("iban") != change.get("new_iban") or disclosed.get("ico") != change.get("vendor_ico"):
            raise _Fail(BINDING_MISMATCH, cls, iss)
        if cls == "registry" and not disclosed["iban"].startswith("CZ"):
            raise _Fail(BINDING_MISMATCH, cls, iss)
        revoked_set = load_revoked() if revoked is None else set(revoked)
        if vc_sha in revoked_set or hashlib.sha256(jwt.encode("ascii")).hexdigest() in revoked_set:
            raise _Fail(VC_REVOKED, cls, iss)
        res["ok"] = True
    except _Fail as f:
        res["error"] = f.code
        res["issuer_class"] = res["issuer_class"] or f.issuer_class
        res["iss"] = res["iss"] or f.iss
    except Exception:  # noqa: BLE001 - fail closed, never raise on hostile input
        res["error"] = VC_INVALID
    return res


def distinct_classes(results: list[AttestResult]) -> int:
    """Number of distinct known issuer classes among ok results (F-ATTEST k/3)."""
    return len({r["issuer_class"] for r in results if r.get("ok") is True and r.get("issuer_class") in ISSUER_CLASSES})
