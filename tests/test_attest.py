"""S4 supplier attestation (SD-JWT VC + KB-JWT) tests (CONTRACTS.md v2 §11, §8.2). Owner: WS-D."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from executor.attest import sdjwt
from executor.attest.attestation import commitment
from executor.attest.trust import make_pin, pins_for, pins_from_keys
from executor.attest.vc import distinct_classes, load_revoked, verify_vc
from executor.canonical import canonical_json
from executor.issuers.issuer import (
    ISSUER_URLS,
    IssuerRefused,
    issue_sd_jwt,
    issue_vc,
    load_holder_key,
    load_issuer_key,
    present,
)

NOW = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)
CHANGE = {
    "change_id": "chg_7",
    "aud": "AG1/DEMO/changes/chg_7",
    "change_nonce": "0123456789abcdef0123456789abcdef",
    "new_iban": "CZ2003000000002001234567",
    "vendor_ico": "12345678",
    "vendor_name": "ACME s.r.o.",
}
CLASSES = ("supplier-erp", "supplier-bank", "registry")


@pytest.fixture(scope="module")
def keys():
    return {c: sdjwt.generate_key() for c in CLASSES}


@pytest.fixture(scope="module")
def holder():
    return sdjwt.generate_key()


@pytest.fixture(scope="module")
def pins(keys):
    return [make_pin(c, ISSUER_URLS[c], sdjwt.public_jwk(keys[c]), pinned_at="2024-03-01T00:00:00Z") for c in CLASSES]


@pytest.fixture(scope="module")
def adis(tmp_path_factory):
    p = tmp_path_factory.mktemp("adis") / "adis.json"
    p.write_text(json.dumps({"as_of": "2026-10-19", "payers": {
        "CZ12345678": {"unreliable": False, "accounts": [CHANGE["new_iban"]]}}}))
    return p


def _vc(keys, holder, cls="supplier-erp", change=CHANGE, now=NOW, **kw):
    return issue_vc(cls, change, key=keys[cls], holder_key=holder, now=now, **kw)


def _verify(vc, pins, change=CHANGE, now=NOW, revoked=()):
    return verify_vc(vc, change, pins=pins, now=now, revoked=revoked)


def _swap(vc: str, idx: int, new: str) -> str:
    parts = vc.split("~")
    parts[idx] = new
    return "~".join(parts)


# --- named S4 invariants (CONTRACTS §8.2) -------------------------------------------------------------------------

def test_s4_one_vc_insufficient(keys, holder, pins):
    r = _verify(_vc(keys, holder), pins)
    assert r["ok"] and r["error"] is None
    assert distinct_classes([r]) == 1
    assert distinct_classes([]) == 0


def test_s4_same_class_twice_insufficient(keys, holder, pins):
    rs = [_verify(_vc(keys, holder, "supplier-bank"), pins) for _ in range(2)]
    assert all(r["ok"] for r in rs) and rs[0]["vc_sha256"] != rs[1]["vc_sha256"]
    assert distinct_classes(rs) == 1


def test_s4_kb_jwt_wrong_nonce_or_aud(keys, holder, pins):
    for field, bad in (("change_nonce", "f" * 32), ("aud", "AG1/DEMO/changes/chg_8")):
        r = _verify(_vc(keys, holder, change={**CHANGE, field: bad}), pins)
        assert (r["ok"], r["error"]) == (False, "kb_jwt_invalid"), field


def test_s4_kb_jwt_stale(keys, holder, pins):
    vc = _vc(keys, holder, now=NOW - timedelta(minutes=16))
    assert _verify(vc, pins)["error"] == "kb_jwt_invalid"
    assert _verify(_vc(keys, holder, now=NOW - timedelta(minutes=14)), pins)["ok"]


def test_s4_issuer_not_pinned(keys, holder, pins):
    rogue = sdjwt.generate_key()
    vc = issue_vc("supplier-bank", CHANGE, key=rogue, holder_key=holder, now=NOW)
    r = _verify(vc, pins)
    assert (r["ok"], r["error"], r["issuer_class"], r["iss"]) == (False, "issuer_not_pinned", None, None)


def test_s4_disclosed_iban_must_match_change(keys, holder, pins):
    fraud = {**CHANGE, "new_iban": "LT483999000000001234"}
    r = _verify(_vc(keys, holder, change=fraud), pins)  # VC for the fraudster IBAN presented on the ACME change
    assert (r["ok"], r["error"]) == (False, "binding_mismatch")
    r = _verify(_vc(keys, holder, change={**CHANGE, "vendor_ico": "87654321"}), pins)
    assert r["error"] == "binding_mismatch"
    r = _verify(_vc(keys, holder, disclose=["legal_name", "ico"]), pins)  # iban withheld
    assert r["error"] == "binding_mismatch"


# --- happy paths --------------------------------------------------------------------------------------------------

def test_happy_two_classes(keys, holder, pins):
    rs = [_verify(_vc(keys, holder, c), pins) for c in ("supplier-erp", "supplier-bank")]
    assert all(r["ok"] for r in rs)
    assert [r["issuer_class"] for r in rs] == ["supplier-erp", "supplier-bank"]
    assert rs[0]["disclosed"] == {"legal_name": "ACME s.r.o.", "iban": CHANGE["new_iban"], "ico": "12345678"}
    assert rs[0]["iss"] == "https://issuer.acme.example/erp"
    assert distinct_classes(rs) == 2


def test_happy_three_classes(keys, holder, pins, adis):
    rs = [_verify(_vc(keys, holder, c, adis_path=adis), pins) for c in CLASSES]
    assert all(r["ok"] for r in rs) and distinct_classes(rs) == 3


def test_demo_keys_and_pins_roundtrip():
    """data/issuer_keys (DEMO-ONLY) load and verify against pins_from_keys."""
    key, iss = load_issuer_key("supplier-bank")
    assert iss == "https://issuer.bank0300.example/accounts"
    vc = issue_vc("supplier-bank", CHANGE, key=key, holder_key=load_holder_key("12345678"), now=NOW, iss=iss)
    r = _verify(vc, pins_from_keys())
    assert r["ok"] and r["issuer_class"] == "supplier-bank"


def test_key_loaders_reject_path_tricks():
    for bad in ("../issuer_keys/registry", "holder-12345678", "agent"):
        with pytest.raises(ValueError):
            load_issuer_key(bad)
    for bad in ("../../x", "1234567", "１２３４５６７８"):
        with pytest.raises(ValueError):
            load_holder_key(bad)


def test_pins_for_reads_registry_row(pins):
    class S:
        def get(self, table, key):
            return {"vendor_id": key["vendor_id"], "issuer_pins": pins} if key["vendor_id"] == "v_acme" else None
    assert pins_for("v_acme", store=S()) == pins
    assert pins_for("v_beta", store=S()) == []


# --- attacks ------------------------------------------------------------------------------------------------------

def test_tampered_disclosure(keys, holder, pins):
    vc = _vc(keys, holder)
    jwt, ds, _ = sdjwt.split_presentation(vc)
    evil = sdjwt.make_disclosure("iban", "LT483999000000001234")
    ds2 = [evil if sdjwt.parse_disclosure(d)[0] == "iban" else d for d in ds]
    # re-sign the KB-JWT with the real holder key: only the disclosure digest check can catch this
    forged = sdjwt.presentation_prefix(jwt, ds2) + sdjwt.kb_jwt(
        holder, issuer_jwt=jwt, disclosures=ds2, aud=CHANGE["aud"], nonce=CHANGE["change_nonce"],
        iat=int(NOW.timestamp()))
    assert _verify(forged, pins)["error"] == "vc_invalid"


def test_tampered_issuer_signature(keys, holder, pins):
    vc = _vc(keys, holder)
    jwt = vc.split("~")[0]
    h, p, s = jwt.split(".")
    payload = json.loads(sdjwt.b64u_decode(p))
    payload["change_id"] = "chg_7"
    payload["exp"] += 86400  # attacker extends validity
    p2 = sdjwt.b64u_encode(json.dumps(payload).encode())
    assert _verify(_swap(vc, 0, f"{h}.{p2}.{s}"), pins)["error"] == "vc_invalid"
    sig = bytearray(sdjwt.b64u_decode(s))
    sig[5] ^= 1
    assert _verify(_swap(vc, 0, f"{h}.{p}.{sdjwt.b64u_encode(bytes(sig))}"), pins)["error"] == "vc_invalid"


def test_class_spoofing_uses_pin_class(keys, holder, pins):
    """VC claims issuer_class supplier-bank but is signed by the key pinned as supplier-erp -> class from pin."""
    jwt, ds = issue_sd_jwt("supplier-bank", CHANGE, key=keys["supplier-erp"], holder_key=holder, now=NOW,
                           iss=ISSUER_URLS["supplier-erp"])
    vc = present(jwt, ds, holder_key=holder, aud=CHANGE["aud"], nonce=CHANGE["change_nonce"], now=NOW)
    spoof = _verify(vc, pins)
    assert spoof["ok"] and spoof["issuer_class"] == "supplier-erp"
    real_erp = _verify(_vc(keys, holder, "supplier-erp"), pins)
    assert distinct_classes([spoof, real_erp]) == 1


def test_no_pins_break_glass_required(keys, holder):
    r = _verify(_vc(keys, holder), [])
    assert (r["ok"], r["error"]) == (False, "break_glass_required")


def test_revoked(keys, holder, pins):
    vc = _vc(keys, holder)
    r = _verify(vc, pins, revoked={hashlib.sha256(vc.encode()).hexdigest()})
    assert (r["ok"], r["error"]) == (False, "vc_revoked")
    jwt_sha = hashlib.sha256(vc.split("~")[0].encode()).hexdigest()
    assert _verify(vc, pins, revoked=[jwt_sha])["error"] == "vc_revoked"


def test_registry_refuses_foreign_iban(keys, holder, pins, adis):
    with pytest.raises(IssuerRefused):
        _vc(keys, holder, "registry", change={**CHANGE, "new_iban": "LT483999000000001234"}, adis_path=adis)
    with pytest.raises(IssuerRefused):  # CZ but not published in ADIS for CZ12345678
        _vc(keys, holder, "registry", change={**CHANGE, "new_iban": "CZ6203000000000123456789"}, adis_path=adis)
    # verifier also refuses a registry-pinned VC over a foreign account (defence in depth)
    jwt, ds = issue_sd_jwt("registry", {**CHANGE, "new_iban": "LT483999000000001234"}, key=keys["registry"],
                           holder_key=holder, now=NOW, iss=ISSUER_URLS["registry"])
    vc = present(jwt, ds, holder_key=holder, aud=CHANGE["aud"], nonce=CHANGE["change_nonce"], now=NOW)
    r = _verify(vc, pins, change={**CHANGE, "new_iban": "LT483999000000001234"})
    assert r["error"] == "binding_mismatch"


def test_kb_jwt_from_other_holder_key(keys, holder, pins):
    jwt, ds = issue_sd_jwt("supplier-erp", CHANGE, key=keys["supplier-erp"], holder_key=holder, now=NOW,
                           iss=ISSUER_URLS["supplier-erp"])
    thief = sdjwt.generate_key()
    vc = present(jwt, ds, holder_key=thief, aud=CHANGE["aud"], nonce=CHANGE["change_nonce"], now=NOW)
    assert _verify(vc, pins)["error"] == "kb_jwt_invalid"


def test_alg_none_and_hs256_rejected(keys, holder, pins):
    vc = _vc(keys, holder)
    jwt, ds, kb = sdjwt.split_presentation(vc)
    payload = json.loads(sdjwt.b64u_decode(jwt.split(".")[1]))
    jwk = sdjwt.public_jwk(keys["supplier-erp"])
    for alg, sig in (("none", b""), ("HS256", b"\1" * 32)):
        enc = lambda o: sdjwt.b64u_encode(json.dumps(o).encode())
        forged = f"{enc({'alg': alg, 'typ': 'dc+sd-jwt', 'jwk': jwk})}.{enc(payload)}.{sdjwt.b64u_encode(sig)}"
        assert _verify(_swap(vc, 0, forged), pins)["error"] == "vc_invalid", alg
        kb_claims = json.loads(sdjwt.b64u_decode(kb.split(".")[1]))
        forged_kb = f"{enc({'alg': alg, 'typ': 'kb+jwt'})}.{enc(kb_claims)}.{sdjwt.b64u_encode(sig)}"
        assert _verify(_swap(vc, -1, forged_kb), pins)["error"] == "kb_jwt_invalid", alg


def test_future_iat_rejected(keys, holder, pins):
    vc = _vc(keys, holder, now=NOW + timedelta(minutes=5))
    assert not _verify(vc, pins)["ok"]
    assert _verify(_vc(keys, holder, now=NOW + timedelta(seconds=30)), pins)["ok"]  # small clock skew ok


def test_expired_vc_rejected(keys, holder, pins):
    jwt, ds = issue_sd_jwt("supplier-erp", CHANGE, key=keys["supplier-erp"], holder_key=holder,
                           now=NOW - timedelta(hours=2), iss=ISSUER_URLS["supplier-erp"])
    vc = present(jwt, ds, holder_key=holder, aud=CHANGE["aud"], nonce=CHANGE["change_nonce"], now=NOW)
    assert _verify(vc, pins)["error"] == "vc_invalid"


def test_garbage_never_raises(pins):
    for junk in ("", "~", "a.b.c~", "x" * 5000, "a.b.c~~d.e.f", None, 42, "é.é.é~a.b.c"):
        r = verify_vc(junk, CHANGE, pins=pins, now=NOW, revoked=())  # type: ignore[arg-type]
        assert r["ok"] is False and r["error"]


_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(data=st.data())
def test_random_char_substitutions_never_verify(keys, holder, pins, data):
    """Substitute one char with another char of the SD-JWT alphabet (stays ASCII, so not trivially rejected)."""
    vc = _VC_CACHE.setdefault("vc", _vc(keys, holder))
    assert _verify(vc, pins)["ok"]
    i = data.draw(st.integers(0, len(vc) - 1))
    c = data.draw(st.sampled_from(_ALPHABET).filter(lambda ch: ch != vc[i]))
    assert verify_vc(vc[:i] + c + vc[i + 1:], CHANGE, pins=pins, now=NOW, revoked=())["ok"] is False


def test_every_position_substitution_never_verifies(keys, holder, pins):
    vc = _vc(keys, holder)
    assert _verify(vc, pins)["ok"]
    for i, ch in enumerate(vc):
        c = _ALPHABET[(_ALPHABET.index(ch) + 1) % len(_ALPHABET)]
        assert not _verify(vc[:i] + c + vc[i + 1:], pins)["ok"], i


def _high_s(jws: str) -> str:
    h, p, sig = jws.split(".")
    raw = sdjwt.b64u_decode(sig)
    s = int.from_bytes(raw[32:], "big")
    return f"{h}.{p}.{sdjwt.b64u_encode(raw[:32] + (sdjwt._N - s).to_bytes(32, 'big'))}"


def test_signatures_low_s_and_high_s_twin_rejected(keys, holder, pins):
    """ECDSA (r, n-s) twin would give a second valid issuer JWT with a different sha256 (revocation bypass)."""
    vc = _vc(keys, holder)
    jwt, ds, kb = sdjwt.split_presentation(vc)
    for jws in (jwt, kb):
        assert int.from_bytes(sdjwt.b64u_decode(jws.split(".")[2])[32:], "big") <= sdjwt._N // 2
    twin = _high_s(jwt)
    forged = sdjwt.presentation_prefix(twin, ds) + sdjwt.kb_jwt(
        holder, issuer_jwt=twin, disclosures=ds, aud=CHANGE["aud"], nonce=CHANGE["change_nonce"],
        iat=int(NOW.timestamp()))
    revoked = [hashlib.sha256(jwt.encode()).hexdigest()]
    assert _verify(vc, pins, revoked=revoked)["error"] == "vc_revoked"
    assert _verify(forged, pins, revoked=revoked)["error"] == "vc_invalid"
    assert _verify(_swap(vc, -1, _high_s(kb)), pins)["error"] == "kb_jwt_invalid"


def test_change_without_binding_fields_fails_closed(keys, holder, pins):
    """A VC disclosing nothing must not 'match' a change dict whose iban/ico are missing (None == None)."""
    vc = _vc(keys, holder, disclose=[])
    for field in ("new_iban", "vendor_ico", "aud", "change_nonce", "change_id"):
        bare = {k: v for k, v in CHANGE.items() if k != field}
        r = verify_vc(vc, bare, pins=pins, now=NOW, revoked=())
        assert (r["ok"], r["error"]) == (False, "binding_mismatch"), field
        r = verify_vc(vc, {**bare, field: ""}, pins=pins, now=NOW, revoked=())
        assert r["ok"] is False, field


def test_pin_with_unknown_class_not_trusted(keys, holder, pins):
    bad = [{**p, "issuer_class": "supplier-erp-2"} if p["issuer_class"] == "supplier-erp" else p for p in pins]
    r = _verify(_vc(keys, holder), bad)
    assert (r["ok"], r["error"]) == (False, "issuer_not_pinned")
    fake = {"ok": True, "issuer_class": "agent", "iss": None, "error": None, "disclosed": {}, "vc_sha256": ""}
    truthy = {**fake, "ok": 1, "issuer_class": "registry"}
    assert distinct_classes([fake, truthy, _verify(_vc(keys, holder), pins)]) == 1  # type: ignore[list-item]


def test_naive_now_is_utc(keys, holder, pins):
    assert _verify(_vc(keys, holder), pins, now=NOW.replace(tzinfo=None))["ok"]


def test_load_revoked_rejects_malformed(tmp_path):
    p = tmp_path / "vc_status.json"
    p.write_text(json.dumps({"revoked": "abc"}))
    with pytest.raises(ValueError):
        load_revoked(p)
    p.write_text(json.dumps({"revoked": ["a" * 64]}))
    assert load_revoked(p) == {"a" * 64}
    assert load_revoked(tmp_path / "missing.json") == set()
    assert load_revoked() == set()  # shipped data/vc_status.json


def test_registry_issues_with_shipped_adis_cache(keys, holder, pins):
    """Demo path: ACME legit new IBAN is published in data/adis_cache/adis.json; foreign mule is refused."""
    assert _verify(_vc(keys, holder, "registry"), pins)["ok"]
    with pytest.raises(IssuerRefused):
        _vc(keys, holder, "registry", change={**CHANGE, "new_iban": "LT493999000000005678"})


_VC_CACHE: dict[str, str] = {}


# --- attest log commitment ----------------------------------------------------------------------------------------

def test_commitment_salted():
    body = {"ico": "12345678", "iban": CHANGE["new_iban"]}
    n1, n2 = b"\x01" * 16, b"\x02" * 16
    assert commitment(body, n1) == hashlib.sha256(canonical_json(body) + n1).hexdigest()
    assert commitment(body, n1) != commitment(body, n2)
    assert commitment(body, n1) != hashlib.sha256(CHANGE["new_iban"].encode()).hexdigest()
    with pytest.raises(ValueError):
        commitment(body, b"short")
