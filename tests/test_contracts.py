"""Validate contracts/fixtures against contracts/schemas (CONTRACTS.md v2 is the source of truth)."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")
referencing = pytest.importorskip("referencing")

from executor import render as R  # noqa: E402

ROOT = Path(__file__).resolve().parents[1] / "contracts"
SCHEMAS = ROOT / "schemas"
FIXTURES = ROOT / "fixtures"
BASE = "https://airgap.local/schemas/"


def _registry():
    from referencing import Registry, Resource

    resources = []
    for p in SCHEMAS.glob("*.json"):
        if p.name == "endpoints.json":
            continue
        doc = json.loads(p.read_text())
        resources.append((doc["$id"], Resource.from_contents(doc)))
    return Registry().with_resources(resources)


REGISTRY = _registry()
ENDPOINTS = json.loads((SCHEMAS / "endpoints.json").read_text())


def validate(instance, schema_name):
    schema = {"$ref": f"{BASE}{schema_name}.json"}
    jsonschema.Draft202012Validator(schema, registry=REGISTRY).validate(instance)


def test_schemas_are_valid():
    for p in SCHEMAS.glob("*.json"):
        if p.name == "endpoints.json":
            continue
        jsonschema.Draft202012Validator.check_schema(json.loads(p.read_text()))


ENDPOINT_FIXTURES = sorted(p for p in FIXTURES.glob("*/*.json") if p.parent.name not in ("audit_events", "objects"))


def test_every_endpoint_has_a_fixture():
    covered = {json.loads(p.read_text())["endpoint"] for p in ENDPOINT_FIXTURES}
    must = {"POST /mandates", "POST /proposals", "POST /changes", "POST /changes/{change_id}/reject",
            "GET /challenges/{nonce}", "POST /signatures", "POST /callbacks/{change_id}",
            "POST /changes/{change_id}/attestations", "POST /changes/{change_id}/break-glass", "POST /attestations",
            "GET /attestations/{ico}", "POST /egress", "POST /tools/{name}", "GET /audit/export",
            "GET /receipts/{tx_id}", "GET /checkpoint", "POST /witness/add-checkpoint", "GET /export/pain001/{tx_id}",
            "GET /health"}
    assert not (must - covered)
    assert covered <= set(ENDPOINTS)


def test_removed_v1_endpoints():
    assert "GET /portal/notifications" not in ENDPOINTS
    assert "POST /bank/batch" not in ENDPOINTS


@pytest.mark.parametrize("path", ENDPOINT_FIXTURES, ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_fixture_matches_schema(path):
    fx = json.loads(path.read_text())
    ep = ENDPOINTS[fx["endpoint"]]
    if fx["request"] is not None and fx["status"] != 400:  # 400 fixtures carry invalid requests on purpose
        assert ep["request"], f"{fx['endpoint']} takes no body"
        validate(fx["request"], ep["request"])
    if fx["status"] >= 400:
        validate(fx["response"], ep["error"])
        if isinstance(fx["response"], dict) and fx["response"]["error"] == "egress_blocked":
            validate(fx["response"]["details"]["decision"], "egress_block.decision")
    else:
        validate(fx["response"], ep["response"])


@pytest.mark.parametrize("path", sorted((FIXTURES / "audit_events").glob("*.json")), ids=lambda p: p.stem)
def test_audit_event_fixture(path):
    validate(json.loads(path.read_text()), "audit_event")


@pytest.mark.parametrize("path", sorted((FIXTURES / "objects").glob("*.json")), ids=lambda p: p.stem)
def test_object_fixture(path):
    fx = json.loads(path.read_text())
    validate(fx["instance"], fx["schema"])


def _ev(**kw):
    e = {"v": 2, "log_id": "audit", "seq": 1, "ts": "2026-10-19T12:00:00Z", "type": "execution", "actor": "executor",
         "subject_id": "tx_1", "data": {"tx_id": "tx_1"}, "policy_hash": "a" * 64, "inputs_digest": "b" * 64,
         "facts_digest": "c" * 64, "hints_digest": "d" * 64}
    e.update(kw)
    return e


def test_audit_event_requires_type_specific_data():
    with pytest.raises(jsonschema.ValidationError):
        validate(_ev(), "audit_event")


def test_decision_relevant_events_require_digests():
    data = {"subject_id": "prp_1", "decision": "allow", "rule_ids": [], "mandate_id": None}
    validate(_ev(type="decision", data=data), "audit_event")
    with pytest.raises(jsonschema.ValidationError):
        validate(_ev(type="decision", data=data, policy_hash=None), "audit_event")


def test_r0_deny_never_carries_a_challenge():
    ch = json.loads((FIXTURES / "challenges_get" / "pay.json").read_text())["response"]
    d = {"decision": "deny", "rule_ids": ["I-BLOCK"], "facts": [], "facts_digest": "a" * 64, "mandate_id": None,
         "policy_hash": "b" * 64, "challenge": ch}
    schema = {"$ref": f"{BASE}common.json#/$defs/decision"}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema, registry=REGISTRY).validate(d)
    del d["challenge"]
    jsonschema.Draft202012Validator(schema, registry=REGISTRY).validate(d)


def test_f_fact_display_line_max_18():
    schema = {"$ref": f"{BASE}common.json#/$defs/fact"}
    v = jsonschema.Draft202012Validator(schema, registry=REGISTRY)
    v.validate({"id": "F-PSP", "kind": "F", "severity": "WARN", "label": "x", "display_line": "PSP UNKNOWN"})
    with pytest.raises(jsonschema.ValidationError):
        v.validate({"id": "F-PSP", "kind": "F", "severity": "WARN", "label": "x", "display_line": "X" * 19})


def test_mostlyright_facts_carry_snapshot_hash():
    seen = set()
    for p in FIXTURES.glob("**/*.json"):
        for f in _facts(json.loads(p.read_text())):
            if f["id"] in ("F-PSP", "F-WARNLIST", "F-SANCTION"):
                assert len(f.get("prov", "")) == 64, (p, f)
                seen.add(f["id"])
    assert seen == {"F-PSP", "F-WARNLIST", "F-SANCTION"}


def _facts(obj):
    if isinstance(obj, dict):
        if {"id", "kind", "severity", "display_line"} <= obj.keys():
            yield obj
        for v in obj.values():
            yield from _facts(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _facts(v)


def _challenges(obj):
    if isinstance(obj, dict):
        if {"nonce", "text", "text_sha256", "purpose"} <= obj.keys():
            yield obj
        for v in obj.values():
            yield from _challenges(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _challenges(v)


def test_fixture_challenge_texts_obey_render_contract():
    n = 0
    for p in ENDPOINT_FIXTURES:
        for ch in _challenges(json.loads(p.read_text())):
            n += 1
            text = ch["text"]
            assert R.text_sha256(text) == ch["text_sha256"]
            pages = R.check_text(text, ch["profile"])
            assert len(text.split("\n")) == ch["line_count"] <= R.MAX_LINES
            assert len(pages) == ch["pages"]
            assert f"N {ch['nonce']}" in text.split("\n")
            assert text.startswith(f"AG1/{ch['deployment']} ")
            if ch["purpose"] != "ENROLL":
                assert f"H {ch['subject_hash'][:R.PROFILES[ch['profile']].hash_hex]}" in text.split("\n")
            assert "[H]" not in text and "[F]" not in text
    assert n >= 8


def test_checkpoint_note_signatures_verify():
    """The fixture note is signed with Ed25519 per C2SP signed-note (log, 0x01) and tlog-cosignature (W1, 0x04)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    note = json.loads((FIXTURES / "objects" / "checkpoint_note.json").read_text())["instance"]
    body, sigs = note.split("\n\n", 1)
    body += "\n"
    export = json.loads((FIXTURES / "audit_export" / "ok.json").read_text())["response"]
    for line, (role, t) in zip(sigs.strip("\n").split("\n"), [("log", 1), ("w1", 4)]):
        _, name, b64 = line.split(" ")
        raw = base64.b64decode(b64)
        vname, vkid, vkey = export["pubkeys"][role].split("+", 2)
        assert vname == name
        pub = base64.b64decode(vkey)[1:]
        kid = hashlib.sha256(name.encode() + b"\n" + bytes([t]) + pub).digest()[:4]
        assert raw[:4] == kid
        if t == 1:
            assert kid.hex() == vkid
            Ed25519PublicKey.from_public_bytes(pub).verify(raw[4:], body.encode())
        else:
            ts = int.from_bytes(raw[4:12], "big")
            Ed25519PublicKey.from_public_bytes(pub).verify(raw[12:], f"cosignature/v1\ntime {ts}\n".encode()
                                                           + body.encode())
