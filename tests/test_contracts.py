"""Validate contracts/fixtures against contracts/schemas (CONTRACTS.md is the source of truth)."""

from __future__ import annotations

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


ENDPOINT_FIXTURES = sorted(p for p in FIXTURES.glob("*/*.json") if p.parent.name != "audit_events")


def test_every_endpoint_has_a_fixture():
    covered = {json.loads(p.read_text())["endpoint"] for p in ENDPOINT_FIXTURES}
    missing = {"POST /mandates", "POST /proposals", "POST /changes", "GET /challenges/{nonce}", "POST /signatures",
               "POST /callbacks/{change_id}", "POST /attestations", "GET /attestations/{ico}", "POST /egress",
               "GET /audit/export", "GET /receipts/{tx_id}"} - covered
    assert not missing


@pytest.mark.parametrize("path", ENDPOINT_FIXTURES, ids=lambda p: f"{p.parent.name}/{p.stem}")
def test_fixture_matches_schema(path):
    fx = json.loads(path.read_text())
    ep = ENDPOINTS[fx["endpoint"]]
    if fx["request"] is not None and fx["status"] != 400:  # 400 fixtures carry invalid requests on purpose
        assert ep["request"], f"{fx['endpoint']} takes no body"
        validate(fx["request"], ep["request"])
    if fx["status"] >= 400:
        validate(fx["response"], "error")
        if fx["response"]["error"] == "egress_blocked":
            validate(fx["response"]["details"]["decision"], "egress_block.decision")
    else:
        validate(fx["response"], ep["response"])


@pytest.mark.parametrize("path", sorted((FIXTURES / "audit_events").glob("*.json")), ids=lambda p: p.stem)
def test_audit_event_fixture(path):
    validate(json.loads(path.read_text()), "audit_event")


def test_audit_event_requires_type_specific_data():
    bad = {"v": 1, "log_id": "audit", "seq": 1, "ts": "2026-10-19T12:00:00Z", "type": "execution",
           "actor": "executor", "subject_id": "tx_1", "data": {"tx_id": "tx_1"}}
    with pytest.raises(jsonschema.ValidationError):
        validate(bad, "audit_event")


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
            assert len(text.split("\n")) == ch["line_count"] <= R.MAX_LINES
            assert all(len(l) <= ch["width"] for l in text.split("\n"))
            assert f"n:{ch['nonce']}" in text
    assert n >= 5
