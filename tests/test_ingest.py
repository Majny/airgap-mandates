"""POST /ingest (executor.facts.dkim.ingest) + GET /inbox, /inbox/{id}/raw over the email fixtures. Owner: WS-D."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from executor.config import Settings
from executor.facts import dkim, inbox
from executor.store.memory import MemoryStore
from tests.test_contracts import validate
from tests.wsa_helpers import NOW, Harness

EMAILS = Path(__file__).resolve().parents[1] / "data" / "emails"
MANIFEST = json.loads((EMAILS / "manifest.json").read_text())


def _raw(name: str) -> bytes:
    return (EMAILS / name).read_bytes()


def _ingest(h: Harness, raw: bytes, **extra) -> tuple[int, dict]:
    return h.call("POST", "/ingest", {"raw_b64": base64.b64encode(raw).decode(), **extra}, "ingest")


def _ingest_leaves(h: Harness) -> list[dict]:
    return [x for x in h.leaves() if x["type"] == "ingest"]


@pytest.mark.parametrize("row", MANIFEST, ids=[r["file"] for r in MANIFEST])
def test_fixture_ingests_with_manifest_verdict(row):
    h = Harness()
    st, r = _ingest(h, _raw(row["file"]))
    assert st == 201, r
    validate(r, "ingest.response")
    assert r == {"email_id": row["email_id"], "from_domain": row["from_domain"], "received_at": NOW}
    item = h.store.get("inbox", {"email_id": row["email_id"]})
    expected = row["expected_facts"]["F-DKIM"]
    passed = item["dkim"]["result"] == "pass" and item["dkim"]["aligned"] is True
    assert passed is (expected == "DKIM PASS"), item["dkim"]
    assert item["s3_key"] == f"inbox-raw/{row['email_id']}.eml"
    assert item["sha256"] == dkim._util.sha256_hex(_raw(row["file"]))
    assert (item["gsi1pk"], item["gsi1sk"]) == (f"domain#{row['from_domain']}", NOW)
    assert item["from_addr"].endswith("@" + row["from_domain"]) and item["subject"]
    [leaf] = _ingest_leaves(h)
    assert leaf["actor"] == "ingest" and leaf["subject_id"] == row["email_id"]
    assert leaf["data"] == {"email_id": row["email_id"], "sha256": item["sha256"], "from_domain": row["from_domain"],
                            "received_at": NOW, "dkim": item["dkim"]}
    validate(leaf, "audit_event")


def test_all_fixtures_listed_and_raw_round_trips():
    h = Harness()
    for i, row in enumerate(MANIFEST):
        st, _ = _ingest(h, _raw(row["file"]), received_at=f"2026-10-19T0{i}:00:00Z")
        assert st == 201
    st, r = h.call("GET", "/inbox", principal="tools")
    assert st == 200
    validate(r, "inbox_list.response")
    assert [e["email_id"] for e in r["emails"]] == [row["email_id"] for row in reversed(MANIFEST)]
    for row in MANIFEST:
        st, body = h.call("GET", f"/inbox/{row['email_id']}/raw", principal="tools")
        assert st == 200 and bytes(body) == _raw(row["file"]) and body.content_type == "message/rfc822"


def test_reingest_is_idempotent():
    h = Harness()
    raw = _raw("01_acme_invoice_legit.eml")
    first = _ingest(h, raw, received_at="2026-10-18T08:00:00Z")
    again = _ingest(h, raw, received_at="2026-10-19T09:00:00Z")
    assert first == again and first[1]["received_at"] == "2026-10-18T08:00:00Z"
    assert len(h.store.scan("inbox")) == 1 and len(_ingest_leaves(h)) == 1


def test_received_at_override_ignored_on_aws(monkeypatch):
    s = Settings(backend="aws", fake_now=NOW)
    store = MemoryStore(Settings(backend="memory"))
    puts: list[dict] = []
    monkeypatch.setattr(dkim, "_put_raw", lambda email_id, raw, *, settings: puts.append({"id": email_id}))
    raw = _raw("02_beta_invoice_legit.eml")
    r = dkim.ingest({"raw_b64": base64.b64encode(raw).decode(), "received_at": "2020-01-01T00:00:00Z"},
                    store=store, settings=s)
    assert r["received_at"] != "2020-01-01T00:00:00Z"  # executor clock (fake_now is ignored on aws as well)
    item = store.get("inbox", {"email_id": r["email_id"]})
    assert "raw_b64" not in item and puts == [{"id": r["email_id"]}]


def test_bad_base64_and_wrong_caller():
    h = Harness()
    st, r = h.call("POST", "/ingest", {"raw_b64": "AAA"}, "ingest")
    assert st == 400 and r["error"] == "invalid_request"
    st, r = h.call("POST", "/ingest", {"raw_b64": "not base64!"}, "ingest")
    assert st == 400
    st, r = h.call("POST", "/ingest", {"raw_b64": base64.b64encode(b"x").decode()}, "agent")
    assert st == 403


def test_email_state_after_ingest_carries_raw():
    h = Harness()
    raw = _raw("03_gamma_invoice_legit.eml")
    _, r = _ingest(h, raw)
    st = inbox.email_state(r["email_id"], store=h.store, settings=h.settings)
    assert st["email_raw"] == raw and st["email"]["dkim"]["result"] == "pass"
    assert st["domain_first_seen"] == NOW
