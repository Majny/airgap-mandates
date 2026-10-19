"""F-AMOUNT-DOC: proposal invoice vs the document named by invoice_ref (executor.docs.extract). Owner: WS-D."""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from executor.docs import extract
from executor.facts import compute as compute_mod
from executor.facts import inbox
from executor.facts.amount_doc import amount_doc_fact
from executor.store.memory import MemoryStore
from tests.test_tools import RAW as SYNTH_RAW

DATA = Path(__file__).resolve().parents[1] / "data"
EMAILS = DATA / "emails"
MANIFEST = json.loads((EMAILS / "manifest.json").read_text())
VENDORS = {v["vendor_id"]: v for v in json.loads((DATA / "vendors.json").read_text())}
NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
FIELDS = ("vendor_id", "invoice_no", "issue_date", "due_date", "amount_minor", "currency", "vs", "email_id")


def _raw(name: str) -> bytes:
    return (EMAILS / name).read_bytes()


def _attachment(raw: bytes) -> dict:
    return next(d for d in extract.documents(raw) if d["kind"] == "attachment")


def _invoice(manifest_row: dict) -> tuple[dict, bytes]:
    """Proposal invoice from the data/invoices ground truth, invoice_ref = the ISDOC attachment of the email."""
    truth = json.loads((DATA / "invoices" / manifest_row["invoice"]).read_text())
    raw = _raw(manifest_row["file"])
    inv = {k: truth[k] for k in FIELDS if k in truth}
    return {**inv, "invoice_ref": _attachment(raw)["doc_id"], "reason_code": "DUE"}, raw


LEGIT = [r for r in MANIFEST if r["scenario"] == "legit_invoice"]


@pytest.mark.parametrize("row", LEGIT, ids=[r["file"] for r in LEGIT])
def test_legit_fixtures_info(row):
    inv, raw = _invoice(row)
    f = amount_doc_fact(inv, raw, vendor_ico=VENDORS[row["vendor_id"]]["ico"])
    assert (f["severity"], f["display_line"]) == ("INFO", "AMOUNT OK DOC"), f
    assert f["evidence"]["doc_amount_minor"] == inv["amount_minor"] and f["evidence"]["mismatched"] == ""
    assert f["prov"] == f["evidence"]["doc_sha256"] == _attachment(raw)["sha256"]


@pytest.mark.parametrize("row", LEGIT, ids=[r["file"] for r in LEGIT])
def test_legit_fixtures_amount_plus_one_blocks(row):
    inv, raw = _invoice(row)
    f = amount_doc_fact({**inv, "amount_minor": inv["amount_minor"] + 1}, raw,
                        vendor_ico=VENDORS[row["vendor_id"]]["ico"])
    assert (f["severity"], f["display_line"]) == ("BLOCK", "AMOUNT != DOC")


def test_fixture_06_injection():
    """06: the ISDOC amount is the genuine one; the injected IBAN lives in <Note> and is not an amount question."""
    row = next(r for r in MANIFEST if r["file"] == "06_pdf_injection.eml")
    inv, raw = _invoice(row)
    f = amount_doc_fact(inv, raw, vendor_ico="87654321")
    assert (f["severity"], f["display_line"]) == ("INFO", "AMOUNT OK DOC")


# ---------------------------------------------------------------- synthetic ISDOC in the extract.py dialect

SYNTH_DOC = _attachment(SYNTH_RAW)
SYNTH = {"vendor_id": "ven_12345678", "invoice_no": "FV-2026-0412", "invoice_ref": SYNTH_DOC["doc_id"],
         "issue_date": "2026-10-15", "due_date": "2026-10-29", "amount_minor": 1450000, "currency": "CZK",
         "vs": "20260412", "reason_code": "DUE"}


def _f(raw: bytes | None = SYNTH_RAW, ico: str = "12345678", **over):
    return amount_doc_fact({**SYNTH, **over}, raw, vendor_ico=ico)


def test_synthetic_consistent_info():
    f = _f()
    assert (f["id"], f["kind"], f["severity"], f["display_line"]) == ("F-AMOUNT-DOC", "F", "INFO", "AMOUNT OK DOC")
    assert f["evidence"] == {"invoice_amount_minor": 1450000, "doc_amount_minor": 1450000,
                             "doc_sha256": SYNTH_DOC["sha256"], "invoice_ref": SYNTH_DOC["doc_id"],
                             "reason_code": "DUE", "mismatched": ""}
    assert f["prov"] == SYNTH_DOC["sha256"]


def test_amount_higher_blocks():
    f = _f(amount_minor=1450001)
    assert (f["severity"], f["display_line"]) == ("BLOCK", "AMOUNT != DOC") and f["evidence"]["mismatched"] == "amount"


def test_amount_lower_needs_partial():
    f = _f(amount_minor=1000000)
    assert f["severity"] == "BLOCK" and f["evidence"]["mismatched"] == "amount"
    f = _f(amount_minor=1000000, reason_code="PARTIAL")
    assert (f["severity"], f["display_line"]) == ("INFO", "AMOUNT PART DOC")
    assert f["evidence"]["reason_code"] == "PARTIAL"


@pytest.mark.parametrize("over,ico,field", [({"vs": "99999999"}, "12345678", "vs"),
                                            ({"currency": "EUR"}, "12345678", "currency"), ({}, "87654321", "ico"),
                                            ({"due_date": "2026-11-30"}, "12345678", "due_date"),
                                            ({"invoice_no": "FV-OTHER"}, "12345678", "invoice_no")])
def test_field_mismatch_blocks(over, ico, field):
    f = _f(ico=ico, **over)
    assert (f["severity"], f["display_line"]) == ("BLOCK", "AMOUNT != DOC")
    assert f["evidence"]["mismatched"] == field


def test_mismatched_is_sorted_and_deduplicated():
    f = _f(ico="87654321", amount_minor=1450001, vs="1")
    assert f["evidence"]["mismatched"] == "amount,ico,vs"


@pytest.mark.parametrize("raw", [None, b""])
def test_no_raw_email_blocks(raw):
    f = _f(raw=raw)
    assert (f["severity"], f["display_line"]) == ("BLOCK", "AMOUNT DOC N/A") and "prov" not in f
    assert f["evidence"]["doc_sha256"] is None and f["evidence"]["doc_amount_minor"] is None


def test_unresolved_invoice_ref_blocks():
    f = _f(invoice_ref="doc_0000000000000000")
    assert (f["severity"], f["display_line"]) == ("BLOCK", "AMOUNT DOC N/A") and f["evidence"]["doc_sha256"] is None
    assert _f(invoice_ref=None)["severity"] == "BLOCK"


def test_body_without_amount_blocks_doc_missing():
    body = next(d for d in extract.documents(_raw("05_takeover_acme_real_domain.eml")))
    f = amount_doc_fact({**SYNTH, "invoice_ref": body["doc_id"]}, _raw("05_takeover_acme_real_domain.eml"),
                        vendor_ico="12345678")
    assert (f["severity"], f["display_line"]) == ("BLOCK", "AMOUNT DOC N/A") and f["evidence"]["mismatched"] == ""


def test_extraction_error_fails_closed(monkeypatch):
    def boom(doc):
        raise RuntimeError("parser exploded")

    monkeypatch.setattr(extract, "extract_draft", boom)
    f = _f()
    assert f["severity"] == "BLOCK" and f["evidence"]["doc_sha256"] == SYNTH_DOC["sha256"]


def test_garbage_raw_blocks():
    assert _f(raw=b"\x00\xff not an email")["severity"] == "BLOCK"


def test_evidence_is_json_scalars_only():
    for f in (_f(), _f(raw=None), _f(amount_minor=1)):
        assert all(v is None or isinstance(v, (int, str)) for v in f["evidence"].values())


# ---------------------------------------------------------------- compute() wiring + inbox.email_state


def _payee() -> dict:
    return dict(VENDORS["ven_12345678"], vendor_id="ven_12345678")


def _amount_facts(state: dict) -> list[dict]:
    fs = compute_mod.compute({"kind": "proposal", "subject_id": "prp_1", "invoice": SYNTH, "hints": []},
                             {"payee": _payee(), **state}, NOW)
    return [f for f in fs["facts"] if f["id"] == "F-AMOUNT-DOC"]


def test_compute_always_emits_for_proposals_and_blocks_without_email_raw():
    """FACTS-1: F-AMOUNT-DOC is computed for every proposal; no source email (state without email_raw, or None)
    is BLOCK 'AMOUNT DOC N/A' (fail closed), the cited document is INFO."""
    for state in ({}, {"email_raw": None}):
        (f,) = _amount_facts(state)
        assert (f["severity"], f["display_line"]) == ("BLOCK", "AMOUNT DOC N/A"), (state, f)
    assert [(f["severity"], f["display_line"]) for f in _amount_facts({"email_raw": SYNTH_RAW})] == [
        ("INFO", "AMOUNT OK DOC")]


def test_compute_change_never_emits():
    fs = compute_mod.compute({"kind": "change", "subject_id": "chg_1", "new_iban": "CZ2003000000002001234567"},
                             {"payee": _payee(), "email_raw": None}, NOW)
    assert not any(f["id"] == "F-AMOUNT-DOC" for f in fs["facts"])


def test_email_state_reads_inline_raw():
    from executor.config import Settings

    store = MemoryStore(Settings(backend="memory"))
    store.put("inbox", {"email_id": "eml_x", "from_domain": "acme.cz", "received_at": "2026-10-19T07:00:00Z",
                        "raw_b64": base64.b64encode(SYNTH_RAW).decode()})
    st = inbox.email_state("eml_x", store=store)
    assert st["email_raw"] == SYNTH_RAW and st["email"]["email_id"] == "eml_x"
    assert inbox.email_state(None, store=store)["email_raw"] is None
    assert inbox.email_state("eml_missing", store=store)["email_raw"] is None
