"""WS-D fail-open regressions (review findings CHG-3, FACTS-1, FACTS-2, FACTS-4, FACTS-6, FACTS-7).

Each test reproduces a confirmed fail-open path and pins the fail-closed behaviour. Owner: WS-D.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from executor.config import Settings, iso
from executor.facts import anom, compute, sanction, vop, warnlist
from executor.facts import mostlyright as mr
from executor.store.memory import MemoryStore
from executor.facts._util import digest as _digest
from tests.test_wsd_scenarios import ACME, NEW_IBAN, T0, World, _facts
from tools import load_mostlyright as lm
from tools import seed_data

MR_DB = Path("data/mostlyright/snapshot.sqlite")
NOW = datetime(2026, 10, 19, 10, 0, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------------- CHG-3 same-day activation


def _activate(w: World, cid: str) -> None:
    w.submit_vc(cid, w.vc("supplier-erp", w.store.get("changes", {"change_id": cid})))
    w.submit_vc(cid, w.vc("supplier-bank", w.store.get("changes", {"change_id": cid})), principal="vendor_portal")
    w.tick(w.settings.cooling_seconds + 1)
    c = w.get(cid)
    st_, r = w.sign(c["pending_challenge"], w.clerk)
    assert st_ == 200, r
    st_, r = w.sign(r["challenge"], w.treasury)
    assert st_ == 200 and r["effect"]["state"] == "ACTIVE", r


def test_chg3_iban_activated_after_mandate_same_day_is_outside_its_registry_snapshot():
    w = World()
    m = w.mandate()  # pins the registry snapshot at 12:00:00Z
    st_, r = w.change(ACME, NEW_IBAN, email_key="08")
    assert st_ == 201, r
    cid = r["change"]["change_id"]
    w.tick(5)
    _activate(w, cid)  # ACTIVE the same day, after the mandate was signed
    hist = w.store.get("registry", {"vendor_id": ACME})["iban_history"]
    new, old = hist[-1], hist[-2]
    assert new["iban"] == NEW_IBAN and new["change_id"] == cid
    # full ISO timestamps, never a bare date that sorts before a same-day mandate.created_at
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z", new["from"]), new
    assert new["from"] > m["created_at"] and old["to"] == new["from"]
    st_, p = w.propose("acme_fv-2026-0412", with_email=True)
    assert st_ == 201, p
    assert "I-REGISTRY" in p["decision"]["rule_ids"], p["decision"]  # payee_scope existing_only: not in the snapshot
    assert p["decision"]["decision"] != "allow" and p["tx"] is None


# --------------------------------------------------------------------------- FACTS-1 proposal without a source email

def test_facts1_proposal_without_email_id_is_denied():
    w = World()
    w.mandate()
    st_, p = w.propose("acme_fv-2026-0412", with_email=False, invoice_no="FV-FAKE-9999", amount_minor=7_777_700,
                       invoice_ref="doc_" + hashlib.sha256(b"nonexistent").hexdigest()[:16])
    assert st_ == 201, p
    f = _facts(p["proposal"]["facts"])
    assert f["F-AMOUNT-DOC"] == ("BLOCK", "AMOUNT DOC N/A"), f
    assert f["F-DKIM"] == ("BLOCK", "DKIM FAIL"), f
    assert p["decision"]["decision"] == "deny" and "I-AMOUNT" in p["decision"]["rule_ids"], p["decision"]
    assert p["tx"] is None and w.call("GET", "/ledger")[1]["txs"] == []


def test_facts1_compute_proposal_without_email_state_blocks():
    from executor.facts import compute

    payee = {"vendor_id": ACME, "name": "ACME s.r.o.", "ico": "12345678", "iban": "CZ6508000000192000145399",
             "domain": "acme.cz", "country": "CZ", "iban_history": []}
    inv = {"vendor_id": ACME, "invoice_no": "X-1", "issue_date": "2026-10-15", "amount_minor": 100, "currency": "CZK",
           "invoice_ref": "doc_0000000000000000", "reason_code": "DUE"}
    fs = compute.compute({"kind": "proposal", "subject_id": "prp_x", "invoice": inv},
                         {"payee": payee, "data_dir": "data", "mandate": None, "proposals": [], "history": []}, NOW)
    f = _facts(fs["facts"])
    assert f["F-AMOUNT-DOC"] == ("BLOCK", "AMOUNT DOC N/A") and f["F-DKIM"] == ("BLOCK", "DKIM FAIL"), f


def test_facts1_invoice_ref_of_another_emails_document_is_denied():
    """A real, DKIM-valid source email does not vouch for a document it does not carry: email_id of 01 (ACME's
    FV-2026-0412) with invoice_ref = the ISDOC attachment of 02 (Beta's email) is denied."""
    import base64

    from executor.docs import extract

    w = World()
    w.mandate()
    raw02 = base64.b64decode(w.store.get("inbox", {"email_id": w.emails["02"]})["raw_b64"])
    other_doc = next(x for x in extract.documents(raw02) if x["kind"] == "attachment")["doc_id"]
    st_, ok = w.propose("acme_fv-2026-0412", with_email=True)  # control: its own document is allowed
    assert st_ == 201 and ok["decision"]["decision"] == "allow", ok["decision"]
    st_, p = w.propose("acme_fv-2026-0412", with_email=True, invoice_no="FV-2026-0412-B", invoice_ref=other_doc)
    assert st_ == 201, p
    f = _facts(p["proposal"]["facts"])
    assert f["F-DKIM"] == ("INFO", "DKIM PASS"), f  # the cited email itself is genuine
    assert f["F-AMOUNT-DOC"] == ("BLOCK", "AMOUNT DOC N/A"), f
    assert p["decision"]["decision"] == "deny" and "F-AMOUNT-DOC" in p["decision"]["rule_ids"], p["decision"]
    assert p["tx"] is None and len(w.call("GET", "/ledger")[1]["txs"]) == 1


# --------------------------------------------------------------------------- FACTS-2 F-ANOM over the tool-call log


def _rows(*calls: tuple[int, str, bool], session: str = "ses_t", at: str = "2026-10-19T10:00:00Z") -> list[dict]:
    """tool_calls rows exactly as executor/tools/handler.py stores them (sk / at, no step / ts)."""
    return [{"session_id": session, "sk": f"{step:06d}", "tool": tool, "args_sha256": "0" * 64, "result": "ok",
             "rule_ids": [], "untrusted_read": untrusted, "seq": step, "at": at} for step, tool, untrusted in calls]


def test_facts2_anom_reads_tool_calls_rows_as_stored():
    rows = _rows((1, "inbox.read", True), (2, "invoice.extract", False), (3, "payment.propose", False))
    f = anom.anom_fact({}, rows, payee={}, mandate=None, now=NOW)
    assert f["severity"] == "WARN" and "untrusted_read_before_action" in f["evidence"]["features"], f
    assert f["display_line"] == "ANOM 40/100"


def test_facts2_anom_burst_reads_at_timestamps():
    rows = [{**r, "at": f"2026-10-19T10:00:{i:02d}Z"}
            for i, r in enumerate(_rows(*[(i + 1, "payment.propose", False) for i in range(6)]))]
    assert "proposal_burst" in anom.features({}, rows, mandate=None, now=NOW)


def test_facts2_session_log_appends_in_flight_action():
    store = MemoryStore(Settings(backend="memory"))
    for r in _rows((1, "inbox.read", True)):
        store.put("tool_calls", r)
    log = anom.session_log("ses_t", store=store, action="payment.propose", step=2, now=NOW)
    assert [(r["step"], r["tool"]) for r in log] == [(1, "inbox.read"), (2, "payment.propose")]
    assert log[-1]["ts"] == iso(NOW)
    f = anom.anom_fact({}, log, payee={}, mandate=None, now=NOW)
    assert f["severity"] == "WARN" and f["evidence"]["tool_calls"] == 2


def test_facts2_change_facts_take_the_tool_log():
    from executor.change import machine

    w = World()
    vendor = w.store.get("registry", {"vendor_id": ACME})
    log = anom.normalize_log(_rows((1, "inbox.read", True), (2, "payee.request_change", False)))
    fs = machine.compute_change_facts({"vendor_id": ACME, "new_iban": NEW_IBAN}, vendor, store=w.store,
                                      settings=w.settings, now=w.now, tool_log=log)
    assert _facts(fs["facts"])["F-ANOM"][0] == "WARN"


@pytest.mark.xfail(strict=True, reason="needs WS-A/WS-E wiring: the executor must pass the session tool log "
                                       "(anom.session_log) into compute() for POST /proposals and /changes")
def test_facts2_e2e_untrusted_read_then_propose_steps_up():
    from tests.test_tools import ToolHarness, _isdoc_doc_id, _propose_args

    h = ToolHarness()
    h.mandate()
    st_, r = h.tool("inbox.read", {"email_id": "eml_0000"})  # an untrusted email that is NOT the cited source
    assert st_ == 200, r
    doc_id = _isdoc_doc_id(h)  # reads the cited source eml_0001 (not taint)
    st_, r = h.tool("payment.propose", _propose_args(doc_id))
    assert st_ == 200, r
    (p,) = h.store.scan("proposals")
    a = next(f for f in p["facts"] if f["id"] == "F-ANOM")
    assert a["severity"] == "WARN" and "untrusted_read_before_action" in a["evidence"]["features"]
    assert r["result"]["decision"] == "challenge"


# --------------------------------------------------------------------------- FACTS-4 malformed sanctions rows


@pytest.mark.parametrize("name", ["CJSC TECHNOSVYAZ", "Advanced Systems Technologies", "LLC TEXTILTECHSNAB",
                                  "Concernul pentru tehnologii radioelectronice KRET SA",
                                  "La sociedad de responsabilidad limitada Neftegazpromstroy"])
def test_facts4_shipped_snapshot_sanction_rows_are_matchable(name):
    # the four rows the old loader stored with record_ok = 0, plus one it swallowed whole ('AO AST' itself is under
    # the 5-char floor, so its alias is used)
    f = sanction.sanction_fact(name, "", mr_path=MR_DB)
    assert (f["severity"], f["display_line"]) == ("BLOCK", "EU SANCTION HIT"), f


def test_facts4_shipped_snapshot_keeps_records_after_a_stray_quote():
    """Warnings that used to be swallowed into the preceding malformed sanctions record are their own rows."""
    assert mr.warning_domain_hit("top-placements-hyip.com", mr_path=MR_DB) is not None
    assert mr.warning_domain_hit("capitalnvst.com", mr_path=MR_DB) is not None
    f = warnlist.warnlist_fact("Some Payee s.r.o.", ["igm-markets.com"], mr_path=MR_DB)
    assert f["severity"] == "BLOCK", f


_HEAD = ",".join(lm.COLUMNS)


def _line(record_id: str, record_type: str, source: str, name: str, other: str, national_id: str = "") -> str:
    vals = dict.fromkeys(lm.COLUMNS, "")
    vals.update(record_id=record_id, record_type=record_type, source_list=source, authority="European Commission",
                name=name, other_names=other, national_id=national_id, country="RU", since="2026-07-23")
    buf = io.StringIO()
    csv.writer(buf, lineterminator="\n").writerow([vals[c] for c in lm.COLUMNS])
    return buf.getvalue()


def _build(tmp_path: Path, body: str) -> Path:
    raw = (_HEAD + "\n" + body).encode("latin-1")
    records = lm.parse_csv(raw)
    dest = tmp_path / "snapshot.sqlite"
    lm.build_sqlite(records, dest, {"loader_version": lm.LOADER_VERSION})
    return dest


def test_facts4_loader_stray_quote_never_swallows_records_and_every_sanction_is_queryable(tmp_path):
    a, b, c = "a" * 32, "b" * 32, "c" * 32
    # other_names with lost Cyrillic letters: a bare '"' (U+0422 low byte) and a ',' (U+042C) inside a quoted field
    broken = (f'{a},sanction,eu_financial_sanctions,European Commission,,LLC TEXTILTECHSNAB,'
              f'LLC TEXTILTECHSNAB | TEXTILTECHSNAB S.R.L. | \x1e\x1e\x1e "\x15\x1a!"\x18\x1b,"\x15%!\x1d\x10\x11,'
              f'RU,,,,EU.14574.4,,,,,,,UKR,,,,2026-07-23,,,,,,,,,,3,https://eur-lex.europa.eu/x\n')
    body = (broken + _line(b, "warning", "amf_blacklists", "evil-broker.example", "")
            + _line(c, "sanction", "eu_financial_sanctions", "Krasnaya Zvezda Trading OOO", "KZT", "77001234"))
    db = _build(tmp_path, body)
    conn = sqlite3.connect(db)
    ids = {r[0] for r in conn.execute("SELECT record_id FROM records")}
    conn.close()
    assert ids == {a, b, c}  # nothing swallowed
    raw_heads = re.findall(r"(?m)^([0-9a-f]{32}),sanction,", body)
    for rid in raw_heads:  # every sanctions row of the source is queryable by name
        row = sqlite3.connect(db).execute("SELECT name FROM records WHERE record_id = ?", (rid,)).fetchone()
        assert sanction.sanction_fact(row[0], "", mr_path=db)["severity"] == "BLOCK", rid
    assert sanction.sanction_fact("Unrelated Name s.r.o.", "77001234", mr_path=db)["severity"] == "BLOCK"


def test_facts4_unparseable_sanction_row_still_matches_by_name_and_nid(tmp_path):
    a = "d" * 32
    # far too few fields even after every repair: record_ok stays 0, but the row is a sanction and must match
    body = f'{a},sanction,eu_financial_sanctions,European Commission,,Garbled Holding JSC,"Garbled Alias | x\n'
    db = _build(tmp_path, body)
    (ok,) = sqlite3.connect(db).execute("SELECT record_ok FROM records").fetchone()
    assert ok == 0
    assert sanction.sanction_fact("Garbled Holding JSC", "", mr_path=db)["severity"] == "BLOCK"


def test_facts4_unclassified_rows_make_sanctions_and_warnlist_not_clear(tmp_path):
    # a row whose record_type is unreadable could be a lost sanctions entry: never report CLEAR on such a snapshot
    body = _line("e" * 32, "licence", "cnb_banks", "Some Bank a.s.", "") + "garbage,,row\n"
    db = _build(tmp_path, body)
    assert sqlite3.connect(db).execute("SELECT count(*) FROM records WHERE record_ok = 0").fetchone()[0] == 1
    s = sanction.sanction_fact("ACME s.r.o.", "12345678", mr_path=db)
    w = warnlist.warnlist_fact("ACME s.r.o.", ["acme.cz"], mr_path=db)
    assert (s["severity"], s["display_line"]) == ("WARN", "SANCTIONS N/A"), s
    assert (w["severity"], w["display_line"]) == ("WARN", "WARNLIST N/A"), w


def test_facts4_shipped_snapshot_is_complete():
    """The shipped snapshot has no unclassified rows (otherwise every payment would step up)."""
    assert mr.unclassified_rows(MR_DB) == 0
    src = sorted(Path("data/mostlyright").glob("*.csv"))
    if not src:
        pytest.skip("raw MostlyRight CSV not present")
    text = src[-1].read_bytes().decode("latin-1")
    heads = set(re.findall(r"(?m)^([0-9a-f]{32}),(?:licence|warning|sanction|payment_scheme),", text))
    conn = sqlite3.connect(MR_DB)
    assert heads <= {r[0] for r in conn.execute("SELECT record_id FROM records")}


# --------------------------------------------------------------------------- FACTS-6 VoP legal forms


@pytest.mark.parametrize("holder", ["ACME a.s.", "ACME GmbH", "Acme Ltd.", "ACME SE", "A.C.M.E. s.r.o.", "ACME"])
def test_facts6_different_legal_form_is_cmtc_not_mtch(holder):
    code, _ = vop.match_code("ACME s.r.o.", holder)
    assert code == "CMTC", (holder, code)


@pytest.mark.parametrize("holder", ["ACME s.r.o.", "ACME sro", "ACME, spol. s r.o.", "Acme S.R.O.", "ACME  s. r. o.",
                                    "ACME, s.r.o."])
def test_facts6_same_legal_form_is_mtch(holder):
    assert vop.match_code("ACME s.r.o.", holder) == ("MTCH", 100), holder


def test_facts6_diacritics_and_case_still_mtch():
    assert vop.match_code("Gamma Tisk a.s.", "GAMMA TISK, a. s.")[0] == "MTCH"
    assert vop.match_code("Beta Servis s.r.o.", "Béta Servis s.r.o.")[0] == "MTCH"


# --------------------------------------------------------------------------- FACTS-7 received_at from the Date header


_BACKDATED = (b"From: billing@acme-faktury.cz\r\nTo: ap@airgap.example\r\nSubject: x\r\n"
              b"Date: Mon, 01 Jan 2024 09:00:00 +0000\r\n\r\nhello\r\n")


def test_facts7_seed_inbox_ignores_sender_date_header(tmp_path):
    (tmp_path / "x.eml").write_bytes(_BACKDATED)
    settings = Settings(backend="memory", fake_now=iso(NOW), data_dir=str(Path("data").resolve()))
    store = MemoryStore(settings)
    assert seed_data.seed_inbox(tmp_path, store=store, settings=settings, now=NOW) == 1
    (row,) = store.scan("inbox")
    assert row["received_at"] == iso(NOW), row["received_at"]
    assert seed_data.inbox_row(_BACKDATED, now=NOW)["received_at"] == iso(NOW)


def test_facts7_seed_inbox_uses_manifest_fixture_timestamp(tmp_path):
    (tmp_path / "x.eml").write_bytes(_BACKDATED)
    (tmp_path / "manifest.json").write_text(json.dumps([{"file": "x.eml", "received_at": "2026-10-05T08:00:00Z"}]))
    settings = Settings(backend="memory", fake_now=iso(NOW), data_dir=str(Path("data").resolve()))
    store = MemoryStore(settings)
    seed_data.seed_inbox(tmp_path, store=store, settings=settings, now=NOW)
    (row,) = store.scan("inbox")
    assert row["received_at"] == "2026-10-05T08:00:00Z"
    # a fixture time in the future of the seeding clock is clamped to it
    assert seed_data.fixture_received_at(tmp_path / "x.eml", NOW - timedelta(days=30)) == iso(NOW - timedelta(days=30))


def test_facts7_shipped_fixtures_carry_received_at():
    manifest = json.loads(Path("data/emails/manifest.json").read_text())
    assert {m["file"] for m in manifest} == {p.name for p in Path("data/emails").glob("*.eml")}
    assert all(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", m["received_at"]) for m in manifest)



def test_facts2_change_create_takes_the_tool_log_and_anom_never_drops_on_recompute():
    """machine.create(tool_log=...) feeds F-ANOM; a later recompute (VC received, R0 recheck) has no session log and
    must not lower it (F-ANOM only escalates)."""
    from executor.change import machine

    w = World()
    vendor = w.store.get("registry", {"vendor_id": ACME})
    log = anom.normalize_log(_rows((1, "inbox.read", True), (2, "payee.request_change", False)))
    empty = {"facts": [], "facts_digest": "", "snapshots": {}, "max_severity": "INFO"}
    c = machine.create({"vendor_id": ACME, "new_iban": NEW_IBAN}, empty, vendor, store=w.store, settings=w.settings,
                       now=w.now, tool_log=log)
    assert _facts(c["facts"])["F-ANOM"][0] == "WARN" and c["state"] == "PENDING_ATTEST"
    fs = machine._recompute(c, store=w.store, settings=w.settings, now=w.now)
    assert _facts(fs["facts"])["F-ANOM"][0] == "WARN" and _facts(c["facts"])["F-ANOM"][0] == "WARN"
    assert fs["facts_digest"] == compute.facts_digest(fs["facts"])


# --------------------------------------------------------------------------- FACTS-2 decision (b): cited source is not taint


def _session(w: World, sid: str, *reads: tuple[str, dict]) -> int:
    """tool_calls rows exactly as the tools λ stores them (args hashed); returns the next step."""
    for i, (tool, args) in enumerate(reads, 1):
        w.store.put("tool_calls", {"session_id": sid, "sk": f"{i:06d}", "tool": tool, "args_sha256": _digest(args),
                                   "result": "ok", "rule_ids": [], "untrusted_read": True, "at": iso(w.now)})
    return len(reads) + 1


def _cited(w: World, invoice_no: str, amount_minor: int) -> dict:
    from tools import invoice_mail

    inv = {"vendor_id": ACME, "invoice_no": invoice_no, "issue_date": "2026-10-15", "amount_minor": amount_minor,
           "currency": "CZK", "vs": invoice_no[-4:], "reason_code": "DUE"}
    raw = invoice_mail.invoice_email(inv, data_dir=w.settings.data_dir)
    st_, r = w.call("POST", "/ingest", invoice_mail.ingest_body(raw), "ingest")
    assert st_ == 201, r
    return invoice_mail.cite(inv, raw, r["email_id"])


def _propose(w: World, inv: dict, sid: str, step: int) -> dict:
    st_, r = w.call("POST", "/proposals", {"invoice": inv, "hints": [], "session_id": sid, "step": step}, "tools")
    assert st_ == 201, r
    return r


def test_facts2b_reading_the_cited_source_is_not_taint_and_s1_allows():
    w = World()
    w.mandate()
    inv = _cited(w, "FV-ANOM-0001", 1_450_000)
    step = _session(w, "s-cited", ("inbox.read", {"email_id": inv["email_id"]}),
                    ("invoice.extract", {"doc_id": inv["invoice_ref"]}))
    r = _propose(w, inv, "s-cited", step)
    anom_f = _facts(r["proposal"]["facts"])["F-ANOM"]
    assert anom_f[0] == "INFO", anom_f
    assert r["decision"]["decision"] == "allow", r["decision"]


def test_facts2b_reading_another_untrusted_email_before_proposing_steps_up():
    w = World()
    w.mandate()
    inv = _cited(w, "FV-ANOM-0002", 1_450_000)
    step = _session(w, "s-other", ("inbox.read", {"email_id": w.emails["04"]}),  # the lookalike BEC, not the source
                    ("inbox.read", {"email_id": inv["email_id"]}))
    r = _propose(w, inv, "s-other", step)
    (p,) = [x for x in w.store.scan("proposals") if x["proposal_id"] == r["proposal"]["proposal_id"]]
    a = next(f for f in p["facts"] if f["id"] == "F-ANOM")
    assert a["severity"] == "WARN" and "untrusted_read_before_action" in a["evidence"]["features"], a
    assert r["decision"]["decision"] == "challenge" and "I-ANOM" in r["decision"]["rule_ids"], r["decision"]


def test_facts2b_read_with_other_args_still_counts():
    """Only an exact read of the cited source is excused: extra/other args hash differently (fail safe)."""
    cited = anom.cited_source_args(["eml_aaaaaaaaaaaaaaaa"], ["doc_bbbbbbbbbbbbbbbb"])
    rows = [{"session_id": "s", "step": 1, "tool": "inbox.read", "untrusted_read": True,
             "args_sha256": _digest({"email_id": "eml_aaaaaaaaaaaaaaaa", "x": 1})},
            {"session_id": "s", "step": 2, "tool": "payment.propose", "untrusted_read": False}]
    assert "untrusted_read_before_action" in anom.features({}, rows, mandate=None, now=T0, cited=cited)
    rows[0]["args_sha256"] = _digest({"email_id": "eml_aaaaaaaaaaaaaaaa"})
    assert "untrusted_read_before_action" not in anom.features({}, rows, mandate=None, now=T0, cited=cited)
