"""Mock ledger execution + pain.001 rail (CONTRACTS v2 §3.2, §4.1 #23). Owner: WS-A."""
from __future__ import annotations

import json

import pytest
from lxml import etree

from executor.bank import ledger
from executor.config import Settings
from executor.errors import ApiError
from executor.rail import submit as rail
from executor.rail.pain001 import DEBTOR, NS, build_pain001, format_amount
from executor.store import get_store

S = Settings(backend="memory", fake_now="2026-10-19T10:00:00Z")


def _proposal(pid="prp_1", amount=123_456, vs="2026001"):
    inv = {"vendor_id": "v1", "invoice_no": "F1", "invoice_ref": "r", "issue_date": "2026-10-01",
           "amount_minor": amount, "currency": "CZK", "reason_code": "SERVICES"}
    if vs:
        inv["vs"] = vs
    return {"proposal_id": pid, "vendor_id": "v1", "invoice": inv, "iban": "CZ6508000000192000145399"}


def _setup():
    store = get_store(S)
    store.put("registry", {"vendor_id": "v1", "name": "ACME DEMO S.R.O.", "iban": "CZ6508000000192000145399"})
    store.put("mandates", {"mandate_id": "mdt_1", "status": "ACTIVE", "spent_minor": 0, "count": 0,
                           "max_total_minor": 1_000_000, "max_count": 5, "mandate_no": 1})
    return store


def _execute(store, pid="prp_1"):
    mandate = store.get("mandates", {"mandate_id": "mdt_1"})
    return ledger.execute(_proposal(pid), {"kind": "mandate", "mandate_id": "mdt_1"}, store=store, settings=S,
                          mandate=mandate, leaf_extra={"policy_hash": "ph"})


def test_tx_id_vector():
    assert ledger.tx_id_for("mdt_1", "prp_1") == "tx_cca460dd70da8f61"


def test_amount_format():
    assert [format_amount(a) for a in (0, 5, 100, 123456)] == ["0.00", "0.05", "1.00", "1234.56"]


def test_execute_and_idempotent():
    store = _setup()
    tx = _execute(store)
    assert tx["tx_id"] == ledger.tx_id_for("mdt_1", "prp_1") and tx["seq"] == 0
    assert tx["rail"] == {"status": "PENDING", "xml_c14n_sha256": None} and tx["vs"] == "2026001"
    leaf = json.loads(store.get("audit", {"log_id": "audit", "seq": 0})["event"])
    assert leaf["type"] == "execution" and leaf["data"]["tx_id"] == tx["tx_id"] and leaf["policy_hash"] == "ph"
    again = _execute(store)
    assert again == store.get("ledger", {"tx_id": tx["tx_id"]})
    assert store.get("mandates", {"mandate_id": "mdt_1"})["count"] == 1


def test_pain001_structure_and_deterministic_hash():
    store = _setup()
    tx = _execute(store)
    row = {**tx, "creditor_name": "ACME DEMO S.R.O."}
    xml, h = build_pain001(row, debtor=DEBTOR, msg_id="AG1-" + tx["tx_id"])
    xml2, h2 = build_pain001(row, debtor=DEBTOR, msg_id="AG1-" + tx["tx_id"])
    assert (xml, h) == (xml2, h2) and len(h) == 64
    root = etree.fromstring(xml.encode())
    ns = {"p": NS}

    def t(path):
        return root.findtext(path, namespaces=ns)

    assert t("p:CstmrCdtTrfInitn/p:GrpHdr/p:MsgId") == "AG1-" + tx["tx_id"]
    assert t("p:CstmrCdtTrfInitn/p:GrpHdr/p:NbOfTxs") == "1"
    assert t("p:CstmrCdtTrfInitn/p:GrpHdr/p:CtrlSum") == "1234.56"
    pmt = "p:CstmrCdtTrfInitn/p:PmtInf/"
    assert t(pmt + "p:PmtMtd") == "TRF"
    assert t(pmt + "p:ReqdExctnDt/p:Dt") == "2026-10-19"
    assert t(pmt + "p:DbtrAcct/p:Id/p:IBAN") == DEBTOR["iban"]
    assert t(pmt + "p:DbtrAgt/p:FinInstnId/p:Othr/p:Id") == "NOTPROVIDED"
    cti = pmt + "p:CdtTrfTxInf/"
    assert t(cti + "p:PmtId/p:EndToEndId") == tx["tx_id"]
    amt = root.find(cti + "p:Amt/p:InstdAmt", namespaces=ns)
    assert (amt.text, amt.get("Ccy")) == ("1234.56", "CZK")
    assert t(cti + "p:Cdtr/p:Nm") == "ACME DEMO S.R.O."
    assert t(cti + "p:CdtrAcct/p:Id/p:IBAN") == tx["iban"]
    assert t(cti + "p:RmtInf/p:Strd/p:CdtrRefInf/p:Ref") == "2026001"
    # different msg_id -> different hash; no VS -> Ustrd tx_id
    assert build_pain001(row, debtor=DEBTOR, msg_id="other")[1] != h
    xml3, _ = build_pain001({k: v for k, v in row.items() if k != "vs"}, debtor=DEBTOR, msg_id="m")
    assert etree.fromstring(xml3.encode()).findtext(cti + "p:RmtInf/p:Ustrd", namespaces=ns) == tx["tx_id"]


def test_debtor_iban_valid():
    import schwifty

    schwifty.IBAN(DEBTOR["iban"]).validate()
    assert DEBTOR["iban"][4:8] == "0100"


def test_submit_actc_then_dupl_and_export():
    store = _setup()
    tx = _execute(store)
    r1 = rail.submit(tx, store=store, settings=S)
    assert r1["status"] == "ACTC" and r1["msg_id"] == "AG1-" + tx["tx_id"]
    row = store.get("ledger", {"tx_id": tx["tx_id"]})
    assert row["rail"] == {"status": "ACTC", "xml_c14n_sha256": r1["xml_c14n_sha256"]}
    r2 = rail.submit(tx, store=store, settings=S)
    assert r2["status"] == "DUPL" and r2["xml_c14n_sha256"] == r1["xml_c14n_sha256"]
    assert store.get("ledger", {"tx_id": tx["tx_id"]}) == row
    leaves = [json.loads(i["event"]) for i in store.query("audit", ("log_id", "audit")) if "event" in i]
    assert [(e["type"], e["data"].get("status")) for e in leaves] == [
        ("execution", None), ("rail_submitted", "ACTC"), ("rail_submitted", "DUPL")]
    assert leaves[1]["data"]["format"] == "pain.001.001.09"
    exp = rail.pain001_export(tx["tx_id"], store=store, settings=S)
    assert exp["xml_c14n_sha256"] == r1["xml_c14n_sha256"] and "ACME DEMO S.R.O." in exp["xml"]
    with pytest.raises(ApiError) as ei:
        rail.pain001_export("tx_missing", store=store, settings=S)
    assert ei.value.code == "not_found"


def test_recover_unsubmitted():
    store = _setup()
    a = _execute(store, "prp_a")
    b = _execute(store, "prp_b")
    rail.submit(a, store=store, settings=S)
    assert rail.recover_unsubmitted(store=store, settings=S) == [b["tx_id"]]
    assert store.get("ledger", {"tx_id": b["tx_id"]})["rail"]["status"] == "ACTC"
    assert rail.recover_unsubmitted(store=store, settings=S) == []
