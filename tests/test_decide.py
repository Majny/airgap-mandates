"""decide() / may_issue_chg_challenge() goldens and tables (CONTRACTS.md v2 §2.2, §8.1). Owner: WS-A."""
from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from executor.policy import invariants as inv
from executor.policy import rules
from executor.policy.facts_wsa import wsa_facts

pytest.importorskip("cedarpy")
from executor.policy.decide import decide, decide_inputs, inputs_digest, may_issue_chg_challenge  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "contracts/fixtures"
POLICY = rules.policy_material()
NOW = "2026-10-19T12:02:00Z"


def _load(rel: str) -> dict:
    return json.loads((FIX / rel).read_text())


def mandate(**over) -> dict:
    m = _load("mandates_active/ok.json")["response"]
    m.update(policy_hash=rules.policy_hash(), spent_minor=0, count=0)
    m.update(over)
    return m


PAYEES = {v["vendor_id"]: v for v in _load("vendors_list/ok.json")["response"]["vendors"]}


def fact(fid, sev, line, kind="F", **evidence) -> dict:
    f = {"id": fid, "kind": kind, "severity": sev, "label": fid, "display_line": line}
    if evidence:
        f["evidence"] = evidence
    return f


def factset(*facts) -> dict:
    return {"subject_id": "prp_1", "computed_at": NOW, "facts": list(facts), "facts_digest": "0" * 64,
            "snapshots": {}, "max_severity": "INFO"}


VOP = fact("F-VOP", "INFO", "VOP MTCH", code="MTCH")


def invoice(**over) -> dict:
    i = {"vendor_id": "ven_12345678", "invoice_no": "FV-2026-0500", "invoice_ref": "doc_1", "issue_date": "2026-10-15",
         "amount_minor": 1_450_000, "currency": "CZK", "reason_code": "DUE"}
    i.update(over)
    return i


def run(inv_over=None, facts=(VOP,), m="default", payee="default", proposals=(), history=(), now=NOW, **st):
    subject = {"proposal_id": "prp_1", "invoice": invoice(**(inv_over or {}))}
    state = {"mandate": mandate() if m == "default" else m,
             "payee": PAYEES[subject["invoice"]["vendor_id"]] if payee == "default" else payee,
             "proposals": list(proposals), "history": list(history), "now": now, **st}
    return decide(subject, factset(*facts), state, POLICY)


def _out(d):
    return d["decision"], d["rule_ids"]


# ---------------------------------------------------------------- fixture goldens

def _fixture_case(name):
    fx = _load(f"proposals_create/{name}.json")
    p, dec = fx["response"]["proposal"], fx["response"]["decision"]
    subject = {"proposal_id": p["proposal_id"], "invoice": fx["request"]["invoice"]}
    facts = {"subject_id": p["proposal_id"], "computed_at": p["created_at"], "facts": p["facts"],
             "facts_digest": dec["facts_digest"], "snapshots": {}, "max_severity": "INFO"}
    spent = next((f["evidence"]["spent_minor"] for f in p["facts"] if f["id"] == "F-MANDATE"), 0)
    prior = _load("proposals_create/allow.json")["response"]["proposal"]
    state = {"mandate": mandate(spent_minor=spent), "payee": PAYEES[subject["invoice"]["vendor_id"]],
             "proposals": [prior] if name == "deny_dup" else [], "history": [], "now": p["created_at"]}
    return subject, facts, state, dec


@pytest.mark.parametrize("name", ["allow", "challenge", "deny_dup", "deny_warnlist_r0"])
def test_fixture_goldens(name):
    subject, facts, state, golden = _fixture_case(name)
    d = decide(subject, facts, state, POLICY)
    assert (d["decision"], d["rule_ids"]) == (golden["decision"], golden["rule_ids"])
    assert d["mandate_id"] == golden["mandate_id"] and d["facts_digest"] == golden["facts_digest"]
    assert d["facts"] == facts["facts"] and d["policy_hash"] == rules.policy_hash() and "challenge" not in d


def test_challenge_fixture_f_mandate_from_wsa_facts():
    subject, facts, state, _ = _fixture_case("challenge")
    got = [f for f in wsa_facts(subject, state, datetime(2026, 10, 19, 12, 2, tzinfo=timezone.utc))]
    want = [f for f in facts["facts"] if f["id"] == "F-MANDATE"]
    assert got == want


# ---------------------------------------------------------------- golden table

W = fact("F-PSP", "WARN", "PSP UNKNOWN")
LEDGER = [{"vendor_id": "ven_12345678", "amount_minor": a, "executed_at": "2026-10-10T10:00:00Z"}
          for a in (1_000_000, 1_010_000, 990_000, 1_020_000, 1_000_000, 980_000)]

TABLE = [
    ("allow", {}, ("allow", [])),
    ("no mandate", dict(m=None), ("challenge", ["I-MANDATE"])),
    ("mandate not active", dict(m=mandate(status="PENDING_SIG_CLERK")), ("challenge", ["I-MANDATE"])),
    ("stale policy_hash", dict(m=mandate(policy_hash="ab" * 32)), ("challenge", ["I-MANDATE"])),
    ("expired", dict(now="2026-10-21T00:00:00Z"), ("challenge", ["I-EXP"])),
    ("not yet valid", dict(now="2026-10-19T09:00:00Z"), ("challenge", ["I-EXP"])),
    ("per payment", dict(inv_over={"amount_minor": 8_000_001}, m=mandate(max_per_payment_minor=8_000_000)),
     ("challenge", ["I-PER", "I-SPLIT"])),
    ("budget", dict(m=mandate(spent_minor=24_000_000)), ("challenge", ["I-BUDGET"])),
    ("count", dict(m=mandate(count=20)), ("challenge", ["I-COUNT"])),
    ("registry", dict(reg_hit=False), ("challenge", ["I-REGISTRY"])),
    ("vop cmtc", dict(facts=(fact("F-VOP", "INFO", "VOP CMTC", code="CMTC"),)), ("challenge", ["I-VOP"])),
    ("vop missing -> NOAP", dict(facts=()), ("challenge", ["I-VOP"])),
    ("vop from display_line", dict(facts=(fact("F-VOP", "INFO", "VOP MTCH"),)), ("allow", [])),
    ("anom", dict(facts=(VOP, fact("F-ANOM", "INFO", "ANOM 40/100", score=40))), ("challenge", ["I-ANOM"])),
    ("anom below", dict(facts=(VOP, fact("F-ANOM", "INFO", "ANOM 39/100", score=39))), ("allow", [])),
    ("split", dict(history=[{"vendor_id": "ven_12345678", "amount_minor": 7_000_000,
                             "executed_at": "2026-10-19T08:00:00Z"}]), ("challenge", ["I-SPLIT"])),
    ("split outside window", dict(history=[{"vendor_id": "ven_12345678", "amount_minor": 7_000_000,
                                            "executed_at": "2026-10-18T12:02:00Z"}]), ("allow", [])),
    ("z", dict(history=LEDGER), ("challenge", ["I-Z"])),
    ("warn", dict(facts=(VOP, W)), ("challenge", ["F-PSP", "I-WARN"])),
    ("payee unknown", dict(payee=None), ("deny", ["I-PAYEE"])),
    ("payee no iban", dict(payee={**PAYEES["ven_12345678"], "iban": ""}), ("deny", ["I-PAYEE"])),
    ("payee inactive", dict(payee={**PAYEES["ven_12345678"], "status": "SUSPENDED"}), ("deny", ["I-PAYEE"])),
    ("dup invoice no", dict(proposals=[{"proposal_id": "prp_0", "status": "EXECUTED",
                                        "invoice": invoice(invoice_no="fv 2026 500", amount_minor=1, issue_date="2025-01-01")}]),
     ("deny", ["I-DUP"])),
    ("dup amount/date", dict(proposals=[{"proposal_id": "prp_0", "status": "PENDING_SIG",
                                         "invoice": invoice(invoice_no="X1", amount_minor=1_443_000,
                                                            issue_date="2026-10-18")}]), ("deny", ["I-DUP"])),
    ("dup ignores DENIED", dict(proposals=[{"proposal_id": "prp_0", "status": "DENIED", "invoice": invoice()}]),
     ("allow", [])),
    ("dup ignores self", dict(proposals=[{"proposal_id": "prp_1", "status": "PENDING_SIG", "invoice": invoice()}]),
     ("allow", [])),
    ("block", dict(facts=(VOP, W, fact("F-WARNLIST", "BLOCK", "WARNLIST HIT"))),
     ("deny", ["F-PSP", "F-WARNLIST", "I-BLOCK"])),
    ("amount != doc", dict(facts=(VOP, fact("F-AMOUNT-DOC", "BLOCK", "AMOUNT != DOC"))),
     ("deny", ["F-AMOUNT-DOC", "I-AMOUNT", "I-BLOCK"])),
    ("amount = doc", dict(facts=(VOP, fact("F-AMOUNT-DOC", "INFO", "AMOUNT = DOC"))), ("allow", [])),
    ("block beats mandate", dict(m=None, facts=(fact("F-VOP", "BLOCK", "VOP NMTC", code="NMTC"),)),
     ("deny", ["F-VOP", "I-BLOCK"])),
]


@pytest.mark.parametrize("case", TABLE, ids=[c[0] for c in TABLE])
def test_golden_table(case):
    _, kw, want = case
    assert _out(run(**kw)) == want


def test_determinism_and_replay():
    kw = dict(facts=(VOP, W, fact("H-AGENT", "INFO", "trust me", kind="H")), history=LEDGER)
    subject = {"proposal_id": "prp_1", "invoice": invoice()}
    facts = factset(*kw["facts"])
    state = {"mandate": mandate(), "payee": PAYEES["ven_12345678"], "proposals": [], "history": LEDGER, "now": NOW}
    a = decide(copy.deepcopy(subject), copy.deepcopy(facts), copy.deepcopy(state), POLICY)
    b = decide(subject, facts, state, rules.policy_material())
    assert a == b and inputs_digest(subject, facts, state) == inputs_digest(subject, facts, state)
    x = decide_inputs(subject, facts, state)
    assert decide_inputs(**x) == x  # idempotent projection
    assert "CZ65" not in json.dumps(x)  # no IBAN in the leaf
    replay = json.loads(json.dumps(x))  # what verify_audit reads back from the leaf
    assert decide(**replay, policy=json.loads(json.dumps(POLICY))) == a
    assert a["policy_hash"] == rules.policy_hash()


def test_decide_inputs_have_no_floats():
    from executor.canonical import canonical_json

    canonical_json(decide_inputs({"proposal_id": "p", "invoice": invoice()}, factset(VOP),
                                 {"mandate": mandate(), "payee": None, "now": NOW}))


# ---------------------------------------------------------------- invariants helpers

def test_normalize_invoice_no():
    assert inv.normalize_invoice_no("FV-2026-0412") == inv.normalize_invoice_no("fv2026412") == "FV2026412"
    assert inv.normalize_invoice_no("000") == "0" and inv.normalize_invoice_no("a/007-b") == "A7B"


def test_z_hit_needs_five_and_mad():
    assert not inv.z_hit({"vendor_id": "v", "amount_minor": 10**9}, [{"vendor_id": "v", "amount_minor": 1}] * 4)
    assert not inv.z_hit({"vendor_id": "v", "amount_minor": 10**9}, [{"vendor_id": "v", "amount_minor": 1}] * 9)
    assert inv.z_hit(invoice(), LEDGER) and not inv.z_hit(invoice(amount_minor=1_030_000), LEDGER)


# ---------------------------------------------------------------- change policy set

def change(**over):
    c = {"change_id": "chg_7", "vendor_id": "ven_12345678", "state": "PENDING_ATTEST", "in_network": True,
         "break_glass": False, "attest_count": 2, "not_before": None, "callback": {"status": "none"}}
    c.update(over)
    return c


ATT0 = fact("F-ATTEST", "BLOCK", "ATT 0/3")
CHG_TABLE = [
    ("allowed in-network", change(), (), (True, [])),
    ("attest 1/3", change(attest_count=1), (), (False, ["I-ATTEST"])),
    ("attest fact block", change(attest_count=0), (ATT0,), (False, ["F-ATTEST", "I-ATTEST", "I-BLOCK"])),
    ("off-network no callback", change(in_network=False, attest_count=0), (), (False, ["I-CALLBACK"])),
    ("off-network callback ok", change(in_network=False, attest_count=0, callback={"status": "confirmed"}), (),
     (True, [])),
    ("break-glass no callback", change(break_glass=True, attest_count=0), (), (False, ["I-CALLBACK"])),
    ("break-glass callback ok", change(break_glass=True, attest_count=0, callback={"status": "confirmed"}), (),
     (True, [])),
    ("cool-off", change(not_before="2026-10-19T12:30:00Z"), (), (False, ["I-COOLOFF"])),
    ("cool-off over", change(not_before="2026-10-19T12:00:00Z"), (), (True, [])),
    ("other block", change(), (fact("F-DOMAIN", "BLOCK", "DOMAIN LOOKALIKE"),), (False, ["F-DOMAIN", "I-BLOCK"])),
]


@pytest.mark.parametrize("case", CHG_TABLE, ids=[c[0] for c in CHG_TABLE])
def test_may_issue_chg_challenge(case):
    _, c, facts, want = case
    assert may_issue_chg_challenge(c, factset(*facts), now=NOW, policy=POLICY) == want
    now_dt = datetime(2026, 10, 19, 12, 2, tzinfo=timezone.utc)
    assert may_issue_chg_challenge(c, factset(*facts), now=now_dt, policy=POLICY) == want
