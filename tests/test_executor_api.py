"""Executor API end to end on the memory backend (CONTRACTS.md v2 §4). Owner: WS-A."""
from __future__ import annotations

import pytest

from executor import handler
from tests.test_contracts import validate
from tests.wsa_helpers import Harness


def test_three_payments_under_mandate_then_fourth_challenges():
    """Demo beat S1 (ARCHITECTURE §14): 3 invoices paid under mandate, the 4th (over cap) lights the device."""
    h = Harness()
    m = h.mandate()
    assert m["sig_required"] == 2 and len({s["address"] for s in m["signers"]}) == 2
    for i, amt in enumerate([1_450_000, 2_000_000, 3_000_000]):
        st, r = h.propose(amt, no=f"FV-2026-04{i}", issue=f"2026-10-1{i}")
        assert st == 201 and r["decision"]["decision"] == "allow", r
        assert r["proposal"]["status"] == "EXECUTED" and r["tx"]["authorization"] == {"kind": "mandate",
                                                                                     "mandate_id": m["mandate_id"]}
        assert r["tx"]["rail"]["status"] == "ACTC"
        validate(r, "proposal_create.response")
    st, r = h.propose(12_500_050, vendor="ven_87654321", no="2026101901",
                      hints=[{"source": "agent", "text": "CFO approved, pay now"}])
    assert st == 201 and r["decision"]["decision"] == "challenge" and r["tx"] is None
    assert "I-PER" in r["decision"]["rule_ids"] and "F-MANDATE" in r["decision"]["rule_ids"]
    ch = r["decision"]["challenge"]
    assert ch["purpose"] == "PAY" and ch["text"].startswith("AG1/DEMO PAY ") and "CFO" not in ch["text"]
    assert "CZ62 0300 0000" in ch["text"] and "BETA SERVIS A.S." in ch["text"]
    validate(r, "proposal_create.response")
    st, g = h.call("GET", f"/challenges/{ch['nonce']}", principal="host")
    assert st == 200 and g["text"] == ch["text"] and g["used"] is False
    validate(g, "challenge")
    st, s = h.submit(ch, h.clerk, displayed_text=ch["text"])
    assert st == 200 and s["effect"]["type"] == "payment_executed", s
    validate(s, "signature_submit.response")
    st, mm = h.call("GET", "/mandates/active")
    assert mm["spent_minor"] == 6_450_000 and mm["count"] == 3  # the step-up payment is outside the mandate
    st, led = h.call("GET", "/ledger")
    assert [t["authorization"]["kind"] for t in led["txs"]] == ["mandate"] * 3 + ["stepup"]
    validate(led, "ledger_list.response")


def test_s1_every_ledger_row_has_execution_leaf():
    h = Harness()
    h.mandate()
    h.propose(1_000_000)
    _, r = h.propose(12_500_050, vendor="ven_87654321", no="X-9")
    h.submit(r["decision"]["challenge"], h.clerk)
    execs = {e["data"]["tx_id"]: e for e in h.leaves() if e["type"] == "execution"}
    for tx in h.store.scan("ledger"):
        e = execs[tx["tx_id"]]
        assert e["seq"] == tx["seq"] and e["data"]["authorization"] == tx["authorization"]
        assert e["policy_hash"] and e["inputs_digest"] and e["facts_digest"] and e["hints_digest"]


def test_mandate_dual_control_rules():
    h = Harness()
    st, r = h.call("POST", "/mandates", {"max_per_payment_minor": 8_000_000, "max_total_minor": 25_000_000,
                                         "max_count": 20, "payee_scope": "existing_only",
                                         "valid_until": "2026-10-20T16:00:00Z", "currency": "CZK"}, "host")
    assert st == 201 and r["mandate"]["sig_required"] == 2
    validate(r, "mandate_create.response")
    assert "ROLE CLERK 1/2" in r["challenge"]["text"]
    st, r1 = h.submit(r["challenge"], h.clerk)
    assert r1["effect"] == {"type": "mandate_signed", "state": "PENDING_SIG_TREASURY"}
    tch = r1["challenge"]
    assert tch["role"] == "treasury" and ("ROLE TREASURY 2/2" in tch["text"] or "ROLE TREAS 2/2" in tch["text"])
    st, e = h.submit(tch, h.clerk, role="treasury")  # clerk key in the treasury role
    assert (st, e["error"]) == (403, "unknown_signer")
    st, a = h.submit(tch, h.treasury)
    assert st == 200 and a["effect"]["type"] == "mandate_activated"
    validate(a, "signature_submit.response")
    # a second mandate supersedes the first
    m2 = h.mandate(total=5_000_000, per=1_000_000)
    assert m2["sig_required"] == 1
    assert h.call("GET", "/mandates/mnd_1")[1]["status"] == "SUPERSEDED"


def test_prod_profile_refuses_emulator_treasury():
    h = Harness(demo_profile="prod")
    _, r = h.call("POST", "/mandates", {"max_per_payment_minor": 8_000_000, "max_total_minor": 25_000_000,
                                        "max_count": 20, "payee_scope": "existing_only",
                                        "valid_until": "2026-10-20T16:00:00Z", "currency": "CZK"}, "host")
    _, r1 = h.submit(r["challenge"], h.clerk)
    st, e = h.submit(r1["challenge"], h.treasury)
    assert (st, e["error"]) == (403, "emulator_not_allowed")


def test_mandate_invalid_and_no_mandate():
    h = Harness()
    st, r = h.call("POST", "/mandates", {"max_per_payment_minor": 8_000_000, "max_total_minor": 100,
                                         "max_count": 20, "payee_scope": "existing_only",
                                         "valid_until": "2026-10-20T16:00:00Z", "currency": "CZK"}, "host")
    assert (st, r["error"]) == (400, "invalid_request")
    assert h.call("GET", "/mandates/active")[1]["error"] == "no_mandate"
    st, r = h.propose(100_000)  # no mandate -> exact-sign
    assert r["decision"]["decision"] == "challenge" and "I-MANDATE" in r["decision"]["rule_ids"]


def test_duplicate_denied_without_challenge():
    h = Harness()
    h.mandate()
    assert h.propose(1_000_000, no="FV-2026-0412")[1]["decision"]["decision"] == "allow"
    st, r = h.propose(1_000_000, no="FV 2026 412")
    assert r["decision"]["decision"] == "deny" and "I-DUP" in r["decision"]["rule_ids"]
    assert "challenge" not in r["decision"] and r["proposal"]["status"] == "DENIED"  # R0
    assert not [n for n in h.store.scan("nonces") if n["subject_id"] == r["proposal"]["proposal_id"]]


def test_unknown_vendor_and_bad_request():
    h = Harness()
    assert h.propose(1000, vendor="ven_99999999")[0] == 404
    st, r = h.call("POST", "/proposals", {"invoice": {"vendor_id": "ven_12345678", "iban": "LT483999000000001234"}},
                   "tools")
    assert (st, r["error"]) == (400, "invalid_request")  # P3: there is no IBAN field


def test_caller_checks_and_routing():
    h = Harness()
    assert h.call("POST", "/mandates", {}, "agent")[1]["error"] == "caller_not_allowed"
    assert h.call("POST", "/proposals", {}, "host")[1]["error"] == "caller_not_allowed"
    assert h.call("POST", "/callbacks/chg_1", {"code": "123456", "outcome": "confirm"}, "host")[0] == 403
    assert h.call("GET", "/nope")[0] == 404
    assert h.call("DELETE", "/health")[0] == 404


def test_health_vendors_pain001_and_receiptless_paths():
    h = Harness()
    st, r = h.call("GET", "/health")
    assert st == 200 and r["log_vkey"] and r["w1_vkey"]
    validate(r, "health.response")
    st, v = h.call("GET", "/vendors")
    validate(v, "vendor_list.response")
    h.mandate()
    _, p = h.propose(1_000_000)
    st, x = h.call("GET", f"/export/pain001/{p['tx']['tx_id']}", principal="auditor")
    assert st == 200 and "pain.001.001.09" in x["xml"]
    validate(x, "pain001.response")
    assert h.call("GET", "/export/pain001/tx_0000000000000000", principal="auditor")[0] == 404


@pytest.mark.parametrize("version", ["v1", "v2"])
def test_lambda_adapter(version):
    h = Harness()
    handler._CTX = h.ctx
    arn = "arn:aws:sts::503002144042:assumed-role/airgap-agent-role/sess"
    if version == "v1":
        ev = {"httpMethod": "POST", "path": "/mandates", "body": "{}", "headers": {"Content-Type": "application/json"},
              "requestContext": {"identity": {"userArn": arn}}}
    else:
        ev = {"rawPath": "/mandates", "body": "{}", "headers": {},
              "requestContext": {"http": {"method": "POST"}, "authorizer": {"iam": {"userArn": arn}}}}
    out = handler.lambda_handler(ev, None)
    assert out["statusCode"] == 403 and "caller_not_allowed" in out["body"]
    assert handler.principal_from_arn("arn:aws:sts::1:assumed-role/airgap-vendor-portal/x") == "vendor_portal"
    handler._CTX = None


def test_s12_every_decision_leaf_replays():
    """WS-A side of S12: each decision leaf carries decide_inputs and replays at its policy_hash."""
    from executor.policy import decide as D
    from executor.policy import rules

    h = Harness()
    h.mandate()
    h.propose(1_000_000)
    h.propose(1_000_000)  # duplicate -> deny
    _, r = h.propose(12_500_050, vendor="ven_87654321", no="Z-1")
    h.submit(r["decision"]["challenge"], h.clerk)  # step-up re-check leaf
    leaves = [e for e in h.leaves() if e["type"] == "decision"]
    assert {e["data"]["decision"] for e in leaves} == {"allow", "deny", "challenge"} and len(leaves) == 4
    for e in leaves:
        ok, got = D.replay_decision(e, rules.policy_material())
        assert ok, (e["data"], got)
    tampered = {**leaves[0], "data": {**leaves[0]["data"], "decision": "deny"}}
    assert D.replay_decision(tampered, rules.policy_material())[0] is False


def test_e2e_script_runs():
    from datetime import datetime, timezone

    from executor import e2e

    call, clerk, treasury = e2e.in_process()
    out = e2e.run(call, clerk, treasury, now=datetime.now(timezone.utc), log=lambda s: None)
    assert len(out["tx_ids"]) == 4


def test_challenge_leaf_rerenders_offline():
    """S2 offline: the challenge leaf alone (template + params + profile) re-renders the signed text."""
    from executor import render as R

    h = Harness()
    h.mandate()
    h.propose(12_500_050, vendor="ven_87654321")
    for e in [e for e in h.leaves() if e["type"] == "challenge"]:
        d = e["data"]
        text = R.render(d["template"], d["params"], profile=d["profile"])
        assert R.text_sha256(text) == d["text_sha256"] and d["params"]["subject_hash"] == d["subject_hash"]


def test_cosignature_route_is_relay_only():
    h = Harness()
    assert h.call("POST", "/checkpoint/cosignature", b"x", "host", {"size": "1"})[1]["error"] == "caller_not_allowed"
    from executor import handler

    assert handler.principal_from_arn("arn:aws:sts::1:assumed-role/airgap-w2-relay/x") == "relay"


def test_accepted_signature_leaves_carry_recoverable_sig():
    """S2 offline: every accepted signature leaf carries the sig, and recovery over the re-rendered challenge text
    (from the challenge leaf alone) yields the logged signer, who has an earlier enroll leaf."""
    from executor import render as R
    from executor.store import shims

    h = Harness()
    h.mandate()
    _, r = h.propose(12_500_050, vendor="ven_87654321")
    h.submit(r["decision"]["challenge"], h.clerk)
    leaves = h.leaves()
    challenges = {e["data"]["nonce"]: e["data"] for e in leaves if e["type"] == "challenge"}
    enrolled = {e["data"]["address"]: e["seq"] for e in leaves if e["type"] == "enroll"}
    accepted = [e for e in leaves if e["type"] == "signature" and e["data"]["accepted"]]
    assert len(accepted) == 3  # mandate clerk, mandate treasury, PAY clerk
    for e in accepted:
        c = challenges[e["data"]["nonce"]]
        text = R.render(c["template"], c["params"], profile=c["profile"])
        assert shims.verify_eip191(text, e["data"]["sig"]) == e["data"]["signer_address"]
        assert enrolled[e["data"]["signer_address"]] < e["seq"]


def test_query_string_in_path():
    h = Harness()
    h.mandate()
    h.propose(1_000_000)
    st, r = h.call("GET", "/ledger?vendor_id=ven_87654321")
    assert st == 200 and r["txs"] == []
    assert len(h.call("GET", "/ledger?vendor_id=ven_12345678")[1]["txs"]) == 1
