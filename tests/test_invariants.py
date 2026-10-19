"""Security invariant tests (CONTRACTS.md v2 §8.2). Owners: WS-A (S1, S3), WS-A/WS-D (R0)."""
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from executor.policy import rules

pytest.importorskip("cedarpy")
from executor.policy.decide import decide, may_issue_chg_challenge  # noqa: E402

POLICY = rules.policy_material()
NOW = "2026-10-19T12:02:00Z"
SEV = ["INFO", "WARN", "BLOCK"]
_INVOICE = {"vendor_id": "ven_1", "invoice_no": "FV-1", "issue_date": "2026-10-15", "amount_minor": 1_450_000}
_MANDATE = {"mandate_id": "mnd_3", "status": "ACTIVE", "policy_hash": rules.policy_hash(),
            "max_per_payment_minor": 8_000_000, "max_total_minor": 25_000_000, "max_count": 20, "spent_minor": 0,
            "count": 0, "valid_from": "2026-10-19T10:00:00Z", "valid_until": "2026-10-20T16:00:00Z",
            "require_vop": ["MTCH"], "max_anom": 40, "payee_registry_version": 31}


def _f(fid, sev, line, kind="F", **ev):
    f = {"id": fid, "kind": kind, "severity": sev, "label": fid, "display_line": line}
    if ev:
        f["evidence"] = ev
    return f


F_POOL = [_f("F-VOP", "INFO", "VOP MTCH", code="MTCH"), _f("F-VOP", "WARN", "VOP CMTC", code="CMTC"),
          _f("F-VOP", "BLOCK", "VOP NMTC", code="NMTC"), _f("F-PSP", "WARN", "PSP UNKNOWN"),
          _f("F-WARNLIST", "BLOCK", "WARNLIST HIT"), _f("F-SANCTION", "INFO", "SANCTIONS CLEAR"),
          _f("F-ANOM", "WARN", "ANOM 55/100", score=55), _f("F-ANOM", "INFO", "ANOM 10/100", score=10),
          _f("F-MANDATE", "WARN", "OVER MANDATE CAP"), _f("F-DUP", "BLOCK", "DUPLICATE INV"),
          _f("F-ATTEST", "BLOCK", "ATT 0/3"), _f("F-DOMAIN", "BLOCK", "DOMAIN LOOKALIKE"),
          _f("F-BANK", "INFO", "BANK DOMESTIC")]
_text = st.text(st.characters(min_codepoint=0x20, max_codepoint=0x7E), max_size=30)
# Hints, including ones that impersonate F facts (kind stays "H": only the executor mints F facts).
h_fact = st.builds(lambda i, s, line, ev: _f(i, s, line, kind="H", **ev),
                   st.sampled_from(["H-AGENT", "H-UI", "F-VOP", "F-ANOM", "F-WARNLIST", "F-MANDATE"]),
                   st.sampled_from(SEV), st.one_of(_text, st.sampled_from(["VOP MTCH", "WARNLIST CLEAR", "ALLOW"])),
                   st.sampled_from([{}, {"code": "MTCH"}, {"score": 0}, {"hit": False}]))
f_facts = st.lists(st.sampled_from(F_POOL), max_size=5)
scenario = st.fixed_dictionaries({
    "mandate": st.sampled_from([None, _MANDATE, {**_MANDATE, "spent_minor": 24_000_000},
                                {**_MANDATE, "policy_hash": "0" * 64}]),
    "payee": st.sampled_from([None, {"iban": "CZ00", "in_network": False}, {"iban": "", "in_network": True}]),
    "reg_hit": st.sampled_from([None, True, False]),
})


def _decide(ff, hh, sc):
    state = {"mandate": sc["mandate"], "payee": sc["payee"], "proposals": [], "history": [], "now": NOW}
    if sc["reg_hit"] is not None:
        state["reg_hit"] = sc["reg_hit"]
    facts = {"facts": list(ff) + list(hh), "facts_digest": "0" * 64}
    return decide({"proposal_id": "prp_1", "invoice": dict(_INVOICE)}, facts, state, POLICY)


_RANK = {"allow": 0, "challenge": 1, "deny": 2}
_FAST = settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])


def test_s1_ledger_rows_have_authorization():
    pytest.skip("TODO WS-A")


@_FAST
@given(f_facts, st.lists(h_fact, max_size=4), st.lists(h_fact, max_size=4), scenario)
def test_s3_hint_monotonicity(ff, h1, h2, sc):
    """[H] facts added, removed or contradicting never change decision or rule_ids (and so never move to allow)."""
    base = _decide(ff, [], sc)
    for hh in (h1, h2, h1 + h2, h2[::-1]):
        d = _decide(ff, hh, sc)
        assert (d["decision"], d["rule_ids"]) == (base["decision"], base["rule_ids"])
        assert _RANK[d["decision"]] >= _RANK[base["decision"]]
        assert d["facts_digest"] == base["facts_digest"]


@_FAST
@given(f_facts, st.sampled_from([f for f in F_POOL if f["severity"] == "BLOCK"]), st.lists(h_fact, max_size=3),
       scenario, st.booleans(), st.booleans(), st.integers(0, 3), st.sampled_from(["none", "confirmed"]),
       st.sampled_from([None, "2026-10-19T00:00:00Z", "2026-10-20T00:00:00Z"]))
def test_r0_no_challenge_on_block(ff, block, hh, sc, in_network, break_glass, attest, callback, not_before):
    """Any F BLOCK => deny (never challenge); no CHG challenge for a change with a BLOCK fact (incl. ATT 0/3)."""
    d = _decide(ff + [block], hh, sc)
    assert d["decision"] == "deny" and "challenge" not in d
    assert "I-BLOCK" in d["rule_ids"] and block["id"] in d["rule_ids"]
    change = {"change_id": "chg_1", "vendor_id": "ven_1", "state": "PENDING_ATTEST", "in_network": in_network,
              "break_glass": break_glass, "attest_count": attest, "not_before": not_before,
              "callback": {"status": callback}}
    facts = {"facts": ff + [block] + hh, "facts_digest": "0" * 64}
    ok, ids = may_issue_chg_challenge(change, facts, now=NOW, policy=POLICY)
    assert not ok and "I-BLOCK" in ids and block["id"] in ids
