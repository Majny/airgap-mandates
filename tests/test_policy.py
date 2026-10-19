"""Contract data checks: Cedar policy sets + schema, policy_hash, tool manifest, config, enums (CONTRACTS.md v2)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from executor import errors, models
from executor import render as R
from executor.config import DemoNotReady, Settings, assert_demo_ready, physical_table
from executor.policy import rules
from executor.tools import manifest

cedarpy = pytest.importorskip("cedarpy")
ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("name", ["hard_deny", "mandate_allow", "change"])
def test_cedar_policy_sets_validate_against_schema(name):
    res = cedarpy.validate_policies(rules.policy_set_text(name), rules.cedar_schema())
    assert res.validation_passed, res.errors


def test_tool_policies_validate():
    d = ROOT / "executor/tools/policies"
    res = cedarpy.validate_policies((d / "tools.cedar").read_text(), json.loads((d / "tools.cedarschema.json").read_text()))
    assert res.validation_passed, res.errors


def test_rule_ids_are_cedar_ids():
    ids = set()
    for name in ("hard_deny", "mandate_allow", "change"):
        ids |= set(rules.policy_ids(rules.policy_set_text(name)))
    assert {i for i in ids if i.startswith("I-")} == set(models.RULE_IDS) - {"I-NONCE"}
    assert all(i.startswith(("I-", "P-")) for i in ids)


def _mandate_entities(**over):
    attrs = dict(status="ACTIVE", policy_current=True, max_per_payment_minor=8_000_000, max_total_minor=25_000_000,
                 max_count=20, spent_minor=0, count=0, valid_from=0, valid_until=2_000_000_000, require_vop=["MTCH"],
                 max_anom=40, payee_registry_version=31)
    attrs.update(over)
    return [{"uid": {"type": "Mandate", "id": "mnd_3"}, "attrs": attrs, "parents": []},
            {"uid": {"type": "Payee", "id": "ven_87654321"}, "attrs": {"known": True, "active": True,
                                                                       "in_network": False}, "parents": []}]


def _ctx(**over):
    c = dict(amount_minor=1_450_000, vop="MTCH", reg_hit=True, warn_hit=False, block_hit=False, warn_count=0, anom=0,
             dup=False, split_sum=0, z_hit=False, now=1_792_400_000, attest_count=0,
             amount_doc_block=False)
    c.update(over)
    return c


def _authz(policy_set, ctx, **mandate):
    text = rules.policy_set_text(policy_set)
    req = {"principal": 'Mandate::"mnd_3"', "action": 'Action::"pay"', "resource": 'Payee::"ven_87654321"',
           "context": ctx}
    r = cedarpy.is_authorized(req, text, _mandate_entities(**mandate), schema=rules.cedar_schema())
    ids = rules.policy_ids(text)
    return r.decision == cedarpy.Decision.Allow, sorted(ids[int(p.removeprefix("policy"))] for p in r.diagnostics.reasons)


def test_tri_state_semantics_smoke():
    assert _authz("hard_deny", _ctx()) == (True, ["P-BASE"])
    assert _authz("mandate_allow", _ctx()) == (True, ["P-MANDATE"])
    allowed, ids = _authz("mandate_allow", _ctx(amount_minor=12_500_050, warn_hit=True, warn_count=1))
    assert not allowed and ids == ["I-PER", "I-SPLIT", "I-WARN"]
    allowed, ids = _authz("hard_deny", _ctx(block_hit=True, dup=True))
    assert not allowed and ids == ["I-BLOCK", "I-DUP"]
    allowed, ids = _authz("mandate_allow", _ctx(), status="PENDING_SIG_CLERK")
    assert not allowed and ids == ["I-MANDATE"]


def test_policy_hash_stable_and_covers_material():
    h = rules.policy_hash()
    assert len(h) == 64 and h == rules.policy_hash()
    m = rules.policy_material()
    assert set(m) == {"cedar_policies_text", "cedar_schema", "translit_table", "fact_severity_table", "params",
                      "policy_v"}
    assert m["policy_v"] == 2 and m["translit_table"] is R.TRANSLIT
    assert set(m["fact_severity_table"]) == set(models.FACT_ORDER)


def test_fact_order_shared():
    assert list(R.FACT_ORDER) == models.FACT_ORDER


def test_tool_manifest_has_no_iban_on_propose():
    assert "iban" not in manifest.TOOL_MANIFEST["payment.propose"]["args"]
    assert len(manifest.manifest_sha256()) == 64


def test_config_v2_env():
    s = Settings.from_env({"AIRGAP_DEPLOYMENT_ID": "DEMO", "AIRGAP_COOLING_SECONDS": "30", "AGENT_MODE": "naive",
                           "AIRGAP_RENDER_PROFILE": "safe3-mono-16x4"})
    assert s.cooling_seconds == 30 and s.agent_mode == "naive" and s.render_profile == R.DEFAULT_PROFILE
    d = Settings()
    assert (d.cooling_seconds, d.tsa_url, d.checkpoint_every_n_leaves, d.mandate_dual_threshold_minor) == (
        20, "off", 10, 10_000_000)
    assert physical_table(d, "proposals") == "airgap-main"
    assert physical_table(d, "portal_notifications") == "airgap-portal"
    assert physical_table(d, "registry") == "airgap-registry"


def test_demo_requires_aws():
    with pytest.raises(DemoNotReady):
        assert_demo_ready(Settings(backend="memory"))
    with pytest.raises(DemoNotReady):
        assert_demo_ready(Settings(backend="aws", aws_region="eu-west-1"))
    assert_demo_ready(Settings(backend="aws"))


def test_error_codes_v2():
    assert "vendor_attestation_missing" not in errors.ERROR_CODES
    for c in ("attestation_insufficient", "kb_jwt_invalid", "issuer_not_pinned", "break_glass_required",
              "callback_attempts_exceeded", "emulator_not_allowed", "checkpoint_inconsistent", "stale_checkpoint"):
        assert c in errors.ERROR_CODES
    assert errors.status_for("checkpoint_inconsistent") == 422 and errors.status_for("stale_checkpoint") == 409
