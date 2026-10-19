"""Policy freeze guard (Tue 06:00): the policy material may not change after the freeze without a deliberate,
reviewed update of FROZEN_POLICY_HASH (and `make contracts`). Owner: WS-A.

Hash-relevant (executor.policy.rules.policy_material()): executor/policy/cedar/{hard_deny,mandate_allow,change}.cedar,
executor/policy/cedar/schema.cedarschema.json, rules.FACT_SEVERITY, rules.PARAMS, rules.POLICY_V and
executor/render.TRANSLIT (WS-C). Everything else (render layout, display lines, facts code) does not move the hash.
"""
from executor.policy import rules

FROZEN_POLICY_HASH = "3909f806c268773b10b6b3012a736a3efd183154ed4a2916f42488b9d877e8cd"


def test_policy_hash_is_frozen():
    assert rules.policy_hash() == FROZEN_POLICY_HASH, (
        "policy material changed after the freeze: if intended, update FROZEN_POLICY_HASH, run make contracts, "
        "and tell every workstream (mandates pin policy_hash; old ones fail I-MANDATE)")


def test_fixtures_carry_the_real_policy_hash():
    import json
    from pathlib import Path

    fx = json.loads((Path(__file__).parents[1] / "contracts/fixtures/health/ok.json").read_text())
    assert fx["response"]["policy_hash"] == FROZEN_POLICY_HASH
