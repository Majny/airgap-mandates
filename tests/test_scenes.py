"""Demo beats S2 / S3 through dispatch on the memory backend (executor/scenes.py). Owner: WS-A."""
import pytest

from executor import scenes


def test_scene_s2_lookalike_escalation_exfil():
    out = scenes.scene_s2(log=lambda s: None)
    assert out["change"]["state"] == "REJECTED" and "F-DOMAIN" in out["change"]["rule_ids"]
    assert set(out["escalation"]) == {"mandate.write", "agent->/signatures", "self-approval", "replay"}
    assert out["money_to_attacker_minor"] == 0


def test_scene_s3_takeover_rejected_without_challenge():
    out = scenes.scene_s3(log=lambda s: None, legit=False)
    assert out["takeover"]["state"] == "REJECTED"


@pytest.mark.xfail(strict=True, reason="WS-D: attestation rows keyed by sk vc#<n> and CHG challenges via "
                   "policy.challenge.issue_challenge (in flight); remove this marker with that fix")
def test_scene_s3_legit_change_reaches_active():
    out = scenes.scene_s3(log=lambda s: None)
    assert out["legit"]["state"] == "ACTIVE"
