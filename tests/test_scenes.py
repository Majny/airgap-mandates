"""Demo beats S2 / S3 through dispatch on the memory backend (executor/scenes.py). Owner: WS-A."""
from executor import scenes


def test_scene_s2_lookalike_escalation_exfil():
    out = scenes.scene_s2(log=lambda s: None)
    assert out["change"]["state"] == "REJECTED" and "F-DOMAIN" in out["change"]["rule_ids"]
    assert set(out["escalation"]) == {"mandate.write", "agent->/signatures", "self-approval", "replay"}
    assert out["money_to_attacker_minor"] == 0


def test_scene_s3_takeover_rejected_without_challenge():
    out = scenes.scene_s3(log=lambda s: None, legit=False)
    assert out["takeover"]["state"] == "REJECTED"


def test_scene_s3_legit_change_reaches_active():
    out = scenes.scene_s3(log=lambda s: None)
    assert out["legit"]["state"] == "ACTIVE"


def test_host_reject_expired_change_gets_no_challenge_and_reason_is_kept():

    env = scenes.DemoEnv()
    st, r = env.call("POST", "/changes", {"vendor_id": scenes.ACME, "new_iban": scenes.TAKEOVER_IBAN,
                                          "email_id": scenes.TAKEOVER_EMAIL, "hints": []}, "tools")
    cid = r["change"]["change_id"]
    # live change: host reject issues a CHG_REJECT challenge; the clerk's signature rejects with the reason kept
    st, r = env.call("POST", f"/changes/{cid}/reject", {"reason": "clerk: not expected"}, "host")
    assert st == 200 and r["challenge"]["purpose"] == "CHG_REJECT"
    st, s = env.sign(r["challenge"], env.clerk)
    assert st == 200 and s["effect"]["type"] == "change_rejected", s
    assert "clerk: not expected" in str(s["change"]["history"][-1])
    # expired but never read: lazily advanced first -> 409, no challenge, no nonce
    _, r = env.call("POST", "/changes", {"vendor_id": scenes.ACME, "new_iban": scenes.LEGIT_NEW_IBAN,
                                         "email_id": scenes.LEGIT_CHANGE_EMAIL, "hints": []}, "tools")
    cid2 = r["change"]["change_id"]
    env.advance(env.settings.change_ttl_seconds + 1)
    st, r = env.call("POST", f"/changes/{cid2}/reject", {"reason": "late"}, "host")
    assert (st, r["error"]) == (409, "state_conflict") and not env.nonces_for(cid2)
