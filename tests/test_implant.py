"""Attack h: simulated malware on the clerk's PC (host.implant, attacker level H4). tamper() swaps only the IBAN lines
of a real PAY device text; end to end on the in-memory executor the swap is refused (render_mismatch), the nonce is not
consumed and nothing reaches the attacker, then an honest signature pays. Owner: WS-F."""
from __future__ import annotations

import pytest

from attacker import attacks
from executor import render as R
from executor.scenes import DemoEnv
from host import implant, signer
from tools.local_stack import seed_pending_overcap

ATTACKER_IBAN = attacks.FRAUD_IBAN


@pytest.fixture(autouse=True)
def _isolate_implant(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRGAP_IMPLANT_DIR", str(tmp_path / "implant"))
    yield


def _pending_delta(env: DemoEnv) -> tuple[str, dict]:
    """Seed the over-cap Delta payment (PENDING_SIG) and return (nonce, full challenge)."""
    pid = seed_pending_overcap(env.call, env.now, data_dir=env.settings.data_dir)
    assert pid, "could not seed the pending over-cap payment"
    st, prop = env.call("GET", f"/proposals/{pid}", None, "host")
    nonce = prop["challenge_nonce"]
    st, ch = env.call("GET", f"/challenges/{nonce}", None, "host")
    assert st == 200 and ch["purpose"] == "PAY"
    return nonce, ch


def test_tamper_swaps_only_iban_lines():
    env = DemoEnv()
    env.active_mandate()
    _, ch = _pending_delta(env)
    text = ch["text"]
    out = implant.tamper(text, ATTACKER_IBAN)
    assert out != text
    before, after = text.split("\n"), out.split("\n")
    assert len(before) == len(after)
    # the delta IBAN groups are gone; the attacker IBAN groups are present, in the same 2-line layout
    assert "CZ52 0100 0000" in before and "CZ52 0100 0000" not in after
    assert R.format_iban_lines("", ATTACKER_IBAN, R.DEFAULT_WIDTH) == [ln for ln in after if ln not in before]
    # every other line is byte-for-byte identical
    changed = [i for i, (a, b) in enumerate(zip(before, after)) if a != b]
    assert changed == [2, 3], changed  # exactly the two IBAN lines
    # still a valid 16-col device text (printable ASCII + LF)
    R.check_text(out, env.settings.render_profile)
    assert all(c == "\n" or " " <= c <= "~" for c in out)


def test_tamper_leaves_non_pay_untouched():
    env = DemoEnv()
    st, r = env.call("POST", "/mandates", {"max_per_payment_minor": 8_000_000, "max_total_minor": 25_000_000,
                                           "max_count": 20, "payee_scope": "existing_only",
                                           "valid_until": "2026-10-20T12:00:00Z", "currency": "CZK"}, "host")
    mand_text = r["challenge"]["text"]
    assert "MANDATE" in mand_text.split("\n")[0]
    assert implant.tamper(mand_text, ATTACKER_IBAN) == mand_text


def test_one_shot_arm_disarm_outcome():
    assert implant.armed() is None and implant.last() is None
    rec = implant.arm(ATTACKER_IBAN)
    assert rec["armed"] and rec["iban"] == ATTACKER_IBAN and implant.armed()["iban"] == ATTACKER_IBAN
    implant.record("refused_by_executor", error="render_mismatch", proposal_id="prp_1", device_text_iban="LT48 ...")
    assert implant.armed() is None  # one-shot: recording disarms
    assert implant.last()["outcome"] == "refused_by_executor"
    implant.arm(ATTACKER_IBAN)
    implant.disarm()
    assert implant.armed() is None


def test_e2e_swap_refused_then_honest_pays():
    env = DemoEnv()
    env.active_mandate()
    nonce, _ = _pending_delta(env)
    implant.arm(ATTACKER_IBAN)
    # armed: the device is shown the attacker IBAN; confirming sends the tampered text -> executor refuses it
    res = signer.sign_challenge(nonce, "clerk", call=env.call, driver=signer.SoftwareSignerDriver(env.clerk))
    assert res["_http"] == 403 and res["error"] == "render_mismatch"
    assert env.store.get("nonces", {"nonce": nonce})["used"] is False  # nonce NOT consumed
    assert not [t for t in env.store.scan("ledger") if t["iban"] in attacks.ATTACKER_IBANS]
    assert implant.last()["outcome"] == "refused_by_executor" and implant.last()["error"] == "render_mismatch"
    assert implant.armed() is None  # one-shot: disarmed after use
    # the rejected signature is logged as a render_mismatch leaf
    st, exp = env.call("GET", "/audit/export?log_id=audit&from_seq=0", None, "auditor")
    errs = [((le.get("event") or {}).get("data") or {}).get("error") for le in exp["leaves"]
            if (le.get("event") or {}).get("type") == "signature"]
    assert "render_mismatch" in errs
    # implant disarmed: the clerk approves again, honestly -> paid
    res2 = signer.sign_challenge(nonce, "clerk", call=env.call, driver=signer.SoftwareSignerDriver(env.clerk))
    assert res2["_http"] == 200 and res2["effect"]["type"] == "payment_executed"
    paid = env.store.get("registry", {"vendor_id": "ven_77665546"})["iban"]
    assert any(t["iban"] == paid for t in env.store.scan("ledger"))


def test_e2e_rejected_on_device():
    env = DemoEnv()
    env.active_mandate()
    nonce, _ = _pending_delta(env)
    implant.arm(ATTACKER_IBAN)
    with pytest.raises(signer.SignerCancelled):
        signer.sign_challenge(nonce, "clerk", call=env.call,
                              driver=signer.SoftwareSignerDriver(env.clerk, reject=True))
    assert implant.last()["outcome"] == "rejected_on_device"
    assert implant.armed() is None
    assert env.store.get("nonces", {"nonce": nonce})["used"] is False
    assert env.store.scan("ledger") == [] or not [t for t in env.store.scan("ledger")
                                                  if t["iban"] in attacks.ATTACKER_IBANS]


def test_story_card_render_mismatch():
    from host import story

    assert story.SIG_ATTACKS["render_mismatch"][0] == "Tampered approval stopped"
    # a refused render_mismatch signature leaf becomes an attack card
    env = DemoEnv()
    env.active_mandate()
    nonce, _ = _pending_delta(env)
    implant.arm(ATTACKER_IBAN)
    signer.sign_challenge(nonce, "clerk", call=env.call, driver=signer.SoftwareSignerDriver(env.clerk))
    st, bundle = env.call("GET", "/audit/export?log_id=audit&from_seq=0", None, "auditor")
    _, cards = story.build(bundle, [], [], [])
    titles = [c["title"] for c in cards]
    assert "Tampered approval stopped" in titles
