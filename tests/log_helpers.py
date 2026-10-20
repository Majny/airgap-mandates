"""Shared driver for tests/test_explain.py and tests/test_oplog.py: the seeded memory executor, scenes S2/S3 and every
attack in attacker/attacks.py, with attack h (clerk PC malware) carried through to the clerk's signing. Owner: orchestrator."""
from __future__ import annotations

from typing import Any, Callable

from attacker import attacks
from executor import scenes

# the kind each attack must produce at least once (executor.audit.explain vocabulary)
ATTACK_KINDS = {
    "bec_lookalike": "lookalike domain (BEC)",
    "mailbox_takeover": "mailbox takeover?",
    "invoice_injection": "prompt injection",
    "stolen_agent_creds": "stolen agent credentials",
    "replay_approval": "replayed approval",
    "forged_approval": "forged approval",
    "fake_supplier_portal": "fake attestation",
    "clerk_pc_malware": "tampered approval (PC malware)",
}


# Track 3: the threat class and the defence layer each attack must be named with (executor.audit.explain)
ATTACK_THREATS = {
    "bec_lookalike": ("PAYMENT FRAUD (BEC)", "executor facts + policy"),
    "mailbox_takeover": ("ACCOUNT TAKEOVER", "executor facts + policy"),
    "invoice_injection": ("PROMPT INJECTION", "input sanitisation"),
    "stolen_agent_creds": ("PRIVILEGE ESCALATION", "permission scoping"),
    "replay_approval": ("REPLAY / FORGERY", "hardware signature"),
    "forged_approval": ("REPLAY / FORGERY", "hardware signature"),
    "fake_supplier_portal": ("REPLAY / FORGERY", "executor facts + policy"),
    "clerk_pc_malware": ("HOST TAMPERING", "hardware signature"),
}


def leaves(env: scenes.DemoEnv, from_seq: int = 0) -> list[dict[str, Any]]:
    st, b = env.call("GET", f"/audit/export?log_id=audit&from_seq={from_seq}", None, "auditor")
    assert st == 200, b
    return b["leaves"]


def seeded(with_scenes: bool = True) -> tuple[scenes.DemoEnv, str | None]:
    """DemoEnv + (S2, S3 or just an ACTIVE mandate) + the waiting over-cap Delta payment attack h needs."""
    from tools.local_stack import seed_pending_overcap

    env = scenes.DemoEnv()
    if with_scenes:
        scenes.scene_s2(env, log=lambda s: None)
        scenes.scene_s3(env, log=lambda s: None)
    else:
        env.active_mandate()
    return env, seed_pending_overcap(env.call, env.now, data_dir=env.settings.data_dir)


def run_attack(key: str, env: scenes.DemoEnv, pending: str | None) -> attacks.AttackResult:
    """One attack; attack h only arms the implant, so the clerk then approves the waiting payment (the swap is
    refused with render_mismatch, like on stage)."""
    from host import signer

    s = attacks.Session(env.call, data_dir=env.settings.data_dir, mode="local")
    res = attacks.run_attack(key, s)
    if key == "clerk_pc_malware" and pending:
        st, prop = env.call("GET", f"/proposals/{pending}", None, "host")
        signer.sign_challenge(prop["challenge_nonce"], "clerk", call=env.call,
                              driver=signer.SoftwareSignerDriver(env.clerk))
    return res


def run_all(env: scenes.DemoEnv, pending: str | None,
            each: Callable[[str, attacks.AttackResult], None] = lambda k, r: None) -> None:
    for key in attacks.ATTACKS:
        each(key, run_attack(key, env, pending))
