"""The attacker workstation's attacks, run against the in-process memory executor (executor.scenes.DemoEnv): every
attack must be refused and move 0 CZK to the attacker IBANs. If any attack gets through, that is a real finding and
this test fails loudly. Owner: WS-F."""
from __future__ import annotations

import pytest

from attacker import attacks
from executor.scenes import DemoEnv


@pytest.fixture(autouse=True)
def _isolate_implant(tmp_path, monkeypatch):
    """Keep attack h's simulated implant (host.implant) out of the repo's .local: give each test a throwaway dir."""
    monkeypatch.setenv("AIRGAP_IMPLANT_DIR", str(tmp_path / "implant"))
    yield


def _session() -> attacks.Session:
    env = DemoEnv()
    env.active_mandate()  # accepted hardware approvals in the log (so the replay attack has something to capture)
    return attacks.Session(env.call, data_dir=env.settings.data_dir, mode="local")


@pytest.mark.parametrize("key", list(attacks.ATTACKS))
def test_attack_is_blocked(key: str) -> None:
    res = attacks.run_attack(key, _session())
    assert res.money_to_attacker_minor == 0, f"{key} moved money to the attacker: {res.czk()}"
    assert res.blocked, f"{key} was NOT blocked (breach: {res.breach}); verdict: {res.verdict}"
    assert res.requests, f"{key} sent no requests"


def test_bec_lookalike_rejected_no_challenge() -> None:
    res = attacks.run_attack("bec_lookalike", _session())
    change = next((r for r in res.requests if r.path == "/changes"), None)
    assert change is not None and change.status == 201
    ch = change.response["change"]
    assert ch["state"] == "REJECTED"
    assert not ch.get("pending_challenge"), "a BLOCKed change must never get a device challenge (R0)"


def test_mailbox_takeover_stuck_at_attestations() -> None:
    res = attacks.run_attack("mailbox_takeover", _session())
    change = next((r for r in res.requests if r.path == "/changes"), None)
    assert change is not None
    assert change.response["change"]["state"] == "PENDING_ATTEST"
    assert not change.response["change"].get("pending_challenge")


def test_replay_refused() -> None:
    res = attacks.run_attack("replay_approval", _session())
    submit = [r for r in res.requests if r.path == "/signatures"]
    assert submit and submit[-1].response.get("error") in ("nonce_reused", "expired")


def test_forged_refused() -> None:
    res = attacks.run_attack("forged_approval", _session())
    submit = [r for r in res.requests if r.path == "/signatures"]
    assert submit and submit[-1].response.get("error") in ("unknown_signer", "not_found")


def test_stolen_creds_cannot_mint_mandate() -> None:
    res = attacks.run_attack("stolen_agent_creds", _session())
    mandate = next((r for r in res.requests if r.path == "/mandates"), None)
    assert mandate is not None and mandate.response.get("error") == "caller_not_allowed"


def test_lookalike_story_card() -> None:
    from host import story

    reg = {"acme.cz": "ACME s.r.o.", "betaservis.cz": "Beta Servis a.s."}
    assert story._lookalike_of("acme-cz.com", reg) == "acme.cz"
    assert story._lookalike_of("acme.cz", reg) is None
    assert story._lookalike_of("vendor-review-partners.example", reg) is None


@pytest.mark.parametrize("key", [k for k in attacks.ATTACKS if k != "clerk_pc_malware"])
def test_attack_result_carries_the_banks_log(key: str) -> None:
    """Under every attack the attacker console shows the bank's own log lines for it, read back from the executor
    (audit export + explain, and the ring of request-level refusals that wrote no leaf): threat, layer, evidence."""
    from tests.log_helpers import ATTACK_THREATS

    res = attacks.run_attack(key, _session())
    threat, layer = ATTACK_THREATS[key]
    hits = [d for d in res.bank_log if d["level"] == "ATTACK" and d["threat"] == threat and d["layer"] == layer]
    assert hits, [(d["level"], d["threat"], d["layer"], d["headline"]) for d in res.bank_log]
    page = attacks.bank_log_html(res.bank_log)
    assert "The bank's log" in page and threat in page.replace("&amp;", "&")
    assert f"stopped by <b>{layer}</b>" in page or f"held by <b>{layer}</b>" in page
    if key == "stolen_agent_creds":  # refused at the door: no audit entry, still in the bank's log
        door = [d for d in res.bank_log if d["source"].startswith("refused at the door")]
        assert {d["kind"] for d in door} >= {"stolen agent credentials", "IBAN injection"}
        assert "caller_not_allowed" in page


def test_bank_log_on_aws_falls_back_to_the_refusal_response(monkeypatch) -> None:
    """Against AWS the ring is not reachable: a refused request is explained from the executor's own refusal body
    (the same explain.refusal the executor writes to CloudWatch), never twice for a kind a leaf already tells."""
    from executor import oplog

    monkeypatch.setattr(oplog, "fetch_recent", lambda call, after=0: [])
    res = attacks.run_attack("stolen_agent_creds", _session())
    aws = [d for d in res.bank_log if "CloudWatch" in d["source"]]
    assert {d["kind"] for d in aws} == {"stolen agent credentials", "IBAN injection"}


def test_bank_log_html_escapes_attacker_text() -> None:
    page = attacks.bank_log_html([{"level": "ATTACK", "threat": "PROMPT INJECTION", "title": "<img src=x>",
                                   "layer": "input sanitisation", "evidence": "<script>", "seq": 3, "kind": "x"}])
    assert "<img" not in page and "<script>" not in page and "&lt;img" in page
