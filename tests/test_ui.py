"""Host UI smoke tests (headless Streamlit AppTest). Owner: WS-F."""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

from host import ui  # noqa: E402

UI_PATH = str(Path(ui.__file__).resolve())


def _run(monkeypatch: pytest.MonkeyPatch, trezor_path: str = "") -> AppTest:
    monkeypatch.setenv("AIRGAP_EXECUTOR_URL", "http://127.0.0.1:9")  # unreachable: every tab must degrade, not crash
    monkeypatch.setenv("AIRGAP_TREZOR_PATH", trezor_path)
    return AppTest.from_file(UI_PATH, default_timeout=30).run()


def test_ui_renders_without_executor(monkeypatch: pytest.MonkeyPatch):
    at = _run(monkeypatch)
    assert not at.exception
    assert any("LOCAL" in m.value for m in at.markdown)
    assert not any("FALLBACK: EMULATOR CLERK" in m.value for m in at.markdown)


def test_ui_emulator_fallback_banner(monkeypatch: pytest.MonkeyPatch):
    at = _run(monkeypatch, "udp:127.0.0.1:21324")
    assert any("FALLBACK: EMULATOR CLERK" in m.value for m in at.markdown)


def test_device_labels_from_enroll_leaves():
    bundle = {"leaves": [{"seq": 0, "event": {"type": "enroll", "data": {"address": "0xAbC", "device": "GENUINE"}}},
                         {"seq": 1, "event": {"type": "enroll", "data": {"address": "0xdef", "device": "EMULATOR"}}}]}
    assert ui.device_labels(bundle) == {"0xabc": "GENUINE", "0xdef": "EMULATOR"}


def test_story_of_the_scenes_in_plain_words():
    """The Overview feed over a normal day, the lookalike BEC with agent escalation and the mailbox takeover."""
    from executor import e2e, scenes
    from host import story

    env = scenes.DemoEnv()
    e2e.run(env.call, env.clerk, env.treasury, now=env.now, log=lambda s: None)
    scenes.scene_s2(env, log=lambda s: None)
    scenes.scene_s3(env, log=lambda s: None)
    get = lambda path, key, who="host": env.call("GET", path, None, who)[1][key]  # noqa: E731
    bundle = env.call("GET", "/audit/export?log_id=audit&from_seq=0", None, "auditor")[1]
    kpis, cards = story.build(bundle, get("/vendors", "vendors"), get("/changes", "changes"),
                              get("/proposals", "proposals"))
    titles = " | ".join(c["title"] for c in cards)
    assert kpis["attacker_minor"] == 0 and kpis["paid_n"] == 5 and kpis["auto_n"] == 3
    for t in ("Paid automatically", "Needs a human", "Account-change attack stopped", "Mailbox takeover stopped",
              "Replay attack stopped", "Forged approval stopped", "Hijacked agent", "New account active"):
        assert t in titles, t
    assert kpis["attacks"] == sum(c["tone"] == "attack" for c in cards)
    assert cards[0]["seq"] > cards[-1]["seq"]  # newest first
    assert "embedded_reference" not in " ".join(c["body"] for c in cards)


def test_ui_renders_on_seeded_memory_executor(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AIRGAP_EXECUTOR_URL", "memory:")
    monkeypatch.setenv("AIRGAP_UI_REFRESH_S", "0")
    at = AppTest.from_file(UI_PATH, default_timeout=60).run()
    assert not at.exception
    assert [m.value for m in at.metric][1] == "0.00 CZK"  # paid to unregistered accounts


def test_expired_sign_in_is_named_not_shown_as_unreachable():
    assert ui._login_expired({"message": "The security token included in the request is expired"})
    assert ui._login_expired({"error": "unreachable",
                              "message": "TokenRetrievalError: Error when retrieving token from sso: Token has expired"})
    assert not ui._login_expired({"error": "unreachable", "message": "ConnectError: connection refused"})
    assert not ui._login_expired("text")


def test_assumed_role_credentials_are_reassumed_before_expiry(monkeypatch: pytest.MonkeyPatch):
    """A console left open longer than the 1 h STS session must not start failing with 'token expired'."""
    from datetime import datetime, timedelta, timezone

    from infra import aws_e2e

    issued: list[datetime] = []

    class Sts:
        def get_caller_identity(self):
            return {"Account": "503002144042"}

        def assume_role(self, **kw):
            exp = datetime.now(timezone.utc) + (timedelta(minutes=2) if not issued else timedelta(hours=1))
            issued.append(exp)
            return {"Credentials": {"AccessKeyId": f"AK{len(issued)}", "SecretAccessKey": "s", "SessionToken": "t",
                                    "Expiration": exp}}

    monkeypatch.setattr(aws_e2e.boto3, "client", lambda *a, **k: Sts())
    monkeypatch.setattr(aws_e2e, "_creds", {})
    assert aws_e2e.role_creds("host").access_key == "AK1"  # expires in 2 min: inside the 5 min margin
    assert aws_e2e.role_creds("host").access_key == "AK2"  # so it is re-assumed
    assert aws_e2e.role_creds("host").access_key == "AK2"  # and the fresh one is reused


def test_challenge_countdown(monkeypatch: pytest.MonkeyPatch):
    from datetime import datetime, timedelta, timezone

    monkeypatch.setattr(ui, "EXECUTOR", "https://example.execute-api.eu-central-1.amazonaws.com/prod")
    soon = (datetime.now(timezone.utc) + timedelta(seconds=130)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert 125 <= ui.expires_in({"exp": soon}) <= 130
    assert ui.expires_in({"exp": "2026-01-01T00:00:00Z"}) == 0
    assert ui.expires_in({}) is None
    monkeypatch.setattr(ui, "EXECUTOR", "memory:")  # seeded executor: fixed past clock, no countdown
    assert ui.expires_in({"exp": soon}) is None
