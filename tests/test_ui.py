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
