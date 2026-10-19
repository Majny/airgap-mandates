"""Host UI smoke tests (headless Streamlit AppTest). Owner: WS-F."""
from __future__ import annotations

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

from host import ui  # noqa: E402


def _run(monkeypatch: pytest.MonkeyPatch, trezor_path: str = "") -> AppTest:
    monkeypatch.setenv("AIRGAP_EXECUTOR_URL", "http://127.0.0.1:9")  # unreachable: every tab must degrade, not crash
    monkeypatch.setenv("AIRGAP_TREZOR_PATH", trezor_path)
    return AppTest.from_file("host/ui.py", default_timeout=30).run()


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
