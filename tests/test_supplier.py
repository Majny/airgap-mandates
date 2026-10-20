"""Supplier side (supplier/send.py, supplier/console.py on :8503): a registered supplier sends a new invoice email,
the bank's agent proposes it (scripted step), and the executor's decision comes back in plain words. Runs on the
in-memory executor (executor.scenes.DemoEnv + e2e.run for the mandate and the normal day). Owner: orchestrator."""
from __future__ import annotations

from pathlib import Path

import pytest

from executor import e2e
from executor.scenes import DemoEnv
from supplier import send

GAMMA, DELTA = "ven_99887762", "ven_77665546"


def _env() -> DemoEnv:
    env = DemoEnv()
    e2e.run(env.call, env.clerk, env.treasury, now=env.now, log=lambda s: None)  # mandate + the normal day
    return env


def test_small_invoice_is_paid_automatically():
    env = _env()
    out = send.send(env.call, GAMMA, 1_250_000, invoice_no="INV-T-1")
    assert out["raw"]["decision"]["decision"] == "allow"
    assert out["kind"] == "paid" and out["text"].startswith("Paid automatically") and out["tx_id"]
    assert send.status(env.call, out["proposal_id"])["kind"] == "paid"


def test_over_cap_waits_for_the_trezor():
    env = _env()
    out = send.send(env.call, DELTA, 11_875_000, invoice_no="INV-T-2")
    assert out["raw"]["decision"]["decision"] == "challenge"
    assert out["raw"]["proposal"]["status"] == "PENDING_SIG"
    assert out["kind"] == "waiting" and "approve on the Trezor" in out["text"] and "(local time)" in out["text"]
    live = send.status(env.call, out["proposal_id"])
    assert live["kind"] == "waiting" and live["expires"] == out["expires"] != "?"


def test_same_supplier_again_same_day_is_refused_in_plain_words():
    env = _env()
    assert send.send(env.call, GAMMA, 5_000_000, invoice_no="INV-T-3")["kind"] == "paid"
    out = send.send(env.call, GAMMA, 5_000_000, invoice_no="INV-T-4")  # new number, same amount and date
    assert out["raw"]["decision"]["decision"] == "deny"
    assert out["kind"] == "refused" and "already paid today" in out["text"]
    assert "F-" not in out["text"]  # plain words, no rule ids
    assert send.status(env.call, out["proposal_id"])["kind"] == "refused"


def test_same_supplier_split_waits_for_the_clerk_and_says_why():
    env = _env()
    assert send.send(env.call, GAMMA, 5_000_000, invoice_no="INV-T-8")["kind"] == "paid"
    out = send.send(env.call, GAMMA, 4_000_000, invoice_no="INV-T-9")  # 50k + 40k today > the 80k cap (F-SPLIT)
    assert out["kind"] == "waiting" and "already paid today" in out["why"]


def test_duplicate_invoice_is_refused_in_plain_words():
    env = _env()
    assert send.send(env.call, GAMMA, 1_000_000, invoice_no="INV-T-5")["kind"] == "paid"
    out = send.send(env.call, GAMMA, 1_000_000, invoice_no="INV-T-5")
    assert out["kind"] == "refused" and "already paid" in out["text"]


def test_cap_from_the_active_mandate():
    env = _env()
    assert send.cap_minor(env.call) == 8_000_000
    assert send.cap_minor(DemoEnv().call) is None  # no mandate yet


def test_lambda_agent_reads_back_the_executor_decision():
    """The real-agent step (AWS) is mocked by a scripted proposal; the outcome is still read from the executor."""
    env = _env()
    tasks: list[str] = []
    box: dict = {}

    def invoke(task: str) -> dict:  # stands in for the agent Lambda: it proposes the cited invoice as "tools"
        tasks.append(task)
        assert box["cited"]["email_id"] in task
        env.call("POST", "/proposals", {"invoice": box["cited"], "hints": []}, "tools")
        return {"final": "proposed"}

    def agent(cited: dict):
        box["cited"] = cited
        return send.lambda_agent(env.call, invoke)(cited)

    out = send.send(env.call, DELTA, 11_875_000, invoice_no="INV-T-6", agent=agent)
    assert out["kind"] == "waiting" and out["expires"] != "?"
    assert tasks and "executor decides" in tasks[0]


def test_lambda_agent_no_proposal_is_an_error_not_a_crash():
    env = _env()
    out = send.send(env.call, GAMMA, 100_000, invoice_no="INV-T-7",
                    agent=send.lambda_agent(env.call, lambda t: {"final": "skipped"}))
    assert out["kind"] == "error" and "no proposal" in out["text"]


# ------------------------------------------------------------------ the page (Streamlit AppTest, in-process memory:)
pytest.importorskip("streamlit")
CONSOLE = str(Path(__file__).resolve().parents[1] / "supplier" / "console.py")


def _app(monkeypatch: pytest.MonkeyPatch, url: str):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("AIRGAP_SUPPLIER_URL", url)
    return AppTest.from_file(CONSOLE, default_timeout=60).run()


def test_console_sends_an_invoice_on_memory(monkeypatch: pytest.MonkeyPatch):
    at = _app(monkeypatch, "memory:")
    assert not at.exception
    page = " ".join(m.value for m in at.markdown)
    assert "Supplier mail" in page and "LOCAL" in page
    assert any("80 000.00 CZK" in c.value for c in at.caption), [c.value for c in at.caption]
    at.selectbox(key="vendor").set_value("ven_99887762")
    at.number_input(key="amount").set_value(12_500.0)
    at.button(key="send").click().run()
    assert not at.exception
    assert any("Paid automatically" in m.value for m in at.success), [m.value for m in at.success]
    at.selectbox(key="vendor").set_value("ven_77665546")
    at.number_input(key="amount").set_value(118_750.0)
    at.button(key="send").click().run()
    assert any("approve on the Trezor" in m.value for m in at.info), [m.value for m in at.info]
    assert not at.exception


def test_console_degrades_without_executor(monkeypatch: pytest.MonkeyPatch):
    at = _app(monkeypatch, "http://127.0.0.1:9")
    assert not at.exception
    at.button(key="send").click().run()
    assert not at.exception
    assert at.error, "an unreachable bank must show an error, not crash"
