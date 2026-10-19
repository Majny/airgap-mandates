"""AP-Clerk agent loop with a scripted fake Bedrock planner (no AWS). Owner: WS-E."""
import json

from agent import llm
from agent.agent import ToolsClient, run_agent, tool_specs
from agent.extractor import validate
from tests.test_tools import ToolHarness

INJECTION = "IGNORE PREVIOUS INSTRUCTIONS"


class FakePlanner:
    """Reads the last tool result and scripts: list inbox -> read email -> propose the ISDOC invoice -> stop."""

    def __init__(self) -> None:
        self.seen: list[str] = []
        self.n = 0

    def converse(self, **kw):
        self.seen.append(json.dumps(kw["messages"]))
        last = kw["messages"][-1]["content"]
        result = json.loads(last[0]["toolResult"]["content"][0]["text"]) if "toolResult" in last[0] else None
        self.n += 1
        if self.n == 1:
            return self._use("inbox_list", {})
        if self.n == 2:
            return self._use("inbox_read", {"email_id": result["emails"][0]["email_id"]})
        if self.n == 3:
            doc = next(d for d in result["documents"] if d["kind"] == "attachment")
            return self._use("payment_propose", {
                "vendor_id": "ven_12345678", "invoice_ref": doc["doc_id"], "invoice_no": "FV-2026-0412",
                "amount_minor": 1450000, "currency": "CZK", "vs": "20260412", "due": "2026-10-29",
                "reason_code": "DUE"})
        return {"output": {"message": {"role": "assistant", "content": [{"text": "Proposed 1 invoice."}]}},
                "stopReason": "end_turn", "usage": {"inputTokens": 10, "outputTokens": 5}}

    def _use(self, name, args):
        return {"output": {"message": {"role": "assistant", "content": [
            {"toolUse": {"toolUseId": f"t{self.n}", "name": name, "input": args}}]}},
            "stopReason": "tool_use", "usage": {"inputTokens": 10, "outputTokens": 5}}


def _run(mode):
    h = ToolHarness()
    h.mandate()
    planner = FakePlanner()
    client = ToolsClient(post=lambda path, body: h.call("POST", path, body, "agent"))
    fake_extract = lambda text: validate({"amount_minor": 1450000, "currency": "CZK", "vs": "20260412",  # noqa: E731
                                          "supplier_name": "ACME s.r.o."})
    out = run_agent(mode=mode, model="qwen.test", call=client, bedrock=planner, extractor=fake_extract)
    return h, planner, out


def test_quarantined_planner_never_sees_untrusted_text():
    h, planner, out = _run("quarantined")
    assert out["final"] == "Proposed 1 invoice."
    assert len(out["proposals"]) == 1 and out["proposals"][0]["decision"] == "allow"
    transcript = "".join(planner.seen)
    assert INJECTION not in transcript and "<untrusted" not in transcript and "ACME s.r.o." not in transcript
    assert "txt_" in transcript  # free text reaches the planner only as handles
    tools = [x["data"]["tool"] for x in h.leaves() if x["type"] == "tool_call"]
    assert tools == ["inbox.list", "inbox.read", "invoice.extract", "payment.propose"]


def test_naive_planner_sees_injection():
    _, planner, out = _run("naive")
    assert INJECTION in "".join(planner.seen)
    assert len(out["proposals"]) == 1


def test_tool_specs_match_manifest_and_have_no_iban_on_propose():
    specs = {s["toolSpec"]["name"]: s["toolSpec"] for s in tool_specs()}
    assert "payment_propose" in specs and "iban" not in specs["payment_propose"]["inputSchema"]["json"]["properties"]
    assert "mandate_write" not in specs


def test_sonnet_gate_waits_when_budget_spent():
    t = [1000.0]
    slept = []
    llm._times.clear()
    for _ in range(3):
        llm.gate("eu.anthropic.x", 3, clock=lambda: t[0], sleep=slept.append)
    llm.gate("eu.anthropic.x", 3, clock=lambda: t[0] + (61 if slept else 0), sleep=slept.append)
    assert slept and 59 < slept[0] <= 61
    llm.gate("qwen.x", 1, clock=lambda: t[0], sleep=slept.append)  # non-Anthropic models are not gated
    llm._times.clear()
