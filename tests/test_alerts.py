"""Alert watcher (host/alerts.py) against the seeded in-process executor and a fake webhook. Owner: WS-F."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from host import alerts

EXPECTED = ("Payment blocked", "Account-change attack stopped", "Mailbox takeover stopped", "Replay attack stopped",
            "Forged approval stopped", "Hijacked agent")


@pytest.fixture(scope="module")
def call() -> alerts.Call:
    return alerts.memory_call()


class Hook:
    def __init__(self, codes: list[int] | None = None) -> None:
        self.got: list[dict[str, Any]] = []
        self.codes = codes or []

    def __call__(self, url: str, payload: dict[str, Any]) -> int:
        code = self.codes.pop(0) if self.codes else 200
        if code == 200:
            self.got.append(payload)
        return code


def _attack_cards(call: alerts.Call) -> list[dict[str, Any]]:
    get = lambda p, k: call("GET", p, None, "auditor")[1][k]  # noqa: E731
    bundle = call("GET", "/audit/export?log_id=audit&from_seq=0", None, "auditor")[1]
    return alerts.alert_items(bundle["leaves"], get("/vendors", "vendors"), get("/changes", "changes"),
                              get("/proposals?limit=200", "proposals"))


def test_from_start_posts_every_blocked_attempt_once(call: alerts.Call):
    hook = Hook()
    w = alerts.Watcher(call, hook, "https://hooks.example/x", deployment="DEMO", from_start=True, out=lambda s: None)
    n = w.poll()
    texts = [m["text"] for m in hook.got]
    assert n == len(hook.got) == len(_attack_cards(call)) > 0
    for t in EXPECTED:
        assert any(t in x for x in texts), t
    assert all(set(m) == {"text"} and "[DEMO]" in m["text"] and "audit log seq" in m["text"] for m in hook.got)
    seqs = [int(x.split("audit log seq ")[1].split(";")[0]) for x in texts]
    assert seqs == sorted(seqs)  # oldest first
    assert w.poll() == 0 and len(hook.got) == n  # nothing new, nothing re-sent


def test_default_starts_at_the_head(call: alerts.Call):
    hook, lines = Hook(), []
    w = alerts.Watcher(call, hook, "https://hooks.example/x", out=lines.append)
    assert w.poll() == 0 and not hook.got
    assert "watching from audit seq" in lines[0]


def test_new_attack_after_baseline_is_posted(call: alerts.Call):
    """Only leaves after the watermark alert; earlier leaves stay available as context for the story."""
    hook = Hook()
    cards = _attack_cards(call)
    last = max(c["seq"] for c in cards)
    w = alerts.Watcher(call, hook, "https://hooks.example/x", out=lambda s: None)
    w.poll()
    w.alerted_seq = last - 1  # pretend the newest blocked attempt happened after we started
    assert w.poll() == 1
    assert str(last) in hook.got[0]["text"]


def test_webhook_outage_delays_but_never_drops(call: alerts.Call, tmp_path):
    state = tmp_path / "alerts.json"
    hook = Hook(codes=[200, 500])
    w = alerts.Watcher(call, hook, "https://hooks.example/x", state_file=state, from_start=True, out=lambda s: None)
    assert w.poll() == 1  # the second post failed: stop there, keep order
    first = json.loads(state.read_text())["alerted_seq"]
    w2 = alerts.Watcher(call, hook, "https://hooks.example/x", state_file=state, out=lambda s: None)  # restart
    total = len(_attack_cards(call))
    assert w2.poll() == total - 1
    assert len(hook.got) == total and len({m["text"] for m in hook.got}) == total
    assert json.loads(state.read_text())["alerted_seq"] > first


def test_lost_contact_is_reported_once_then_restored(call: alerts.Call):
    hook = Hook()
    down = {"on": True}

    def flaky(m: str, p: str, b: Any, who: str) -> tuple[int, Any]:
        assert who == "auditor"  # read-only principal
        return (0, {"error": "unreachable"}) if down["on"] else call(m, p, b, who)

    w = alerts.Watcher(flaky, hook, "https://hooks.example/x", out=lambda s: None)
    for _ in range(5):
        w.poll()
    assert len(hook.got) == 1 and "lost contact" in hook.got[0]["text"]
    down["on"] = False
    w.poll()
    assert len(hook.got) == 2 and "in contact with the executor again" in hook.got[1]["text"]


def test_dry_run_prints(call: alerts.Call):
    lines: list[str] = []
    w = alerts.Watcher(call, None, None, from_start=True, out=lines.append)
    assert w.poll() == len(_attack_cards(call)) == len(lines)
    assert any("Mailbox takeover stopped" in x for x in lines)


def test_cli_posts_to_a_real_http_receiver():
    got: list[dict[str, Any]] = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a: Any) -> None:
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_port}/hook"
        assert alerts.main(["--url", "memory:", "--webhook", url, "--allow-http", "--from-start", "--once"]) == 0
    finally:
        srv.shutdown()
    assert got and all(set(m) == {"text"} for m in got)
    assert any("Hijacked agent" in m["text"] for m in got)


def test_cli_refuses_plain_http_webhook():
    with pytest.raises(SystemExit):
        alerts.main(["--url", "memory:", "--webhook", "http://hooks.example/x", "--once"])


def test_messages_name_the_attack_and_how_it_was_stopped(call: alerts.Call):
    """Same vocabulary as the console's Security tab and the ops log: kind, what this is, how stopped, money moved."""
    hook = Hook()
    alerts.Watcher(call, hook, "https://hooks.example/x", deployment="DEMO", from_start=True, out=lambda s: None).poll()
    texts = [m["text"] for m in hook.got]
    assert all(("stopped · " in t or "suspected, on hold" in t) and "Money moved to the attacker: 0.00 CZK" in t
               for t in texts)
    assert any("Payment fraud (BEC) stopped · lookalike domain (BEC)" in t and "How it was stopped:" in t
               for t in texts)
    assert any("Replay / forgery stopped · replayed approval" in t for t in texts)
    assert any("What this is: Business email fraud" in t for t in texts)
    # Track 3: the defence layer and its evidence, and the explainability line
    assert any("Stopped by: executor facts + policy, because F-DOMAIN:" in t for t in texts)
    assert any("Stopped by: hardware signature, because nonce_reused:" in t for t in texts)
    assert all("deterministic: no LLM in the decision path" in t for t in texts)


def test_breach_and_explainer_only_attacks_are_posted():
    """A payment to an account outside the vendor master is a loud breach message; a fake attestation (no story card)
    still alerts."""
    vendors = [{"vendor_id": "ven_1", "name": "ACME", "iban": "CZ6508000000192000145399", "domain": "acme.cz"}]
    leaves = [{"seq": 1, "event": {"type": "execution", "subject_id": "tx_1", "ts": "2026-10-20T09:00:00Z",
                                   "data": {"amount_minor": 500000, "iban": "LT483999000000001234",
                                            "vendor_id": "ven_1", "proposal_id": "prp_1", "tx_id": "tx_1",
                                            "authorization": {"kind": "mandate", "mandate_id": "mnd_1"}}}},
              {"seq": 2, "event": {"type": "change_event", "subject_id": "chg_1", "ts": "2026-10-20T09:01:00Z",
                                   "data": {"change_id": "chg_1", "event": "vc_rejected",
                                            "detail": {"error": "vc_invalid"}}}}]
    items = alerts.alert_items(leaves, vendors, [], [])
    texts = [alerts.message(i, "DEMO")["text"] for i in items]
    assert "MONEY LEFT THE BANK" in texts[0] and "5 000.00 CZK" in texts[0] and "LT48 …1234" in texts[0]
    assert "Replay / forgery stopped · fake attestation" in texts[1]


def test_held_mailbox_takeover_is_posted():
    """Attack b (held payee change with takeover red flags) has no ATTACK leaf until "not us", but the Security tab
    shows it, so the webhook gets it too, keyed by the change's CREATE leaf so the watermark still works."""
    leaves = [{"seq": 4, "event": {"type": "change_event", "subject_id": "chg_1", "ts": "2026-10-20T09:00:00Z",
                                   "data": {"change_id": "chg_1", "event": "facts_computed"}}},
              {"seq": 6, "event": {"type": "state_transition", "subject_id": "chg_1", "ts": "2026-10-20T09:00:01Z",
                                   "data": {"change_id": "chg_1", "event": "CREATE", "to": "PENDING_ATTEST"}}}]
    changes = [{"change_id": "chg_1", "vendor_id": "ven_1", "vendor_name": "ACME s.r.o.", "state": "PENDING_ATTEST",
                "new_iban": "LT493250000000005678", "attest_count": 0,
                "facts": [{"id": "F-VOP", "kind": "F", "severity": "WARN", "label": "VoP close match"},
                          {"id": "F-BANK", "kind": "F", "severity": "WARN", "label": "foreign bank"}]}]
    items = alerts.alert_items(leaves, [], changes, [])
    assert [(i["seq"], i["kind"]) for i in items] == [(6, "mailbox takeover?")]
    text = alerts.message(items[0], "DEMO")["text"]
    assert "Account takeover suspected, on hold · mailbox takeover" in text and "LT49 …5678" in text
    assert "Held by: executor facts + policy, because F-BANK:" in text and "+1 more red flag" in text
    assert "0.00 CZK" in text and "LT493250000000005678" not in text
    changes[0]["state"] = "REJECTED"  # once decided, the leaf explainer takes over
    assert alerts.alert_items(leaves, [], changes, []) == []


def test_request_level_attacks_are_posted(tmp_path, monkeypatch):
    """Attack d (stolen agent credentials) writes no audit leaf: the executor's ring (executor.oplog) carries it, so
    the webhook still gets "Privilege escalation stopped", once, with the refused request named."""
    from attacker import attacks
    from executor import scenes

    monkeypatch.setenv("AIRGAP_IMPLANT_DIR", str(tmp_path / "implant"))
    env = scenes.DemoEnv()
    env.active_mandate()
    hook = Hook()
    w = alerts.Watcher(env.call, hook, "https://hooks.example/x", deployment="DEMO", out=lambda s: None)
    assert w.poll() == 0  # baseline
    attacks.run_attack("stolen_agent_creds", attacks.Session(env.call, data_dir=env.settings.data_dir))
    w.poll()
    texts = [m["text"] for m in hook.got]
    door = [t for t in texts if "refused at the door" in t]
    assert any("Privilege escalation stopped · stolen agent credentials" in t and "POST /signatures by agent" in t
               and "caller_not_allowed" in t for t in door), texts
    assert any("IBAN injection" in t and "no IBAN argument" in t for t in door)
    assert any("Data exfiltration stopped" in t for t in texts)  # the tool calls do write leaves
    n = len(hook.got)
    assert w.poll() == 0 and len(hook.got) == n  # nothing re-sent
