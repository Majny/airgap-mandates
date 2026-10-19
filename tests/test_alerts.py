"""Alert watcher (host/alerts.py) against the seeded in-process executor and a fake webhook. Owner: WS-F."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from host import alerts, story

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
    _, cards = story.build(bundle, get("/vendors", "vendors"), get("/changes", "changes"),
                           get("/proposals?limit=200", "proposals"))
    return [c for c in cards if c["tone"] == "attack"]


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
