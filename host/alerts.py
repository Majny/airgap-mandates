"""Alert watcher (`make alerts`): post every blocked attempt to a Slack / Teams incoming webhook. Owner: WS-F.

    python -m host.alerts --url <executor> --webhook <https url> [--interval 10] [--state-file F] [--dry-run]

It polls `GET /audit/export?from_seq=<next>` with the read-only auditor principal, keeps the leaves it has seen,
and runs them through `host.story.build()` (the same plain-language titles as the console). Every new card with
the "attack" tone becomes one message `{"text": ...}`: a denied payment proposal, a payee change rejected on
arrival or by the "not us" tripwire, a refused hardware signature (replay, forged or self-approval), a forbidden
agent tool call.

Delivery is at-least-once: the watermark (`alerted_seq`, optionally persisted with --state-file) only moves past an
alert after the webhook answered 2xx, so a webhook outage delays alerts instead of dropping them. After three failed
polls in a row it posts one "lost contact with the executor" message, and one "contact restored" when it recovers:
a silent watcher must not look like a quiet day.

Like the console this is an untrusted reading aid (TB3): the signed, witnessed audit log stays the record.
`--url memory:` runs against the seeded in-process executor (demo and tests, no AWS).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Callable

from host import story

Call = Callable[[str, str, Any, str], tuple[int, Any]]
Post = Callable[[str, dict[str, Any]], int]
LOST_AFTER = 3


def memory_call() -> Call:
    """Seeded in-process executor: normal day, lookalike BEC with escalation, takeover + legitimate change."""
    from executor import e2e, scenes

    env = scenes.DemoEnv()
    e2e.run(env.call, env.clerk, env.treasury, now=env.now, log=lambda s: None)
    scenes.scene_s2(env, log=lambda s: None)
    scenes.scene_s3(env, log=lambda s: None)
    return env.call


def http_post(timeout: float = 10.0) -> Post:
    import httpx

    def post(url: str, payload: dict[str, Any]) -> int:
        return httpx.post(url, json=payload, timeout=timeout).status_code

    return post


def message(card: dict[str, Any], deployment: str) -> dict[str, Any]:
    """Slack and Teams incoming webhooks both render a plain {"text": ...}."""
    body = f"\n{card['body']}" if card.get("body") else ""
    return {"text": f"\U0001F6D1 AirGap Mandates [{deployment}]: {card['title']}{body}\n"
                    f"(audit log seq {card['seq']}; verify offline with tools.verify_audit)"}


class Watcher:
    def __init__(self, call: Call, post: Post | None, webhook: str | None, *, deployment: str = "?",
                 state_file: Path | None = None, from_start: bool = False,
                 out: Callable[[str], None] = print) -> None:
        self.call, self.post, self.webhook, self.deployment = call, post, webhook, deployment
        self.state_file, self.out = state_file, out
        self.leaves: dict[int, dict[str, Any]] = {}
        self.next_seq = 0
        self.failures = 0
        self.lost_reported = False
        saved = self._load_state()
        # None = no baseline yet: the first poll marks everything already in the log as seen (unless --from-start)
        self.alerted_seq: int | None = saved if saved is not None else (-1 if from_start else None)

    # ---------------------------------------------------------------- state
    def _load_state(self) -> int | None:
        if self.state_file and self.state_file.exists():
            return int(json.loads(self.state_file.read_text())["alerted_seq"])
        return None

    def _save_state(self) -> None:
        if self.state_file and self.alerted_seq is not None:
            tmp = self.state_file.with_suffix(".tmp")
            tmp.write_text(json.dumps({"alerted_seq": self.alerted_seq}))
            tmp.replace(self.state_file)

    # ---------------------------------------------------------------- delivery
    def _send(self, payload: dict[str, Any]) -> bool:
        if self.post is None or not self.webhook:  # --dry-run
            self.out(payload["text"])
            return True
        try:
            code = self.post(self.webhook, payload)
        except Exception as e:  # noqa: BLE001 - network error: retry on the next poll
            print(f"alerts: webhook error {type(e).__name__}: {e}"[:300], file=sys.stderr)
            return False
        if not 200 <= code < 300:
            print(f"alerts: webhook answered {code}", file=sys.stderr)
        return 200 <= code < 300

    def _get(self, path: str) -> Any:
        code, body = self.call("GET", path, None, "auditor")
        if code != 200 or not isinstance(body, dict):
            raise RuntimeError(f"GET {path.split('?')[0]} -> {code}")
        return body

    # ---------------------------------------------------------------- one poll
    def poll(self) -> int:
        """Fetch new leaves, post new blocked attempts; returns the number of alerts delivered."""
        try:
            bundle = self._get(f"/audit/export?log_id=audit&from_seq={self.next_seq}")
            vendors = self._get("/vendors").get("vendors", [])
            changes = self._get("/changes").get("changes", [])
            proposals = self._get("/proposals?limit=200").get("proposals", [])
        except Exception as e:  # noqa: BLE001 - unreachable executor, expired credentials
            self.failures += 1
            print(f"alerts: poll failed ({self.failures}): {e}"[:300], file=sys.stderr)
            if self.failures >= LOST_AFTER and not self.lost_reported:
                self.lost_reported = self._send({"text": f"⚠️ AirGap Mandates [{self.deployment}]: alert "
                                                         f"watcher lost contact with the executor ({e})."[:500]})
            return 0
        self.failures = 0
        if self.lost_reported and self._send({"text": f"AirGap Mandates [{self.deployment}]: alert watcher is "
                                                      "in contact with the executor again."}):
            self.lost_reported = False
        for leaf in bundle.get("leaves", []):
            self.leaves[int(leaf["seq"])] = leaf
        if self.leaves:
            self.next_seq = max(self.leaves) + 1
        _, cards = story.build({"leaves": list(self.leaves.values())}, vendors, changes, proposals)
        if self.alerted_seq is None:
            self.alerted_seq = self.next_seq - 1
            self._save_state()
            self.out(f"alerts: watching from audit seq {self.next_seq} ({len(self.leaves)} earlier entries skipped)")
            return 0
        sent = 0
        for card in sorted((c for c in cards if c["tone"] == "attack" and c["seq"] > self.alerted_seq),
                           key=lambda c: c["seq"]):
            if not self._send(message(card, self.deployment)):
                break  # keep order; this one and the rest go out on the next poll
            self.alerted_seq = card["seq"]
            sent += 1
        if sent:
            self._save_state()
        return sent


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--url", required=True, help="executor URL (AWS execute-api, http://... or memory:)")
    ap.add_argument("--webhook", help="Slack/Teams incoming webhook URL (https)")
    ap.add_argument("--interval", type=float, default=10.0, help="seconds between polls (default 10)")
    ap.add_argument("--dry-run", action="store_true", help="print alerts instead of posting them")
    ap.add_argument("--state-file", type=Path, help="persist the last alerted audit seq here (survives restarts)")
    ap.add_argument("--from-start", action="store_true", help="also alert on blocked attempts already in the log")
    ap.add_argument("--once", action="store_true", help="poll once and exit (cron, tests)")
    ap.add_argument("--allow-http", action="store_true", help="allow a plain-http webhook (local testing only)")
    a = ap.parse_args(argv)
    if not a.dry_run:
        if not a.webhook:
            ap.error("--webhook is required unless --dry-run")
        if not a.webhook.startswith("https://") and not a.allow_http:
            ap.error("the webhook must be https:// (use --allow-http only for a local test receiver)")
    if a.url.startswith("memory:"):
        call = memory_call()
    else:
        from host.signer import executor_call
        call = executor_call(a.url)
    code, health = call("GET", "/health", None, "auditor")
    deployment = health.get("deployment", "?") if code == 200 and isinstance(health, dict) else "?"
    w = Watcher(call, None if a.dry_run else http_post(), a.webhook, deployment=deployment,
                state_file=a.state_file, from_start=a.from_start)
    while True:
        w.poll()
        if a.once:
            return 0
        time.sleep(a.interval)


if __name__ == "__main__":
    sys.exit(main())
