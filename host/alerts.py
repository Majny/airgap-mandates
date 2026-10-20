"""Alert watcher (`make alerts`): post every blocked attempt to a Slack / Teams incoming webhook. Owner: WS-F.

    python -m host.alerts --url <executor> --webhook <https url> [--interval 10] [--state-file F] [--dry-run]

It polls `GET /audit/export?from_seq=<next>` with the read-only auditor principal, keeps the leaves it has seen,
and runs them through `host.story.build()` and `executor.audit.explain` (the same vocabulary as the console's
Security tab and the executor's ops log). Every new attack becomes one message `{"text": ...}` saying the kind of
attack, what happened, how it was stopped and that no money moved: a denied payment proposal, a payee change rejected
on arrival or by the "not us" tripwire, a refused hardware signature (replay, forged, tampered), a forbidden agent
tool call, a fake supplier attestation, an instruction smuggled into an invoice. A payment to an account outside the
vendor master is posted as a breach. Request-level attacks that write no audit leaf (stolen agent credentials, an
account number smuggled into a request) come from the executor's ring (executor.oplog.fetch_recent: the loopback
stack's read-only RECENT_PATH, or the in-process executor of --url memory:); against AWS they are CloudWatch lines.
Titles carry the Track 3 threat label ("🛑 Prompt injection stopped: …") and the defence layer + evidence.

Delivery is at-least-once: the watermark (`alerted_seq`, optionally persisted with --state-file) only moves past an
alert after the webhook answered 2xx, so a webhook outage delays alerts instead of dropping them. After three failed
polls in a row it posts one "lost contact with the executor" message, and one "contact restored" when it recovers:
a silent watcher must not look like a quiet day.

Like the console this is an untrusted reading aid (TB3): the signed, witnessed audit log stays the record.
`--url memory:` runs against the seeded in-process executor (demo and tests, no AWS).
"""
from __future__ import annotations

import argparse
import html
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Callable

from executor import oplog
from executor.audit import explain as X
from host import story

Call = Callable[[str, str, Any, str], tuple[int, Any]]
Post = Callable[[str, dict[str, Any]], int]
LOST_AFTER = 3


def memory_call() -> Call:
    """Seeded in-process executor: normal day, lookalike BEC with escalation, takeover + legitimate change."""
    from executor import e2e, scenes

    env = scenes.DemoEnv()
    with oplog.replay("S2+S3"):  # the seeded scenes are a demo replay, also in the request-level ring
        e2e.run(env.call, env.clerk, env.treasury, now=env.now, log=lambda s: None)
        scenes.scene_s2(env, log=lambda s: None)
        scenes.scene_s3(env, log=lambda s: None)
    return env.call


def http_post(timeout: float = 10.0) -> Post:
    import httpx

    def post(url: str, payload: dict[str, Any]) -> int:
        return httpx.post(url, json=payload, timeout=timeout).status_code

    return post


def alert_items(leaves: list[dict[str, Any]], vendors: list[dict[str, Any]], changes: list[dict[str, Any]],
                proposals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every attack in the leaves, oldest first: the console's attack cards (story.build) with the explainer's kind
    and how it was stopped, plus attacks and breaches only the explainer names (fake attestation, prompt injection,
    money to an unregistered account). One item per audit seq. The explainer decides what is an attack, exactly as
    on the Security tab: a lone expired approval (maybe a slow clerk), a hard block that is not hostile (an
    unreliable VAT payer) or a bank rejection is not posted."""
    _, cards = story.build({"leaves": leaves}, vendors, changes, proposals)
    xs = {x.seq: x for x in X.explain_all(leaves, vendors, changes, proposals) if x.seq is not None}
    alarming = {seq for seq, x in xs.items() if x.level == X.ATTACK or X.is_breach(x)}
    items: dict[int, dict[str, Any]] = {}
    for c in cards:
        if c["tone"] == "attack" and c["seq"] in alarming:
            x = xs[c["seq"]]
            items[c["seq"]] = {**c, "level": x.level, "kind": x.kind, "why": x.why, "money_minor": x.money_minor,
                               **_stop(x)}
    for seq in sorted(alarming - set(items)):
        x = xs[seq]
        items[seq] = {"seq": seq, "tone": "attack", "title": x.title, "body": "", "level": x.level,
                      "kind": x.kind, "why": x.why, "money_minor": x.money_minor, **_stop(x)}
    for c in changes or []:  # a held payee change with takeover red flags: no leaf says "attack" until "not us"
        risk = X.change_risk(c)
        seq = _create_seq(leaves, str(c.get("change_id") or "")) if risk is not None else None
        if risk is not None and seq is not None and seq not in items:
            items[seq] = {"seq": seq, "tone": "attack", "title": risk.title, "body": "", "level": risk.level,
                          "kind": risk.kind, "why": risk.why, "money_minor": risk.money_minor,
                          "headline": "SUSPECTED ATTACK, ON HOLD", **_stop(risk)}
    return [items[k] for k in sorted(items)]


def _stop(x: Any) -> dict[str, Any]:
    return {"threat": x.threat, "layer": x.layer, "evidence": x.evidence}


def refusal_items(recent: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Request-level attacks (executor.oplog ring, no audit leaf) as alert items, oldest first. Skips the seeded demo
    backdrop and held payee changes (alert_items has those from GET /changes)."""
    out = []
    for d in recent or []:
        if not isinstance(d, dict) or d.get("scene") or d.get("level") != X.ATTACK or d.get("subject"):
            continue
        out.append({"seq": None, "n": d.get("n"), "tone": "attack", "title": d.get("title") or "", "body": "",
                    "level": d.get("level"), "kind": d.get("kind"), "why": d.get("why") or "",
                    "money_minor": d.get("money_minor"), "threat": d.get("threat"), "layer": d.get("layer"),
                    "evidence": d.get("evidence"),
                    "ref": f"refused at the door: {d.get('method')} {d.get('path')} by {d.get('principal')} -> HTTP "
                           f"{d.get('status')}, no audit entry; ops log req={d.get('req')}"})
    return out


def _create_seq(leaves: list[dict[str, Any]], change_id: str) -> int | None:
    """Audit seq of the change's CREATE transition (the incident's own entry), else its first leaf; None if absent."""
    first = None
    for le in X._rows(leaves):
        ev = X._dict(le.get("event"))
        d = X._dict(ev.get("data"))
        if change_id and change_id in (ev.get("subject_id"), d.get("change_id")):
            if ev.get("type") == "state_transition" and d.get("event") == "CREATE":
                return X._seq(le)
            first = X._seq(le) if first is None else first
    return first


def _plain(text: Any) -> str:
    """Story card text (HTML-escaped, may carry <b>) as chat text, every IBAN masked (CZ65 …5399)."""
    return X.mask_ibans(html.unescape(re.sub(r"<[^>]+>", "", str(text or ""))))


def message(card: dict[str, Any], deployment: str) -> dict[str, Any]:
    """Slack and Teams incoming webhooks both render a plain {"text": ...}."""
    kind = str(card.get("kind") or "").rstrip("?")
    threat = str(card.get("threat") or "")
    label = X.threat_title(threat) if threat else (kind[:1].upper() + kind[1:] if kind else "Attack")
    if X.is_breach(card):  # only money to an account outside the vendor master; never a bank rejection
        head = f"\U0001F4A5 AirGap Mandates [{deployment}] MONEY LEFT THE BANK" + (f" · {kind}" if kind else "")
        money = f"Money moved: {X.czk(card.get('money_minor'))} to an account outside the vendor master. Act now."
    elif card.get("headline"):  # a held payee change: suspected, not yet proven
        head = f"\u23F8 AirGap Mandates [{deployment}] {label} suspected, on hold" + (f" · {kind}" if kind else "")
        money = "Money moved to the attacker: 0.00 CZK"
    else:  # "🛑 Prompt injection stopped: …" (Track 3 vocabulary, as in the ops log and the Security tab)
        head = f"\U0001F6D1 AirGap Mandates [{deployment}] {label} stopped" + (f" · {kind}" if kind else "")
        money = "Money moved to the attacker: 0.00 CZK"
    why = _plain(card.get("why"))
    lines = [f"{head}: {_plain(card['title'])}"]
    if card.get("layer"):
        lines.append(f"{'Held' if card.get('headline') else 'Stopped'} by: {card['layer']}"
                     + (f", because {_plain(card.get('evidence'))}" if card.get("evidence") else ""))
    body = _plain(card.get("body"))
    if body and body.rstrip(".")[:40] not in why:  # skip a body the why line repeats
        lines.append(body)
    if kind and X.KIND_PLAIN.get(card.get("kind") or ""):
        lines.append(f"What this is: {X.KIND_PLAIN[card['kind']]}")
    if why:
        lines.append(f"{'Why it is held' if card.get('headline') else 'How it was stopped'}: {why}")
    if card.get("money_minor") and not X.is_breach(card):
        lines.append(f"At stake: {X.czk(card['money_minor'])}")
    lines.append(money)
    if card.get("seq") is None:
        lines.append(f"({card.get('ref') or 'refused at the door: no audit entry, see the ops log'})")
    else:
        lines.append(f"(audit log seq {card['seq']}; {X.DETERMINISTIC}; decision replayed offline with "
                     "tools.verify_audit)")
    return {"text": "\n".join(lines)}


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
        saved, saved_n = self._load_state()
        # request-level attacks (oplog ring) already alerted; None = no baseline yet (set on the first poll)
        self.recent_n: int | None = saved_n if saved_n is not None else (0 if from_start else None)
        # None = no baseline yet: the first poll marks everything already in the log as seen (unless --from-start)
        self.alerted_seq: int | None = saved if saved is not None else (-1 if from_start else None)

    # ---------------------------------------------------------------- state
    def _load_state(self) -> tuple[int | None, int | None]:
        """(alerted_seq, recent_n) from --state-file; recent_n is None in a state file of an older watcher."""
        if self.state_file and self.state_file.exists():
            st = json.loads(self.state_file.read_text())
            n = st.get("recent_n")
            return int(st["alerted_seq"]), int(n) if isinstance(n, int) else None
        return None, None

    def _save_state(self) -> None:
        if self.state_file and self.alerted_seq is not None:
            tmp = self.state_file.with_suffix(".tmp")
            tmp.write_text(json.dumps({"alerted_seq": self.alerted_seq, "recent_n": self.recent_n}))
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
        items = alert_items(sorted(self.leaves.values(), key=lambda le: le["seq"]), vendors, changes, proposals)
        recent = oplog.fetch_recent(self.call)
        if self.recent_n is None:  # no baseline for the ring (first poll, or a state file without recent_n)
            self.recent_n = max((int(d.get("n") or 0) for d in recent), default=0)
            self._save_state()
        if self.alerted_seq is None:
            self.alerted_seq = self.next_seq - 1
            self._save_state()
            self.out(f"alerts: watching from audit seq {self.next_seq} ({len(self.leaves)} earlier entries skipped)")
            return 0
        sent = 0
        for card in (c for c in items if c["seq"] > self.alerted_seq):
            if not self._send(message(card, self.deployment)):
                break  # keep order; this one and the rest go out on the next poll
            self.alerted_seq = card["seq"]
            sent += 1
        if sent:
            self._save_state()
        for card in refusal_items([d for d in recent if int(d.get("n") or 0) > (self.recent_n or 0)]):
            if not self._send(message(card, self.deployment)):
                break
            self.recent_n = int(card["n"])
            self._save_state()
            sent += 1
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
