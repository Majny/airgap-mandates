"""Agent Lambda (VPC, no IGW/NAT; only bedrock-runtime + execute-api endpoints). Owner: WS-E.

Events: {"task": ..., "mode": "naive"|"quarantined"} runs one episode against the private tools API;
{"action": "probe_egress"} tries to reach the internet and must fail (S10 evidence, tests/test_egress.py).
"""
from __future__ import annotations

import socket
import urllib.request
from typing import Any


def probe_egress(urls: tuple[str, ...] = ("https://example.com", "https://checkip.amazonaws.com")) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for url in urls:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:  # noqa: S310 - fixed URLs
                out[url] = f"REACHED {r.status}"
        except (OSError, socket.timeout) as e:
            out[url] = f"blocked: {type(e).__name__}: {str(e)[:120]}"
    out["no_route"] = all(v.startswith("blocked") for k, v in out.items() if k.startswith("http"))
    return out


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    if event.get("action") == "probe_egress":
        return probe_egress()
    from agent.agent import TASK, run_agent

    out = run_agent(event.get("task") or TASK, mode=event.get("mode"))
    out.pop("messages", None)
    return out
