"""Agent Lambda (VPC, no IGW/NAT; only bedrock-runtime + execute-api endpoints). Owner: WS-E.

Events: {"task": ..., "mode": "naive"|"quarantined"} runs one episode against the private tools API;
{"action": "probe_egress"} tries to reach the internet and must fail (S10 evidence, tests/test_egress.py).
"""
from __future__ import annotations

import secrets
import socket
import urllib.error
import urllib.request
from typing import Any, Callable

PROBE_URLS = ("https://example.com", "https://checkip.amazonaws.com")
PROBE_HOST = "example.com"


def probe_egress(urls: tuple[str, ...] = PROBE_URLS, *, names: tuple[str, ...] | None = None,
                 urlopen: Callable[..., Any] = urllib.request.urlopen,
                 resolve: Callable[..., Any] = socket.getaddrinfo,
                 connect: Callable[..., Any] = socket.create_connection) -> dict[str, Any]:
    """HTTP, DNS and raw TCP egress, recorded separately.

    An HTTP error status is an answer from the internet (REACHED). DNS can be an exfil channel on its own, so public
    and attacker-style names (random label, wildcard DNS) are resolved separately (`dns_blocked`). `no_route` needs
    every HTTP attempt to fail AND either DNS to fail or a direct TCP connect to the resolved address to fail.
    """
    names = names or (PROBE_HOST, f"exfil-{secrets.token_hex(4)}.127.0.0.1.nip.io")
    out: dict[str, Any] = {}
    for url in urls:
        try:
            with urlopen(url, timeout=5) as r:  # noqa: S310 - fixed URLs
                out[url] = f"REACHED {r.status}"
        except urllib.error.HTTPError as e:
            out[url] = f"REACHED HTTPError {e.code}"
        except (OSError, socket.timeout) as e:
            out[url] = f"blocked: {type(e).__name__}: {str(e)[:120]}"
    dns: dict[str, str] = {}
    resolved: list[str] = []
    for name in names:
        try:
            ips = sorted({a[4][0] for a in resolve(name, 443, type=socket.SOCK_STREAM)})
            dns[name] = "resolved " + ",".join(ips)
            if name == names[0]:
                resolved = ips
        except OSError as e:
            dns[name] = f"blocked: {type(e).__name__}: {str(e)[:120]}"
    out["dns"] = dns
    out["dns_blocked"] = all(v.startswith("blocked") for v in dns.values())
    ip_blocked = True
    for ip in resolved:
        try:
            connect((ip, 443), timeout=5).close()
            out[f"tcp {ip}:443"] = "REACHED"
            ip_blocked = False
        except OSError as e:
            out[f"tcp {ip}:443"] = f"blocked: {type(e).__name__}: {str(e)[:120]}"
    http_blocked = all(out[u].startswith("blocked") for u in urls)
    out["no_route"] = http_blocked and (out["dns_blocked"] or ip_blocked)
    return out


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    if event.get("action") == "probe_egress":
        return probe_egress()
    from agent.agent import TASK, run_agent

    out = run_agent(event.get("task") or TASK, mode=event.get("mode"))
    out.pop("messages", None)
    return out
