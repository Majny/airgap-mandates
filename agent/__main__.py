"""Agent beat CLI (stage). Owner: WS-E.

  python -m agent run --scenario s1|s2 [--mode quarantined|naive] [--local] [--json]

s1 = the three legitimate invoice emails (expect three proposals allowed under the active mandate);
s2 = the lookalike-domain BEC email (expect no payment, device dark).
Default: invokes the deployed agent λ (airgap-agent, VPC without NAT, Bedrock + private tools API only).
--local runs the same loop on this laptop against AIRGAP_TOOLS_URL / in-process tools (dev only, not the S10 claim).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

MANIFEST = Path(__file__).resolve().parents[1] / "data" / "emails" / "manifest.json"


# s1 = the stage S1 beat: the legitimate invoices (paid under the mandate) plus, once WS-D's fixture lands, one
# over-cap invoice from a fourth vendor that must step up (challenge) instead of paying
SCENARIOS = {"s1": ("legit_invoice", "overcap_invoice"), "s2": ("bec_lookalike",)}
VENDORS = Path(__file__).resolve().parents[1] / "data" / "vendors.json"


def scenario_emails(name: str) -> list[str]:
    return [r["email_id"] for r in json.loads(MANIFEST.read_text()) if r["scenario"] in SCENARIOS[name]]


def scenario_task(name: str) -> str:
    ids = scenario_emails(name)
    return (f"Process only these inbox emails: {', '.join(ids)}. Pay invoices that are due; if bank details differ "
            "from the registered vendor, do not pay and follow the payee-change procedure.")


def run(scenario: str, mode: str, local: bool) -> dict:
    task = scenario_task(scenario)
    if local:
        from agent.agent import run_agent

        out = run_agent(task, mode=mode)
        out.pop("messages", None)
        return out
    import boto3
    from botocore.config import Config

    lam = boto3.client("lambda", region_name="eu-central-1", config=Config(read_timeout=330, retries={"max_attempts": 0}))
    r = lam.invoke(FunctionName="airgap-agent", Payload=json.dumps({"task": task, "mode": mode}).encode())
    return json.loads(r["Payload"].read())


def vendor_names() -> dict[str, str]:
    try:
        return {v.get("vendor_id") or f"ven_{v['ico']}": v["name"] for v in json.loads(VENDORS.read_text())}
    except (OSError, ValueError, KeyError):
        return {}


def proposals(out: dict) -> list[dict]:
    """One record per payment.propose the agent made: what WS-C's stage wrapper prints / signs."""
    rows = []
    for t in out.get("tool_calls", []):
        if t["tool"] != "payment.propose":
            continue
        a, res = t["args"], t["result"]
        rows.append({"vendor_id": a.get("vendor_id"), "invoice_no": a.get("invoice_no"),
                     "amount_minor": a.get("amount_minor"), "currency": a.get("currency"),
                     "decision": res.get("decision") or res.get("error"), "rule_ids": res.get("rule_ids") or [],
                     "proposal_id": res.get("proposal_id"), "tx_id": res.get("tx_id")})
    return rows


def summary(out: dict) -> str:
    names = vendor_names()
    lines = [f"agent ({out.get('mode')}, {out.get('model')}) {out.get('latency_ms')} ms, {out.get('tokens')} tokens"]
    for p in proposals(out):
        verdict = {"allow": "ALLOW (paid under the mandate)", "challenge": "CHALLENGE (needs the device)",
                   "deny": "DENY"}.get(p["decision"], str(p["decision"]).upper())
        ref = p["tx_id"] or p["proposal_id"] or ""
        lines.append(f"  PAY {names.get(p['vendor_id'], p['vendor_id'])[:20]:<20} {str(p['invoice_no'])[:16]:<16} "
                     f"{(p['amount_minor'] or 0) / 100:>12.2f} {p['currency'] or ''} -> {verdict} {ref}".rstrip())
    for t in out.get("tool_calls", []):
        res = t["result"]
        if t["tool"] == "payee.request_change":
            lines.append(f"  CHANGE {t['args'].get('vendor_id')} -> {res.get('state') or res.get('error')}")
        elif t["tool"] != "payment.propose" and "error" in res:
            lines.append(f"  {t['tool']} -> {res.get('error')} {res.get('rule_ids') or ''}")
    lines.append(f"  final: {(out.get('final') or out.get('errorMessage') or '')[:300]}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m agent")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--scenario", choices=["s1", "s2"], required=True)
    r.add_argument("--mode", choices=["quarantined", "naive"], default="quarantined")
    r.add_argument("--local", action="store_true")
    r.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    out = run(a.scenario, a.mode, a.local)
    if a.json:
        print(json.dumps({"scenario": a.scenario, "emails": scenario_emails(a.scenario), "mode": out.get("mode"),
                          "model": out.get("model"), "proposals": proposals(out), "final": out.get("final"),
                          "error": out.get("errorMessage"), "tokens": out.get("tokens"),
                          "latency_ms": out.get("latency_ms")}, indent=1, default=str))
    else:
        print(summary(out))
    return 1 if out.get("errorMessage") else 0


if __name__ == "__main__":
    sys.exit(main())
