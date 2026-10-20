"""Supplier side (outside the bank): send a new invoice email to the bank, let the bank's agent propose it, and say in
plain words what the bank decided. Used by supplier/console.py (:8503). Owner: orchestrator.

The supplier keys nothing into the bank: it only sends a DKIM-signed invoice email (tools/invoice_mail.py, SIMULATED
vendor mail). The bank's agent proposes; the executor decides (paid under the mandate, Trezor step-up, or refused).

    out = send(call, "ven_12345678", 1_250_000)          # scripted agent step (POST /proposals as "tools")
    out["kind"], out["text"]                             # "paid" | "waiting" | "refused" | "expired" | ... , words
    status(call, out["proposal_id"])                     # live status later (GET /proposals/{id})
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from tools.invoice_mail import new_invoice, send_and_propose

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
DEFAULT_CAP_MINOR = 8_000_000  # the demo mandate's per-payment cap; the console reads the live one when it can


def czk(minor: int | None) -> str:
    return f"{(minor or 0) / 100:,.2f} CZK".replace(",", " ")


def vendors(data_dir: str | Path = DATA_DIR) -> list[dict[str, Any]]:
    """The registered suppliers (data/vendors.json): the only senders the bank pays without a payee change."""
    return json.loads((Path(data_dir) / "vendors.json").read_text())


def cap_minor(call: Callable) -> int | None:
    """Per-payment cap of the bank's active mandate (GET /mandates/active as host), or None if there is none/unknown."""
    try:
        st, m = call("GET", "/mandates/active", None, "host")
    except Exception:  # noqa: BLE001 - unreachable or expired sign-in: the console falls back to the default text
        return None
    return int(m["max_per_payment_minor"]) if st == 200 and isinstance(m, dict) and m.get("max_per_payment_minor") else None


def local_time(iso: str | None) -> str:
    """'2026-10-19T12:05:00Z' -> 'HH:MM:SS' in this machine's local time ('?' if unparseable)."""
    try:
        return datetime.fromisoformat(str(iso).replace("Z", "+00:00")).astimezone().strftime("%H:%M:%S")
    except ValueError:
        return "?"


def _plain_block(f: dict[str, Any]) -> str:
    from host.story import plain_fact

    return {
        "F-SPLIT": "this supplier was already paid today; together it would be above the auto-pay limit",
        "F-DUP": "this supplier was already paid today (or is waiting) for the same invoice: same number, or same "
                 "amount and date",
        "F-MANDATE": "the bank has no active mandate for automatic payments",
    }.get(f.get("id", ""), plain_fact(f))


def refusal_reasons(facts: list[dict[str, Any]]) -> str:
    """The BLOCK facts of a refused proposal in plain words."""
    out: list[str] = []
    for f in facts or []:
        if f.get("kind", "F") == "F" and f.get("severity") == "BLOCK":
            words = _plain_block(f)
            if words not in out:
                out.append(words)
    return "; ".join(out) or "the bank's rules refused it"


def wait_reasons(facts: list[dict[str, Any]]) -> str:
    """Why a proposal needs the clerk (its WARN facts) in plain words."""
    words = {"F-MANDATE": "above the bank's auto-pay limit",
             "F-SPLIT": "this supplier was already paid today; together it is above the auto-pay limit"}
    out = [words.get(f.get("id", ""), "") for f in facts or [] if f.get("severity") == "WARN"]
    return "; ".join(dict.fromkeys(w for w in out if w))


def _waiting(pid: Any, exp: str, facts: list[dict[str, Any]]) -> dict[str, Any]:
    why = wait_reasons(facts)
    return {"kind": "waiting", "proposal_id": pid, "expires": exp, "why": why,
            "text": f"Waiting for the clerk to approve on the Trezor — approval request expires at {exp} (local time)"
                    + (f". Why: {why}" if why else "")}


def outcome(st: int, r: Any) -> dict[str, Any]:
    """The bank's answer to a proposal (POST /proposals response) in plain words."""
    if st != 201 or not isinstance(r, dict) or "decision" not in r:
        msg = (r.get("message") or r.get("error")) if isinstance(r, dict) else r
        return {"kind": "error", "text": f"The bank did not take the invoice (HTTP {st}): {msg}", "proposal_id": None}
    dec, prop = r.get("decision") or {}, r.get("proposal") or {}
    pid = prop.get("proposal_id")
    if dec.get("decision") == "allow":
        tx = (r.get("tx") or {}).get("tx_id") or prop.get("tx_id")
        return {"kind": "paid", "text": f"Paid automatically under the bank's mandate (tx {tx})", "proposal_id": pid,
                "tx_id": tx}
    if dec.get("decision") == "challenge":
        return _waiting(pid, local_time((dec.get("challenge") or {}).get("exp")), dec.get("facts") or [])
    return {"kind": "refused", "proposal_id": pid,
            "text": f"Refused by the bank: {refusal_reasons(dec.get('facts') or prop.get('facts') or [])}"}


def status(call: Callable, proposal_id: str) -> dict[str, Any]:
    """Live status of a sent invoice (GET /proposals/{id} as host) in plain words."""
    try:
        st, p = call("GET", f"/proposals/{proposal_id}", None, "host")
    except Exception as e:  # noqa: BLE001
        return {"kind": "error", "text": f"cannot read the bank's status: {type(e).__name__}: {e}"[:200]}
    if st != 200 or not isinstance(p, dict):
        return {"kind": "error", "text": f"cannot read the bank's status (HTTP {st})"}
    s = p.get("status")
    if s == "EXECUTED":
        return {"kind": "paid", "text": f"Paid (tx {p.get('tx_id')})", "tx_id": p.get("tx_id")}
    if s == "PENDING_SIG":
        exp = "?"
        if p.get("challenge_nonce"):
            try:
                cst, ch = call("GET", f"/challenges/{p['challenge_nonce']}", None, "host")
                exp = local_time(ch.get("exp")) if cst == 200 and isinstance(ch, dict) else "?"
            except Exception:  # noqa: BLE001
                pass
        return _waiting(proposal_id, exp, p.get("facts") or [])
    if s == "EXPIRED":
        return {"kind": "expired", "text": "Not paid: the clerk did not approve within 5 minutes"}
    if s == "REJECTED":
        return {"kind": "rejected", "text": "Not paid: the clerk rejected it on the Trezor"}
    return {"kind": "refused", "text": f"Refused by the bank: {refusal_reasons(p.get('facts') or [])}"}


def agent_task(email_id: str) -> str:
    """The task the real agent gets for one supplier email (phrased like agent.__main__.scenario_task)."""
    return (f"Process only this inbox email: {email_id}. Propose payment for the valid invoice in it, even if it is "
            "above the mandate limit: the executor decides whether it is paid under the mandate or needs human "
            "approval, so do not skip it. If bank details differ from the registered vendor, do not pay and follow "
            "the payee-change procedure.")


def lambda_agent(call: Callable, invoke: Callable[[str], dict]) -> Callable[[dict], tuple[int, Any]]:
    """Agent step via the real agent Lambda (AWS, Bedrock): `invoke(task) -> result`. The proposal it made for the
    email is then read back from GET /proposals (matched on the email_id), so the outcome is the executor's own."""

    def run(cited: dict) -> tuple[int, Any]:
        out = invoke(agent_task(cited["email_id"]))
        st, r = call("GET", "/proposals", None, "host")
        mine = [p for p in (r.get("proposals", []) if st == 200 and isinstance(r, dict) else [])
                if (p.get("invoice") or {}).get("email_id") == cited["email_id"]]
        if not mine:
            return 0, {"error": "agent_made_no_proposal",
                       "message": f"the agent made no proposal for this email ({str(out.get('final'))[:160]})"}
        p = mine[-1]
        dec = {"EXECUTED": "allow", "PENDING_SIG": "challenge"}.get(p.get("status"), "deny")
        challenge = {}
        if p.get("challenge_nonce"):
            _, challenge = call("GET", f"/challenges/{p['challenge_nonce']}", None, "host")
        return 201, {"proposal": p, "tx": {"tx_id": p.get("tx_id")},
                     "decision": {"decision": dec, "facts": p.get("facts") or [],
                                  "challenge": challenge if isinstance(challenge, dict) else {}}}

    return run


def send(call: Callable, vendor_id: str, amount_minor: int, *, invoice_no: str | None = None,
         due_date: str | None = None, data_dir: str | Path | None = None,
         agent: Callable[[dict], tuple[int, Any]] | None = None) -> dict[str, Any]:
    """Send one new invoice email from a registered supplier and return the bank's decision in plain words, plus
    the invoice and the raw response (`raw`)."""
    inv = new_invoice(vendor_id, amount_minor, invoice_no=invoice_no, due_date=due_date)
    try:
        st, r = send_and_propose(call, inv, data_dir=data_dir, agent=agent)
    except AssertionError as e:  # e2e.cite: the bank's mail intake refused the email
        st, r = 0, {"error": "ingest_failed", "message": str(e)[:300]}
    return {**outcome(st, r), "invoice": inv, "raw": r, "http": st}
