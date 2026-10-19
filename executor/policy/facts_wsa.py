"""WS-A-owned F facts from mandate + ledger (pure): F-MANDATE, F-DUP, F-SPLIT, F-Z. CONTRACTS.md v2 §2.1.

Called by executor.facts.compute (WS-D) and by the store fallback. No I/O, no clock. Owner: WS-A.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from executor.models import Fact
from executor.policy import invariants as inv
from executor.policy.rules import FACT_SEVERITY


def _fact(fid: str, value: str, label: str, line: str, evidence: dict[str, Any]) -> Fact:
    return {"id": fid, "kind": "F", "severity": FACT_SEVERITY[fid][value], "label": label, "display_line": line,
            "evidence": evidence}


def wsa_facts(subject: dict[str, Any], state: dict[str, Any], now: datetime) -> list[Fact]:
    """subject: {"proposal_id"?, "invoice": {...}}; state: {"mandate", "proposals", "history"}."""
    invoice = subject["invoice"]
    amount = int(invoice["amount_minor"])
    m = state.get("mandate")
    active = m if m is not None and m.get("status") == "ACTIVE" else None
    out: list[Fact] = []

    if active is None:
        out.append(_fact("F-MANDATE", "no_mandate", "No active mandate", "NO MANDATE", {"amount_minor": amount}))
    else:
        per, total = int(active["max_per_payment_minor"]), int(active["max_total_minor"])
        spent, count = int(active.get("spent_minor") or 0), int(active.get("count") or 0)
        ev = {"amount_minor": amount, "max_per_payment_minor": per, "spent_minor": spent, "max_total_minor": total}
        if amount > per or spent + amount > total or count + 1 > int(active["max_count"]):
            out.append(_fact("F-MANDATE", "over_cap", "Above mandate limit", "OVER MANDATE CAP", ev))
        else:
            out.append(_fact("F-MANDATE", "within", "Within mandate limits", "WITHIN MANDATE", ev))

    matched = inv.find_duplicate(invoice, state.get("proposals") or [], proposal_id=subject.get("proposal_id"))
    if matched is not None:
        out.append(_fact("F-DUP", "duplicate", "Duplicate invoice", "DUPLICATE INV", {"matched": matched}))

    history = state.get("history") or []
    if active is not None:
        s = inv.split_sum(invoice, history, now=now)
        if s + amount > int(active["max_per_payment_minor"]):
            out.append(_fact("F-SPLIT", "split", "Vendor total in 24 h above per-payment cap", "SPLIT 24H",
                             {"split_sum_minor": s, "amount_minor": amount,
                              "max_per_payment_minor": int(active["max_per_payment_minor"])}))

    if inv.z_hit(invoice, history):
        out.append(_fact("F-Z", "outlier", "Amount is an outlier for this vendor", "AMOUNT OUTLIER",
                         {"amount_minor": amount, "history_count": len(history)}))
    return out
