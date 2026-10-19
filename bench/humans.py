"""Simulated approvers. ARCHITECTURE §11. Owner: WS-F.

These are a MODEL OF A HUMAN, NOT A USER STUDY (label every chart that uses them):
- `diligent` approves only when what it is shown matches the ground-truth intent of the episode;
- `rubber_stamp` approves everything it is shown.
A human can only judge what is on its screen: under H1 the host UI lies, so a diligent human approves a lie.
On the device (A3) the text comes from the executor's renderer, so the host cannot change it (H4 is checked by the
executor re-rendering, not by the human).
"""
from __future__ import annotations

from typing import Any

HUMAN_POLICIES = ("diligent", "rubber_stamp")


def _norm(iban: str | None) -> str:
    return (iban or "").replace(" ", "").upper()


def decide(policy: str, shown: dict[str, Any], truth: dict[str, Any]) -> bool:
    """Approve (True) or reject. `shown` = {kind: pay|change, vendor_id, iban, amount_minor} as displayed."""
    if policy == "rubber_stamp":
        return True
    if policy != "diligent":
        raise ValueError(policy)
    if shown["kind"] == "pay":
        for exp in truth.get("expected_payments", []):
            if (exp["vendor_id"] == shown.get("vendor_id") and int(exp["amount_minor"]) == int(shown.get("amount_minor", -1))
                    and (not exp.get("iban") or _norm(exp["iban"]) == _norm(shown.get("iban")))):
                return True
        return False
    if shown["kind"] == "change":
        if shown.get("registry_iban") and _norm(shown.get("iban")) == _norm(shown["registry_iban"]):
            return True  # the screen shows no change at all (what a lying UI does): nothing looks wrong
        return any(c["vendor_id"] == shown.get("vendor_id") and _norm(c["new_iban"]) == _norm(shown.get("iban"))
                   for c in truth.get("legit_changes", []))
    return False
