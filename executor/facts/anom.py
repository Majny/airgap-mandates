"""F-ANOM: deterministic action-anomaly score from the executor's own tool-call log. CONTRACTS.md v2 §2.1,
ARCHITECTURE §4.4. Owner: WS-D (WS-E feeds the log).

Integer score 0..100, sum of fired features: untrusted read within 3 steps before payee.request_change /
payment.propose (+40), > 5 proposals in 60 s (+20), amount within 2% below the mandate max_per_payment_minor (+20),
round amount (+10), off-hours Europe/Prague 22:00-06:00 (+10). >= 40 -> WARN 'ANOM 55/100', else INFO.
It can only add a WARN (step-up); it never allows. Thresholds are placeholders until calibrated on the CNB
synthetic transactions.csv.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo

from executor.facts import _util
from executor.models import Fact

LABEL = "Action anomaly score (tool-call log)"
WARN_AT = 40
ACTION_TOOLS = ("payee.request_change", "payment.propose")
UNTRUSTED_WINDOW_STEPS = 3
BURST_COUNT, BURST_SECONDS = 5, 60
ROUND_MINOR = 100_000  # 1 000.00 in major units
TZ = ZoneInfo("Europe/Prague")

WEIGHTS = {"untrusted_read_before_action": 40, "proposal_burst": 20, "just_below_cap": 20, "round_amount": 10,
           "off_hours": 10}


def _untrusted_before_action(log: list[dict[str, Any]]) -> bool:
    reads: dict[str, list[int]] = {}
    for r in log:
        if r.get("untrusted_read"):
            reads.setdefault(str(r.get("session_id")), []).append(int(r.get("step", 0)))
    for r in log:
        if r.get("tool") in ACTION_TOOLS:
            step = int(r.get("step", 0))
            if any(step - UNTRUSTED_WINDOW_STEPS <= s < step for s in reads.get(str(r.get("session_id")), [])):
                return True
    return False


def _utc(dt: datetime) -> datetime:
    """Naive datetimes are UTC, never the host's local zone (keeps the score machine-independent)."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _proposal_burst(log: list[dict[str, Any]]) -> bool:
    ts = sorted(_utc(datetime.fromisoformat(str(r["ts"]).replace("Z", "+00:00")))
                for r in log if r.get("tool") == "payment.propose" and r.get("ts"))
    return any((ts[i + BURST_COUNT] - ts[i]).total_seconds() <= BURST_SECONDS for i in range(len(ts) - BURST_COUNT))


def _amount(subject: dict[str, Any]) -> int | None:
    amt = subject.get("amount_minor")
    if amt is None:
        amt = (subject.get("invoice") or {}).get("amount_minor")
    return int(amt) if isinstance(amt, int) and not isinstance(amt, bool) else None


def features(subject: dict[str, Any], tool_log: list[dict[str, Any]], *, mandate: dict[str, Any] | None,
             now: datetime) -> list[str]:
    """Names of the fired features, in WEIGHTS order."""
    fired: set[str] = set()
    if _untrusted_before_action(tool_log):
        fired.add("untrusted_read_before_action")
    if _proposal_burst(tool_log):
        fired.add("proposal_burst")
    amt = _amount(subject)
    cap = (mandate or {}).get("max_per_payment_minor")
    if amt is not None and amt > 0:
        if isinstance(cap, int) and cap > 0 and cap * 98 <= amt * 100 and amt <= cap:
            fired.add("just_below_cap")
        if amt % ROUND_MINOR == 0:
            fired.add("round_amount")
    hour = _utc(now).astimezone(TZ).hour
    if hour >= 22 or hour < 6:
        fired.add("off_hours")
    return [f for f in WEIGHTS if f in fired]


def anom_fact(subject: dict[str, Any], tool_log: list[dict[str, Any]], *, payee: dict[str, Any],
              mandate: dict[str, Any] | None, now: datetime) -> Fact:
    """F-ANOM; prov = digest(tool_log). `payee` is accepted for future features (same-vendor splitting)."""
    log = list(tool_log or [])
    fired = features(subject, log, mandate=mandate, now=now)
    score = min(100, sum(WEIGHTS[f] for f in fired))
    severity = "WARN" if score >= WARN_AT else "INFO"
    evidence = {"score": score, "features": ",".join(fired), "tool_calls": len(log),
                "vendor_id": payee.get("vendor_id")}
    return _util.make_fact("F-ANOM", severity, f"{LABEL}: {score}/100", f"ANOM {score}/100", evidence=evidence,
                           prov=_util.digest(log))
