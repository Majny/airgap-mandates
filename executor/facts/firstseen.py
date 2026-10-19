"""F-FIRSTSEEN: when this IBAN first appeared in the payee `registry` history. CONTRACTS.md v2 §2.1.

Absent -> WARN 'IBAN NEW 0H'; < 72 h -> WARN 'IBAN NEW 5H'; else INFO 'IBAN SEEN 400D'. Owner: WS-D.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from executor.facts import _util
from executor.facts.vop import norm_iban
from executor.models import Fact

LABEL = "IBAN first seen in payee registry"
NEW_HOURS = 72


def _utc(dt: datetime) -> datetime:
    """Naive datetimes are UTC (never the host's local zone)."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _parse(ts: str) -> datetime:
    """ISO date ('2024-03-01', midnight UTC) or datetime ('...Z' / offset)."""
    return _utc(datetime.fromisoformat(str(ts).replace("Z", "+00:00")))


def firstseen_fact(iban: str, iban_history: list[dict[str, Any]], now: datetime) -> Fact:
    """First seen = earliest `from` for this IBAN; prov = digest(iban_history)."""
    s = norm_iban(iban)
    froms = [_parse(r["from"]) for r in iban_history or [] if r.get("from") and norm_iban(r.get("iban", "")) == s]
    prov = _util.digest(list(iban_history or []))
    if not froms:
        return _util.make_fact("F-FIRSTSEEN", "WARN", f"{LABEL}: never (new)", "IBAN NEW 0H",
                               evidence={"found": False, "first_seen": None, "hours": 0}, prov=prov)
    first = min(froms)
    hours = max(0, int((_utc(now) - first).total_seconds()) // 3600)
    evidence = {"found": True, "first_seen": first.isoformat().replace("+00:00", "Z"), "hours": hours}
    if hours < NEW_HOURS:
        return _util.make_fact("F-FIRSTSEEN", "WARN", f"{LABEL}: {hours} h ago", f"IBAN NEW {hours}H",
                               evidence=evidence, prov=prov)
    days = hours // 24
    return _util.make_fact("F-FIRSTSEEN", "INFO", f"{LABEL}: {days} days ago", f"IBAN SEEN {days}D",
                           evidence=evidence, prov=prov)
