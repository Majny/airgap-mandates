"""F-DOMAIN-AGE: how long the sender domain has been seen in OUR inbox (not WHOIS). CONTRACTS.md v2 §2.1.

Owner: WS-D.

first_seen comes from the inbox by_domain index (store-derived), so the fact has no snapshot prov; evidence carries
first_seen. None means the domain is seen for the first time now (age 0).
"""
from __future__ import annotations

from datetime import datetime, timezone

from executor.facts import _util
from executor.models import Fact

YOUNG_DAYS = 30


def _parse(ts: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def domain_age_fact(from_domain: str, first_seen: str | None, now: datetime) -> Fact:
    """age < 30 d -> WARN "DOMAIN AGE 12D"; else INFO "DOMAIN AGE 400D" (< 365 d) / "DOMAIN AGE 3Y"."""
    now_utc = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    seen = _parse(first_seen) if first_seen else None
    days = max(0, (now_utc - seen).days) if seen else 0  # unknown/unparseable first_seen == first time (WARN)
    evidence = {"from_domain": from_domain, "first_seen": first_seen, "age_days": days}
    if days < YOUNG_DAYS:
        return _util.make_fact("F-DOMAIN-AGE", "WARN",
                               f"Sender domain {from_domain} first seen in our inbox {days} days ago",
                               f"DOMAIN AGE {days}D", evidence=evidence)
    shown = f"{days}D" if days < 365 else f"{days // 365}Y"
    return _util.make_fact("F-DOMAIN-AGE", "INFO", f"Sender domain {from_domain} known for {days} days",
                           f"DOMAIN AGE {shown}"[:_util.DISPLAY_WIDTH], evidence=evidence)
