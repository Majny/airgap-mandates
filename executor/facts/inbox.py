"""Store-backed inputs for the email facts (F-DOMAIN, F-DKIM, F-DOMAIN-AGE). CONTRACTS.md v2 §2.1, §3.1 inbox.

compute() is pure; callers merge email_state() into its `state`. Owner: WS-D.
"""
from __future__ import annotations

from typing import Any


def domain_first_seen(domain: str, *, store: Any) -> str | None:
    """First time this sender domain reached OUR inbox (not WHOIS); ISO string or None."""
    domain = domain.lower()
    seen = [r["received_at"] for r in store.scan("inbox") if (r.get("from_domain") or "").lower() == domain]
    return min(seen) if seen else None


def email_state(email_id: str | None, *, store: Any) -> dict[str, Any]:
    """{"email": inbox row (with the ingest `dkim` verdict) or None, "domain_first_seen": iso | None}."""
    email = store.get("inbox", {"email_id": email_id}) if email_id else None
    domain = (email or {}).get("from_domain") or ""
    return {"email": email, "domain_first_seen": domain_first_seen(domain, store=store) if domain else None}
