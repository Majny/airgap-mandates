"""Store-backed inputs for the email facts (F-DOMAIN, F-DKIM, F-DOMAIN-AGE, F-AMOUNT-DOC). CONTRACTS.md v2 §2.1, §3.1
inbox.

compute() is pure; callers merge email_state() into its `state`. Owner: WS-D.
"""
from __future__ import annotations

import base64
from typing import Any


def domain_first_seen(domain: str, *, store: Any) -> str | None:
    """First time this sender domain reached OUR inbox (not WHOIS); ISO string or None."""
    domain = domain.lower()
    seen = [r["received_at"] for r in store.scan("inbox") if (r.get("from_domain") or "").lower() == domain]
    return min(seen) if seen else None


def raw_email(row: dict[str, Any] | None, *, settings: Any = None) -> bytes | None:
    """Raw .eml of an inbox row, read like GET /inbox/{email_id}/raw: inline `raw_b64` (memory/moto) or
    s3://<inbox_bucket>/<s3_key>. None when it cannot be read (callers fail closed)."""
    if not row:
        return None
    if row.get("raw_b64"):
        return base64.b64decode(row["raw_b64"])
    if not row.get("s3_key"):
        return None
    try:
        import boto3

        from executor.config import Settings

        settings = settings or Settings.from_env()
        obj = boto3.client("s3", region_name=settings.aws_region).get_object(Bucket=settings.inbox_bucket,
                                                                             Key=row["s3_key"])
        return obj["Body"].read()
    except Exception:  # noqa: BLE001 - unreadable raw message: F-AMOUNT-DOC blocks
        return None


def email_state(email_id: str | None, *, store: Any, settings: Any = None) -> dict[str, Any]:
    """{"email": inbox row (with the ingest `dkim` verdict) or None, "domain_first_seen": iso | None,
    "email_raw": raw .eml bytes | None (F-AMOUNT-DOC)}."""
    email = store.get("inbox", {"email_id": email_id}) if email_id else None
    domain = (email or {}).get("from_domain") or ""
    return {"email": email, "domain_first_seen": domain_first_seen(domain, store=store) if domain else None,
            "email_raw": raw_email(email, settings=settings)}
