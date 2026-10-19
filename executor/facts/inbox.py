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


MAX_EVIDENCE = 8


def resolve_email_ids(evidence_ids: list[Any] | None, *, store: Any, settings: Any = None) -> list[str]:
    """Inbox email_ids named by a change request's `evidence_ids` (CONTRACTS §4.2), in order, deduplicated: an
    `eml_` id of a stored email, or a `doc_<16 hex>` handle of a document inside a stored email (the ids the tools
    surface hands the agent). Ids that resolve to nothing are dropped; at most MAX_EVIDENCE are looked at."""
    ids = [i for i in (evidence_ids or []) if isinstance(i, str) and i][:MAX_EVIDENCE]
    out: list[str] = []
    docs: dict[str, str] | None = None  # doc_id -> email_id, built on first doc_ id
    for i in ids:
        eid: str | None = None
        if store.get("inbox", {"email_id": i}) is not None:
            eid = i
        elif i.startswith("doc_"):
            if docs is None:
                docs = _doc_index(store=store, settings=settings)
            eid = docs.get(i)
        if eid and eid not in out:
            out.append(eid)
    return out


def _doc_index(*, store: Any, settings: Any) -> dict[str, str]:
    from executor.docs import extract

    index: dict[str, str] = {}
    for row in sorted(store.scan("inbox"), key=lambda r: (r.get("received_at") or "", r["email_id"])):
        raw = raw_email(row, settings=settings)
        try:
            found = extract.documents(raw) if raw else []
        except Exception:  # noqa: BLE001 - an unparseable message names no document
            found = []
        for d in found:
            index.setdefault(d["doc_id"], row["email_id"])
    return index


def email_state(email_id: str | None, *, store: Any, settings: Any = None) -> dict[str, Any]:
    """{"email": inbox row (with the ingest `dkim` verdict) or None, "domain_first_seen": iso | None,
    "email_raw": raw .eml bytes | None (F-AMOUNT-DOC)}."""
    email = store.get("inbox", {"email_id": email_id}) if email_id else None
    domain = (email or {}).get("from_domain") or ""
    return {"email": email, "domain_first_seen": domain_first_seen(domain, store=store) if domain else None,
            "email_raw": raw_email(email, settings=settings)}
