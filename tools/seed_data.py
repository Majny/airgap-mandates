"""Seed the registry (vendors + issuer pins + registry#meta) and the inbox (.eml + DKIM verdict). CONTRACTS.md v2 §3.1,
§11.

Owner: WS-D.

Fictitious demo data only. Issuer pins come from the DEMO-ONLY keys in data/issuer_keys/<class>.jwk (public part
only) and are written for in-network vendors via executor.attest.trust.pin_issuer (enrolment-time). Emails go straight
into the `inbox` table with the ingest-time DKIM verdict (executor.facts.dkim.dkim_verdict over the DNS snapshot);
when that module is unavailable the verdict is recorded as "none" (fails closed: F-DKIM BLOCK).
"""
from __future__ import annotations

import argparse
import base64
import email
import email.utils
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from executor.config import Settings, iso

META_KEY = "registry#meta"
ISSUER_CLASSES = ("supplier-erp", "supplier-bank", "registry")
_PUBLIC_JWK = ("kty", "crv", "x", "y")
_NO_DKIM = {"result": "none", "d": None, "s": None, "aligned": False}


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 thumbprint of an EC public JWK (fallback when executor.attest.sdjwt is unavailable)."""
    body = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True)
    return _b64u(hashlib.sha256(body.encode("ascii")).digest())


def _issuer_keys(keys_dir: Path) -> list[tuple[str, str, dict[str, Any]]]:
    """[(issuer_class, iss, public jwk)] for every <class>.jwk present."""
    out = []
    for cls in ISSUER_CLASSES:
        path = keys_dir / f"{cls}.jwk"
        if not path.exists():
            continue
        jwk = json.loads(path.read_text())
        iss = jwk.get("iss") or f"https://{cls}.issuer.example"
        out.append((cls, iss, {k: jwk[k] for k in _PUBLIC_JWK}))
    return out


def _pin(vendor_id: str, cls: str, iss: str, jwk: dict[str, Any], *, store: Any, settings: Any,
         now: datetime) -> None:
    try:
        from executor.attest import trust

        trust.pin_issuer(vendor_id, cls, iss, jwk, store=store, settings=settings, now=now)
        return
    except (ImportError, NotImplementedError, AttributeError, TypeError):
        pass
    row = store.get("registry", {"vendor_id": vendor_id}) or {}
    pins = list(row.get("issuer_pins") or [])
    tp = _thumbprint(jwk)
    if not any(p["jwk_thumbprint"] == tp for p in pins):
        pins.append({"issuer_class": cls, "iss": iss, "jwk_thumbprint": tp, "pinned_at": iso(now)})
        store.update_if("registry", {"vendor_id": vendor_id}, {"issuer_pins": pins}, {})


def registry_hash(rows: list[dict[str, Any]]) -> str:
    """payee_registry_hash = sha256(canonical_json(sorted([[vendor_id, iban] ...]))) (CONTRACTS §3.1)."""
    from executor.canonical import canonical_json

    return hashlib.sha256(canonical_json(sorted([[r["vendor_id"], r["iban"]] for r in rows]))).hexdigest()


def seed_registry(vendors: list[dict[str, Any]], *, store: Any, settings: Any, keys_dir: Path,
                  now: datetime) -> dict[str, int]:
    keys = _issuer_keys(keys_dir)
    pinned = 0
    for v in vendors:
        row = dict(v)
        row.setdefault("vendor_id", f"ven_{row['ico']}")
        row["issuer_pins"] = []
        row.setdefault("iban_history", [{"iban": row["iban"], "from": row.get("registered_since", iso(now)[:10]),
                                         "to": None, "change_id": None}])
        store.put("registry", row)
        if row.get("in_network"):
            for cls, iss, jwk in keys:
                _pin(row["vendor_id"], cls, iss, jwk, store=store, settings=settings, now=now)
                pinned += 1
    rows = [store.get("registry", {"vendor_id": dict(v).get("vendor_id") or f"ven_{v['ico']}"}) for v in vendors]
    store.put("registry", {"vendor_id": META_KEY, "registry_version": 1, "registry_hash": registry_hash(rows)})
    return {"vendors": len(vendors), "pins": pinned}


def _dkim(raw: bytes, dns_snapshot: dict[str, Any]) -> dict[str, Any]:
    try:
        from executor.facts import dkim

        return dict(dkim.dkim_verdict(raw, dns_snapshot=dns_snapshot))
    except (ImportError, NotImplementedError, AttributeError):
        return dict(_NO_DKIM)


def inbox_row(raw: bytes, *, dns_snapshot: dict[str, Any], now: datetime) -> dict[str, Any]:
    """`inbox` row for one raw .eml (email_id = eml_<16 hex of sha256(raw)>)."""
    sha = hashlib.sha256(raw).hexdigest()
    msg = email.message_from_bytes(raw)
    from_addr = email.utils.parseaddr(msg.get("From", ""))[1].lower()
    received = now
    if msg.get("Date"):
        try:
            received = email.utils.parsedate_to_datetime(msg["Date"])
            if received.tzinfo is None:
                received = received.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            received = now
    email_id = f"eml_{sha[:16]}"
    return {
        "email_id": email_id, "s3_key": f"inbox-raw/{email_id}.eml", "sha256": sha, "from_addr": from_addr,
        "from_domain": from_addr.rpartition("@")[2], "subject": str(msg.get("Subject", "")),
        "received_at": iso(received.replace(microsecond=0)), "dkim": _dkim(raw, dns_snapshot),
    }


def seed_inbox(emails_dir: Path, *, store: Any, dns_snapshot: dict[str, Any], now: datetime) -> int:
    n = 0
    for path in sorted(emails_dir.glob("*.eml")):
        store.put("inbox", inbox_row(path.read_bytes(), dns_snapshot=dns_snapshot, now=now))
        n += 1
    return n


def seed(*, settings: Any = None, data_dir: str = "data", store: Any = None,
         now: datetime | None = None) -> dict[str, int]:
    """Load data/vendors.json (+ issuer pins) and data/emails/*.eml into the store; returns counts."""
    settings = settings or Settings.from_env()
    if store is None:
        from executor.store import get_store

        store = get_store(settings)
    now = now or datetime.now(timezone.utc)
    base = Path(data_dir)
    vendors_path = base / "vendors.json"
    vendors = json.loads(vendors_path.read_text()) if vendors_path.exists() else []
    out = seed_registry(vendors, store=store, settings=settings, keys_dir=base / "issuer_keys", now=now)
    dns_path = base / "dns_snapshot.json"
    dns_snapshot = json.loads(dns_path.read_text()) if dns_path.exists() else {}
    out["emails"] = seed_inbox(base / "emails", store=store, dns_snapshot=dns_snapshot, now=now)
    return out


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    ap = argparse.ArgumentParser(description="Seed fictitious demo vendors, issuer pins and emails.")
    ap.add_argument("--data-dir", default=None, help="default: AIRGAP_DATA_DIR or data/")
    args = ap.parse_args(argv)
    settings = Settings.from_env()
    try:
        counts = seed(settings=settings, data_dir=args.data_dir or settings.data_dir)
    except NotImplementedError as e:
        print(f"seed: backend not available yet: {e}", file=sys.stderr)
        return 1
    print(json.dumps(counts, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
