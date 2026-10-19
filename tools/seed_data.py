"""Seed the registry (vendors + issuer pins + registry#meta), the enrolled signers and the inbox. CONTRACTS.md v2 §3.1,
§6, §11.

Owner: WS-D.

Fictitious demo data only. Works against any executor.store backend (default: get_store(settings), i.e. the memory
backend in dev/CI) or a store object passed in. Natural keys only (executor.store.KEY_SCHEMA).

* registry: data/vendors.json; issuer pins from the DEMO-ONLY keys in data/issuer_keys/<class>.jwk (public part only)
  via executor.attest.trust.pin_issuer (enrolment-time) for in-network vendors; registry#meta with
  payee_registry_hash from executor.policy.mandate.registry_snapshot.
* enrolled_signers: data/enrollment.json as written by tools/enroll.py (the ceremony transcript is not stored).
* inbox: data/emails/*.eml through executor.facts.dkim.ingest (inbox row + ingest-time DKIM verdict + `ingest` leaf);
  direct rows when ingest() is unavailable (DKIM "none": fails closed, F-DKIM BLOCK).
"""
from __future__ import annotations

import argparse
import base64
import dataclasses
import email
import email.utils
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from executor.canonical import canonical_json
from executor.config import Settings, iso

META_KEY = "registry#meta"
ISSUER_CLASSES = ("supplier-erp", "supplier-bank", "registry")
_PUBLIC_JWK = ("kty", "crv", "x", "y")
_NO_DKIM = {"result": "none", "d": None, "s": None, "aligned": False}
_SIGNER_PRIVATE = ("ceremony", "leaf")  # enroll.py transcript, not an enrolled_signers attribute


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


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


def seed_registry(vendors: list[dict[str, Any]], *, store: Any, settings: Any, keys_dir: Path,
                  now: datetime) -> dict[str, int]:
    from executor.attest import trust
    from executor.policy.mandate import REGISTRY_META, registry_snapshot

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
                trust.pin_issuer(row["vendor_id"], cls, iss, jwk, store=store, settings=settings, now=now)
                pinned += 1
    meta = store.get("registry", REGISTRY_META) or {}
    version = int(meta.get("registry_version", 0)) + 1
    store.put("registry", {**REGISTRY_META, "registry_version": version, "registry_hash": registry_snapshot(store)["hash"]})
    return {"vendors": len(vendors), "pins": pinned}


_ENROLL_FIELDS = ("address", "role", "label", "device", "device_model", "firmware_version", "cert_chain_sha256",
                  "fw_hash", "derivation_path", "enroll_sig")


def _logged_enrolls(store: Any) -> dict[str, int]:
    """canonical `enroll` leaf data -> seq for leaves already in the audit log (a re-seed reuses them)."""
    out: dict[str, int] = {}
    for r in store.scan("audit"):
        ev = r.get("event")
        if not isinstance(ev, str) or '"type":"enroll"' not in ev:
            continue
        e = json.loads(ev)
        out.setdefault(canonical_json(e["data"]).decode(), int(e["seq"]))
    return out


def _enroll(row: dict[str, Any], *, store: Any, settings: Any) -> int:
    """One transaction: `enroll` leaf (§7.2, head-conditioned Put) + the enrolled_signers row with enroll_seq."""
    from executor.store import Put, TxConflict, ensure_head, leaf_ops, next_seq, shims

    data = {k: row.get(k) for k in _ENROLL_FIELDS}
    event = shims.make_event("enroll", data, subject_id=row["address"], actor="executor", settings=settings)
    ensure_head(store, event["log_id"])
    for _ in range(20):
        seq = next_seq(store, event["log_id"])
        if store.transact(leaf_ops(event, seq) + [Put("enrolled_signers", {**row, "enroll_seq": seq})]):
            shims.after_commit(store=store, settings=settings)
            return seq
    raise TxConflict("audit head contention while enrolling")


def seed_signers(path: Path, *, store: Any, settings: Any = None) -> int:
    """enrolled_signers rows from data/enrollment.json ({"signers": [...]}, device set by tools/enroll.py). Each row is
    written in one transaction with its `enroll` leaf (CONTRACTS §6, §7.2) and carries `enroll_seq`, so the offline
    verifier sees the signer enrolled before its first signature. Inactive rows (fallback emulator clerk) are logged
    too; `active` lives only in the row. Re-seeding reuses an identical existing leaf instead of logging twice."""
    if not path.exists():
        return 0
    settings = settings or Settings(backend="memory")
    doc = json.loads(path.read_text())
    logged = _logged_enrolls(store)
    n = 0
    for s in doc.get("signers") or []:
        row = {k: v for k, v in s.items() if k not in _SIGNER_PRIVATE}
        row["address"] = str(row["address"]).lower()
        seq = logged.get(canonical_json({k: row.get(k) for k in _ENROLL_FIELDS}).decode())
        if seq is None:
            _enroll(row, store=store, settings=settings)
        else:
            store.put("enrolled_signers", {**row, "enroll_seq": seq})
        n += 1
    return n


def _received_at(msg: email.message.Message, now: datetime) -> str:
    received = now
    if msg.get("Date"):
        try:
            received = email.utils.parsedate_to_datetime(msg["Date"])
            if received.tzinfo is None:
                received = received.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            received = now
    return iso(received.replace(microsecond=0))


def inbox_row(raw: bytes, *, now: datetime) -> dict[str, Any]:
    """Direct `inbox` row (email_id = eml_<16 hex of sha256(raw)>) for when ingest() is unavailable: no DKIM
    verdict ("none"), so F-DKIM fails closed."""
    sha = hashlib.sha256(raw).hexdigest()
    msg = email.message_from_bytes(raw)
    from_addr = email.utils.parseaddr(msg.get("From", ""))[1].lower()
    email_id = f"eml_{sha[:16]}"
    from_domain = from_addr.rpartition("@")[2]
    received_at = _received_at(msg, now)
    return {
        "email_id": email_id, "s3_key": f"inbox-raw/{email_id}.eml", "sha256": sha, "from_addr": from_addr,
        "from_domain": from_domain, "subject": str(msg.get("Subject", "")), "received_at": received_at,
        "dkim": dict(_NO_DKIM), "gsi1pk": f"domain#{from_domain}", "gsi1sk": received_at,
        "raw_b64": base64.b64encode(raw).decode("ascii"),
    }


def seed_inbox(emails_dir: Path, *, store: Any, settings: Any, now: datetime) -> int:
    try:
        from executor.facts.dkim import ingest
    except ImportError:
        ingest = None
    n = 0
    for path in sorted(emails_dir.glob("*.eml")):
        raw = path.read_bytes()
        if ingest is not None:
            received_at = _received_at(email.message_from_bytes(raw), now)
            ingest({"raw_b64": base64.b64encode(raw).decode("ascii"), "received_at": received_at},
                   store=store, settings=settings)
        else:
            store.put("inbox", inbox_row(raw, now=now))
        n += 1
    return n


def seed(*, settings: Any = None, data_dir: str | None = None, store: Any = None,
         now: datetime | None = None) -> dict[str, int]:
    """Load vendors.json (+ issuer pins), enrollment.json and emails/*.eml from `data_dir` (default
    settings.data_dir) into `store` (default get_store(settings)); returns counts."""
    settings = settings or Settings.from_env()
    if data_dir is not None and data_dir != settings.data_dir:
        settings = dataclasses.replace(settings, data_dir=data_dir)  # ingest reads the DNS snapshot from data_dir
    if store is None:
        from executor.store import get_store

        store = get_store(settings)
    now = now or datetime.now(timezone.utc)
    base = Path(settings.data_dir)
    vendors_path = base / "vendors.json"
    vendors = json.loads(vendors_path.read_text()) if vendors_path.exists() else []
    out = seed_registry(vendors, store=store, settings=settings, keys_dir=base / "issuer_keys", now=now)
    out["signers"] = seed_signers(base / "enrollment.json", store=store, settings=settings)
    out["emails"] = seed_inbox(base / "emails", store=store, settings=settings, now=now)
    return out


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    ap = argparse.ArgumentParser(description="Seed fictitious demo vendors, issuer pins, signers and emails.")
    ap.add_argument("--data-dir", default=None, help="default: AIRGAP_DATA_DIR or data/")
    args = ap.parse_args(argv)
    settings = Settings.from_env()
    try:
        counts = seed(settings=settings, data_dir=args.data_dir)
    except NotImplementedError as e:
        print(f"seed: backend not available yet: {e}", file=sys.stderr)
        return 1
    print(json.dumps(counts, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
