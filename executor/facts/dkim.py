"""F-DKIM: dkimpy verification at ingest, DNS answered from the content-hashed dns snapshot. CONTRACTS.md v2 §2.1.

Owner: WS-D.

`dkim_verdict` runs once at ingest (the verdict is stored on the inbox row); `dkim_fact` turns that stored verdict
into the fact, with prov = sha256 of data/dns_snapshot.json. No live DNS: a name missing from the snapshot resolves
to nothing, which dkimpy reports as a failed verification.

`ingest` implements POST /ingest (CONTRACTS §4.1 #26, §3.1 inbox, §7.2 `ingest` leaf): the raw .eml goes to
s3://<AIRGAP_INBOX_BUCKET>/inbox-raw/<email_id>.eml on aws, inline as `raw_b64` on the inbox row on memory/moto (where
GET /inbox/{email_id}/raw reads it). Content-addressed and idempotent: the same bytes always give the same email_id.
"""
from __future__ import annotations

import base64
import binascii
import re
from email import message_from_bytes
from email.header import decode_header, make_header
from email.utils import getaddresses
from pathlib import Path
from typing import Any

import dkim as dkimpy

from executor.config import iso
from executor.config import now as clock
from executor.errors import ApiError, ErrorCode
from executor.facts import _util
from executor.models import Fact

_TAG_RE = re.compile(rb"(?:^|;)\s*([a-z]+)\s*=\s*([^;]*)")


def _from_domain(raw_eml: bytes) -> str | None:
    msg = message_from_bytes(raw_eml)
    addrs = getaddresses(msg.get_all("From") or [])
    if len(addrs) != 1 or "@" not in addrs[0][1]:
        return None  # zero or several From addresses: no alignment possible
    return addrs[0][1].rsplit("@", 1)[1].strip().lower().rstrip(".") or None


def _first_signature_tags(raw_eml: bytes) -> dict[str, str] | None:
    msg = message_from_bytes(raw_eml)
    sig = msg.get("DKIM-Signature")
    if sig is None:
        return None
    flat = re.sub(rb"\s+", b"", str(sig).encode("ascii", "replace"))
    return {k.decode(): v.decode("ascii", "replace") for k, v in _TAG_RE.findall(flat)}


def _dnsfunc(dns_snapshot: dict[str, Any]):
    table = {str(k).lower().rstrip("."): v for k, v in dns_snapshot.items()}

    def get_txt(name: bytes | str, timeout: int = 5) -> bytes | None:
        key = (name.decode("ascii", "replace") if isinstance(name, bytes) else name).lower().rstrip(".")
        val = table.get(key)
        return val.encode("ascii") if isinstance(val, str) else None

    return get_txt


def dkim_verdict(raw_eml: bytes, *, dns_snapshot: dict[str, Any]) -> dict[str, Any]:
    """{"result": "pass"|"fail"|"none", "d", "s", "aligned"} for the first DKIM-Signature of a raw message.

    A signature with a body length limit (l=) is a "fail": content appended after the signed length would be shown
    to the agent under a valid signature."""
    from_domain = _from_domain(raw_eml)
    tags = _first_signature_tags(raw_eml)
    if tags is None:
        return {"result": "none", "d": None, "s": None, "aligned": False}
    d = (tags.get("d") or "").lower().rstrip(".") or None
    s = tags.get("s") or None
    signer = dkimpy.DKIM(raw_eml, minkey=1024)
    try:
        ok = bool(signer.verify(dnsfunc=_dnsfunc(dns_snapshot)))
    except Exception:  # noqa: BLE001 - any parse/crypto error is a failed verification (fail closed)
        ok = False
    if ok:
        # d/s as dkimpy actually verified them (not our own tag parse); l= is refused.
        d = signer.domain.decode("ascii", "replace").lower().rstrip(".") if signer.domain else None
        s = signer.selector.decode("ascii", "replace") if isinstance(signer.selector, bytes) else s
        ok = d is not None and b"l" not in (signer.signature_fields or {})
    return {"result": "pass" if ok else "fail", "d": d, "s": s,
            "aligned": bool(ok and d is not None and d == from_domain)}


def _str_or_none(v: Any) -> str | None:
    return v if isinstance(v, str) else None


def dkim_fact(verdict: dict[str, Any], *, prov: str) -> Fact:
    """pass + aligned -> INFO "DKIM PASS"; fail, none or unaligned -> BLOCK "DKIM FAIL"."""
    result = verdict.get("result") if verdict.get("result") in ("pass", "fail", "none") else "none"
    d = _str_or_none(verdict.get("d"))
    s = _str_or_none(verdict.get("s"))
    aligned = verdict.get("aligned") is True  # strict: a truthy non-bool (e.g. "false") never counts as aligned
    evidence = {"result": result, "d": d, "s": s, "aligned": aligned}
    if result == "pass" and aligned:
        return _util.make_fact("F-DKIM", "INFO", f"DKIM signature valid, d={d} aligned with From", "DKIM PASS",
                               evidence=evidence, prov=prov)
    if result == "pass":
        label = f"DKIM signature valid for d={d} but not aligned with the From domain"
    elif result == "fail":
        label = f"DKIM signature did not verify (d={d}, s={s})"
    else:
        label = "No DKIM signature on the message"
    return _util.make_fact("F-DKIM", "BLOCK", label, "DKIM FAIL", evidence=evidence, prov=prov)


# ---------------------------------------------------------------- ingest (POST /ingest)

RAW_PREFIX = "inbox-raw/"


def raw_key(email_id: str) -> str:
    """S3 key of the raw message (CONTRACTS §9 AIRGAP_INBOX_BUCKET)."""
    return f"{RAW_PREFIX}{email_id}.eml"


def _from_addr(raw_eml: bytes) -> str:
    addrs = getaddresses(message_from_bytes(raw_eml).get_all("From") or [])
    return addrs[0][1].strip().lower() if len(addrs) == 1 and "@" in addrs[0][1] else ""


def _subject(raw_eml: bytes) -> str:
    value = message_from_bytes(raw_eml).get("Subject")
    if value is None:
        return ""
    try:
        return str(make_header(decode_header(str(value))))
    except (LookupError, UnicodeError, ValueError):  # undecodable encoded-word: keep the raw header text
        return str(value)


def _received_at(body: dict[str, Any], settings: Any) -> str:
    """Override honoured only off AWS (CONTRACTS §4.1); otherwise the executor clock, whole seconds."""
    if body.get("received_at") and settings.backend != "aws":
        return body["received_at"]
    return iso(clock(settings).replace(microsecond=0))


def _put_raw(email_id: str, raw_eml: bytes, *, settings: Any) -> None:
    import boto3

    boto3.client("s3", region_name=settings.aws_region).put_object(
        Bucket=settings.inbox_bucket, Key=raw_key(email_id), Body=raw_eml, ContentType="message/rfc822")


def ingest(body: dict[str, Any], *, store: Any, settings: Any) -> dict[str, Any]:
    """POST /ingest {raw_b64, received_at?} -> {email_id, from_domain, received_at}.

    email_id = eml_<16 hex of sha256(raw)>; inbox row per CONTRACTS §3.1 with the ingest-time DKIM verdict over the
    dns snapshot in settings.data_dir; one `ingest` leaf (actor ingest). Re-ingesting the same bytes returns the
    stored row unchanged and writes nothing."""
    from executor.store import shims

    try:
        raw_eml = base64.b64decode(body["raw_b64"], validate=True)
    except (binascii.Error, ValueError) as e:
        raise ApiError(ErrorCode.INVALID_REQUEST, "raw_b64: not valid base64") from e
    if not raw_eml:
        raise ApiError(ErrorCode.INVALID_REQUEST, "raw_b64: empty message")
    sha = _util.sha256_hex(raw_eml)
    email_id = f"eml_{sha[:16]}"
    existing = store.get("inbox", {"email_id": email_id})
    if existing is not None:
        return {k: existing[k] for k in ("email_id", "from_domain", "received_at")}

    dns_snapshot, _ = _util.load_json(Path(settings.data_dir) / _util.SNAPSHOT_FILES["dns"])
    from_addr = _from_addr(raw_eml)
    from_domain = from_addr.rsplit("@", 1)[1].rstrip(".") if from_addr else ""
    received_at = _received_at(body, settings)
    row: dict[str, Any] = {
        "email_id": email_id, "s3_key": raw_key(email_id), "sha256": sha, "from_addr": from_addr,
        "from_domain": from_domain, "subject": _subject(raw_eml), "received_at": received_at,
        "dkim": dkim_verdict(raw_eml, dns_snapshot=dns_snapshot),
        "gsi1pk": f"domain#{from_domain}", "gsi1sk": received_at,
    }
    if settings.backend == "aws":
        _put_raw(email_id, raw_eml, settings=settings)  # before the row: a row never points at a missing object
    else:
        row["raw_b64"] = base64.b64encode(raw_eml).decode("ascii")  # memory/moto: read back by GET /inbox/{id}/raw
    if not store.put_if_absent("inbox", row, "email_id"):  # concurrent ingest of the same bytes won
        won = store.get("inbox", {"email_id": email_id}) or row
        return {k: won[k] for k in ("email_id", "from_domain", "received_at")}
    data = {"email_id": email_id, "sha256": sha, "from_domain": from_domain, "received_at": received_at,
            "dkim": row["dkim"]}
    shims.append(shims.make_event("ingest", data, subject_id=email_id, actor="ingest", settings=settings),
                 store=store, settings=settings)
    return {"email_id": email_id, "from_domain": from_domain, "received_at": received_at}
