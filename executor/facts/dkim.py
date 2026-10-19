"""F-DKIM: dkimpy verification at ingest, DNS answered from the content-hashed dns snapshot. CONTRACTS.md v2 §2.1.

Owner: WS-D.

`dkim_verdict` runs once at ingest (the verdict is stored on the inbox row); `dkim_fact` turns that stored verdict
into the fact, with prov = sha256 of data/dns_snapshot.json. No live DNS: a name missing from the snapshot resolves
to nothing, which dkimpy reports as a failed verification.
"""
from __future__ import annotations

import re
from email import message_from_bytes
from email.utils import getaddresses
from typing import Any

import dkim as dkimpy

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
