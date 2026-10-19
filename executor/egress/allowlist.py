"""Destination allowlist (vendor domains from registry + internal addresses). CONTRACTS.md §4.2.

send_email: the recipient domain must equal a registry vendor's `domain` (or the domain of its registered
`contact_email`), or an internal domain. http_*/upload: https only, host equal to a vendor domain (or www.<domain>).
Exact ASCII matches only: no subdomains of vendor domains, no IDN/homoglyph hosts, no userinfo or ports.

Owner: WS-E.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

INTERNAL_DOMAINS: frozenset[str] = frozenset({"airgap.example"})

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)$")
_URL_IN_TEXT_RE = re.compile(r"(?:https?:)?//[^\s)\"'<>]+", re.I)
_MAX_PLAIN_PARAM = 64


def _vendor_domains(vendors: list[dict[str, Any]]) -> set[str]:
    out: set[str] = set()
    for v in vendors:
        if v.get("domain"):
            out.add(str(v["domain"]).lower().strip("."))
        m = _EMAIL_RE.match(str(v.get("contact_email") or ""))
        if m:
            out.add(m.group(1).lower())
    return out


def target_domain(tool: str, target: str) -> str | None:
    """Domain a target resolves to, or None if malformed / not plain ASCII."""
    if not target.isascii():
        return None
    if tool == "send_email":
        m = _EMAIL_RE.match(target.strip())
        return m.group(1).lower() if m else None
    parts = urlsplit(target)
    if parts.scheme != "https" or parts.username or parts.password or parts.port:
        return None
    return (parts.hostname or "").lower().strip(".") or None


def is_allowed(tool: str, target: str, *, vendors: list[dict[str, Any]]) -> bool:
    """True if target is on the allowlist."""
    dom = target_domain(tool, target)
    if dom is None:
        return False
    allowed = _vendor_domains(vendors) | INTERNAL_DOMAINS
    if tool == "send_email":
        return dom in allowed
    return dom in allowed or (dom.startswith("www.") and dom[4:] in allowed)


def urls_in(text: str) -> list[str]:
    """URLs (incl. markdown image/link targets) embedded in free text."""
    return [m.group(0) for m in _URL_IN_TEXT_RE.finditer(text or "")]


def _looks_encoded(value: str) -> bool:
    """Value is long, or decodes (base64/base32/hex/url-escaped) to printable text."""
    from executor.egress import dlp

    v = unquote(value)
    if len(v) > _MAX_PLAIN_PARAM:
        return True
    return bool(dlp.decode_blobs(v)) or (v != value and len(v) >= 16 and not v.replace("-", "").isalnum())


def url_data_findings(target: str) -> list[dict[str, Any]]:
    """E-URLDATA findings for data smuggled in URL query/path/fragment. Plain ids, slugs and UUIDs pass; registry
    identifiers anywhere in a URL are caught by DLP on the target string."""
    if "//" not in target:
        return []
    parts = urlsplit(target if "://" in target else "https:" + target)
    findings: list[dict[str, Any]] = []
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        if _looks_encoded(v):
            findings.append({"rule_id": "E-URLDATA", "detail": f"query parameter {k[:32]}", "count": 1})
    for seg in parts.path.split("/"):
        if _looks_encoded(seg.rsplit(".", 1)[0]):
            findings.append({"rule_id": "E-URLDATA", "detail": "encoded path segment", "count": 1})
    if parts.fragment and _looks_encoded(parts.fragment):
        findings.append({"rule_id": "E-URLDATA", "detail": "fragment", "count": 1})
    return findings
