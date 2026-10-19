"""DLP content checks: IBANs, ICOs, registry names, card numbers (Luhn), record counts, encoded payloads. CONTRACTS.md §4.2.

Registry identifiers are matched by lookup (exact value from the vendor registry), not only by checksum: the demo ICOs
12345678 / 87654321 deliberately fail the CZ mod-11 checksum. Unknown identifiers are caught by checksum (IBAN mod-97,
labelled ICO mod-11, card Luhn). Base64/hex blobs are decoded one level and re-scanned.

Owner: WS-E.
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import Any

# Order of rule ids in decisions (CONTRACTS §4.2).
RULE_ORDER: list[str] = ["E-ALLOWLIST", "E-DLP-IBAN", "E-DLP-ICO", "E-DLP-NAME", "E-DLP-CARD", "E-DLP-COUNT",
                         "E-ENCODED", "E-URLDATA", "E-GUARDRAILS", "E-SIZE", "E-RATE"]

COUNT_THRESHOLD = 3  # >= this many identifiers (IBAN + ICO + card) in one message is a bulk record dump
NAME_THRESHOLD = 2  # >= this many distinct registry vendor names in one message

_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b")
_ICO_RE = re.compile(r"(?<!\d)\d{8}(?!\d)")
_ICO_LABEL_RE = re.compile(r"(?:I[CČ]O?|I[CČ]|DI[CČ]|reg(?:istration)?\.?\s*no\.?)\s*[:.]?\s*(?:CZ)?\s*$", re.I)
_CARD_RE = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)")
_B64_RE = re.compile(r"[A-Za-z0-9+/_-]{20,}={0,2}")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")


def iban_valid(iban: str) -> bool:
    """ISO 13616 mod-97 check."""
    s = iban.replace(" ", "").upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    digits = "".join(str(int(c, 36)) for c in s[4:] + s[:4])
    return int(digits) % 97 == 1


def ico_valid(ico: str) -> bool:
    """CZ IČO mod-11 check."""
    if not re.fullmatch(r"\d{8}", ico):
        return False
    s = sum(int(ico[i]) * (8 - i) for i in range(7))
    check = (11 - s % 11) % 10
    return check == int(ico[7])


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _registry_sets(vendors: list[dict[str, Any]]) -> tuple[set[str], set[str], dict[str, str]]:
    ibans: set[str] = set()
    icos: set[str] = set()
    names: dict[str, str] = {}
    for v in vendors:
        if v.get("iban"):
            ibans.add(str(v["iban"]).replace(" ", "").upper())
        for h in v.get("iban_history") or []:
            if h.get("iban"):
                ibans.add(str(h["iban"]).replace(" ", "").upper())
        if v.get("ico"):
            icos.add(str(v["ico"]))
        if v.get("name"):
            names[_norm_name(str(v["name"]))] = str(v["name"])
    return ibans, icos, names


def _norm_name(name: str) -> str:
    return re.sub(r"\s+", " ", name).strip().casefold()


def _find_ibans(text: str, registry: set[str]) -> tuple[set[str], set[str]]:
    """(registry IBANs, other mod-97-valid IBANs) found in text."""
    compact = text.upper()
    hit_reg: set[str] = set()
    hit_other: set[str] = set()
    for m in _IBAN_RE.finditer(compact):
        cand = m.group(0).replace(" ", "")
        # A greedy match may swallow trailing text; try every prefix length from longest down.
        for n in range(len(cand), 14, -1):
            c = cand[:n]
            if c in registry:
                hit_reg.add(c)
                break
            if iban_valid(c):
                hit_other.add(c)
                break
    # Registry values also match when embedded without word boundaries (e.g. "x=CZ65...").
    flat = re.sub(r"\s", "", compact)
    hit_reg |= {i for i in registry if i in flat}
    return hit_reg, hit_other - hit_reg


def _find_icos(text: str, registry: set[str]) -> tuple[set[str], set[str]]:
    """(registry ICOs, labelled checksum-valid ICOs). Unlabelled 8-digit numbers (VS, dates) are not flagged."""
    hit_reg: set[str] = set()
    hit_other: set[str] = set()
    for m in _ICO_RE.finditer(text):
        v = m.group(0)
        if v in registry:
            hit_reg.add(v)
        elif ico_valid(v) and _ICO_LABEL_RE.search(text[max(0, m.start() - 24):m.start()]):
            hit_other.add(v)
    return hit_reg, hit_other


def _find_cards(text: str) -> set[str]:
    return {re.sub(r"\D", "", m.group(0)) for m in _CARD_RE.finditer(text) if luhn_valid(m.group(0))}


def _find_names(text: str, names: dict[str, str]) -> set[str]:
    t = _norm_name(text)
    return {orig for norm, orig in names.items() if norm and norm in t}


def _decode_blobs(text: str) -> list[tuple[str, str]]:
    """[(kind, decoded text)] for base64 / hex runs that decode to mostly printable text."""
    out: list[tuple[str, str]] = []
    for m in _B64_RE.finditer(text):
        s = m.group(0)
        if s.isdigit() or re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", s):
            continue  # plain numbers / IBANs are not encodings
        pad = s + "=" * (-len(s) % 4)
        for dec in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = dec(pad.replace("-", "+").replace("_", "/") if dec is base64.b64decode else pad)
            except (binascii.Error, ValueError):
                continue
            txt = _printable(raw)
            if txt is not None:
                out.append(("base64", txt))
                break
    for m in _HEX_RE.finditer(text):
        s = m.group(0)
        if len(s) % 2:
            s = s[:-1]
        txt = _printable(bytes.fromhex(s))
        if txt is not None:
            out.append(("hex", txt))
    return out


def _printable(raw: bytes) -> str | None:
    if len(raw) < 8:
        return None
    try:
        txt = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    ok = sum(1 for c in txt if c.isprintable() or c in "\n\r\t")
    return txt if ok / len(txt) >= 0.9 else None


def _identifiers(text: str, vendors: list[dict[str, Any]]) -> dict[str, set[str]]:
    reg_ibans, reg_icos, names = _registry_sets(vendors)
    ib_reg, ib_other = _find_ibans(text, reg_ibans)
    ico_reg, ico_other = _find_icos(text, reg_icos)
    return {"iban_reg": ib_reg, "iban_other": ib_other, "ico_reg": ico_reg, "ico_other": ico_other,
            "card": _find_cards(text), "name": _find_names(text, names)}


def scan(content: str, attachments: list[dict[str, Any]], *, vendors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Findings [{rule_id, detail, count}]."""
    parts = [content or ""]
    for a in attachments or []:
        parts.append(str(a.get("name", "")))
        try:
            raw = base64.b64decode(a.get("content_b64", ""), validate=True)
        except (binascii.Error, ValueError):
            raw = b""
        parts.append(raw.decode("utf-8", "replace"))
    text = "\n".join(parts)

    ids = _identifiers(text, vendors)
    findings: list[dict[str, Any]] = []
    if ids["iban_reg"]:
        findings.append({"rule_id": "E-DLP-IBAN", "detail": "IBANs from vendor registry", "count": len(ids["iban_reg"])})
    if ids["iban_other"]:
        findings.append({"rule_id": "E-DLP-IBAN", "detail": "IBAN pattern (mod-97)", "count": len(ids["iban_other"])})
    if ids["ico_reg"]:
        findings.append({"rule_id": "E-DLP-ICO", "detail": "ICO from vendor registry", "count": len(ids["ico_reg"])})
    if ids["ico_other"]:
        findings.append({"rule_id": "E-DLP-ICO", "detail": "labelled ICO (mod-11)", "count": len(ids["ico_other"])})
    if len(ids["name"]) >= NAME_THRESHOLD:
        findings.append({"rule_id": "E-DLP-NAME", "detail": "several registry vendor names", "count": len(ids["name"])})
    if ids["card"]:
        findings.append({"rule_id": "E-DLP-CARD", "detail": "card number (Luhn)", "count": len(ids["card"])})
    n_ids = sum(len(ids[k]) for k in ("iban_reg", "iban_other", "ico_reg", "ico_other", "card"))
    if n_ids >= COUNT_THRESHOLD:
        findings.append({"rule_id": "E-DLP-COUNT", "detail": f"{n_ids} identifiers in one message", "count": n_ids})

    blobs = _decode_blobs(text)
    if blobs:
        kinds = sorted({k for k, _ in blobs})
        hidden = 0
        for _, dec in blobs:
            d = _identifiers(dec, vendors)
            hidden += sum(len(d[k]) for k in ("iban_reg", "iban_other", "ico_reg", "ico_other", "card"))
        detail = f"{'/'.join(kinds)} blob" + (f" hiding {hidden} identifiers" if hidden else "")
        findings.append({"rule_id": "E-ENCODED", "detail": detail, "count": len(blobs)})
    return findings


def order_rule_ids(findings: list[dict[str, Any]]) -> list[str]:
    ids = {f["rule_id"] for f in findings}
    return [r for r in RULE_ORDER if r in ids]
