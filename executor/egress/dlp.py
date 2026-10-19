"""DLP content checks: IBANs, ICOs, registry names, card numbers (Luhn), record counts, encoded payloads. CONTRACTS.md §4.2.

Registry identifiers are matched by lookup (exact value from the vendor registry), not only by checksum: the demo ICOs
12345678 / 87654321 deliberately fail the CZ mod-11 checksum. Before matching, text is normalised (NFKC, format chars
such as zero-width spaces removed, spelled-out digits mapped) and registry values are also searched in separator-joined
digit runs (forwards and reversed), which covers dashes/dots/spaces, the CZ domestic form `19-2000145399/0800` and
letter-only obfuscations such as ROT13 of the country code. Unknown IBANs are caught by mod-97 and cards by IIN+Luhn.
Third-party ICOs that are not in the registry are public data and are not flagged. base64/base32/base85/hex blobs
(and adjacent base64 chunks joined) are decoded one level and re-scanned.

Strict by design: a vendor's own registry identifiers are blocked even when sent back to that vendor; the agent only
sends fixed templates (mail.send_template) so legitimate mail never needs them.

Owner: WS-E.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from typing import Any

# Order of rule ids in decisions (CONTRACTS §4.2).
RULE_ORDER: list[str] = ["E-ALLOWLIST", "E-DLP-IBAN", "E-DLP-ICO", "E-DLP-NAME", "E-DLP-CARD", "E-DLP-COUNT",
                         "E-ENCODED", "E-URLDATA", "E-GUARDRAILS", "E-SIZE", "E-RATE"]

COUNT_THRESHOLD = 3  # >= this many identifiers (IBAN + ICO + card) in one message is a bulk record dump
NAME_THRESHOLD = 3  # >= this many distinct registry vendor names in one message

_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b")
_CARD_RE = re.compile(r"(?<![\d-])(?:\d{4}([ -]?)\d{4}\1\d{4}\1\d{4}|3[47]\d{2}([ -]?)\d{6}\2\d{5})(?![\d-])")
_SEP_RE = re.compile(r"(?<=[0-9A-Za-z])[\s\-./_,:;|+*'\"]{1,3}(?=[0-9A-Za-z])")
_DIGITS_RE = re.compile(r"\d{6,}")
_B64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_-]{8,}={0,2}")
_B64_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_B32_RE = re.compile(r"[A-Z2-7]{16,}={0,6}")
_B85_RE = re.compile(r"[!-~]{20,}")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_DIGIT_WORDS = {w: str(i) for i, ws in enumerate([
    ("zero", "nula"), ("one", "jedna", "jeden"), ("two", "dva", "dve", "dvě"), ("three", "tri", "tři"),
    ("four", "ctyri", "čtyři"), ("five", "pet", "pět"), ("six", "sest", "šest"), ("seven", "sedm"),
    ("eight", "osm"), ("nine", "devet", "devět")]) for w in ws}
_DIGIT_WORD_RE = re.compile(r"\b(" + "|".join(sorted(_DIGIT_WORDS, key=len, reverse=True)) + r")\b", re.I)


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
    return (11 - s % 11) % 10 == int(ico[7])


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


def normalize(text: str) -> str:
    """NFKC, drop format chars (zero-width, soft hyphen, BOM), map spelled-out digits."""
    t = unicodedata.normalize("NFKC", text)
    t = "".join(c for c in t if unicodedata.category(c) != "Cf")
    return _DIGIT_WORD_RE.sub(lambda m: _DIGIT_WORDS[m.group(1).lower()], t)


class Registry:
    """Lookup sets derived from registry rows."""

    def __init__(self, vendors: list[dict[str, Any]]) -> None:
        self.ibans: set[str] = set()
        self.icos: set[str] = set()
        self.names: dict[str, str] = {}
        for v in vendors:
            for i in [v.get("iban")] + [h.get("iban") for h in v.get("iban_history") or []]:
                if i:
                    self.ibans.add(str(i).replace(" ", "").upper())
            if v.get("ico"):
                self.icos.add(str(v["ico"]))
            if v.get("name"):
                self.names[_norm_name(str(v["name"]))] = str(v["name"])
        # Digit cores: IBAN without country code, and for CZ the account (prefix+number) without leading zeros.
        # Short cores (< 10 digits) only count as a whole digit run or followed by the bank code (domestic form).
        self.iban_cores: dict[str, str] = {}
        self.short_cores: dict[str, str] = {}
        for i in self.ibans:
            if i[2:].isdigit():
                self.iban_cores[i[2:]] = i
            if i.startswith("CZ") and len(i) == 24:
                core = (i[8:14] + i[14:]).lstrip("0")
                if len(core) >= 10:
                    self.iban_cores[core] = i
                else:
                    self.short_cores[core] = i
                    self.iban_cores[core + i[4:8]] = i


def _norm_name(name: str) -> str:
    return re.sub(r"\s+", " ", name).strip().casefold()


def _digit_runs(text: str) -> list[str]:
    joined = _SEP_RE.sub("", text)
    runs = _DIGITS_RE.findall(joined)
    return runs + [r[::-1] for r in runs]


def _registry_hits(text: str, reg: Registry) -> tuple[set[str], set[str]]:
    """(registry IBANs, registry ICOs) present in text in any separator/ordering form."""
    upper = text.upper()
    flat = _SEP_RE.sub("", upper)
    ibans = {i for i in reg.ibans if i in flat or i[::-1] in flat}
    icos: set[str] = set()
    for run in _digit_runs(upper):
        ibans |= {i for core, i in reg.iban_cores.items() if core in run}
        ibans |= {i for core, i in reg.short_cores.items() if core == run.lstrip("0")}
        icos |= {c for c in reg.icos if c == run}  # whole run: avoids hits inside parcel/order numbers
    # An ICO found only inside a registry IBAN's digits is that IBAN, not the ICO.
    rest = flat
    for i in ibans:
        rest = rest.replace(i, " ").replace(i[::-1], " ")
        for core, owner in reg.iban_cores.items():
            if owner == i:
                rest = rest.replace(core, " ")
    rest_runs = _digit_runs(rest)
    icos = {c for c in icos if c in rest_runs}
    return ibans, icos


def _other_ibans(text: str, reg: Registry) -> set[str]:
    out: set[str] = set()
    for m in _IBAN_RE.finditer(text.upper()):
        cand = m.group(0).replace(" ", "")
        for n in range(len(cand), 14, -1):  # greedy match may swallow trailing text
            if iban_valid(cand[:n]):
                if cand[:n] not in reg.ibans:
                    out.add(cand[:n])
                break
    return out


def _find_cards(text: str) -> set[str]:
    out = set()
    for m in _CARD_RE.finditer(text):
        n = re.sub(r"\D", "", m.group(0))
        if re.match(r"4|5[1-5]|2[2-7]|3[47]|6(?:011|5)", n) and luhn_valid(n):
            out.add(n)
    return out


def _find_names(text: str, reg: Registry) -> set[str]:
    t = _norm_name(text)
    return {orig for norm, orig in reg.names.items() if norm and norm in t}


def printable(raw: bytes) -> str | None:
    if len(raw) < 8:
        return None
    try:
        txt = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    ok = sum(1 for c in txt if c.isprintable() or c in "\n\r\t")
    letters = sum(1 for c in txt if c.isalnum())
    return txt if ok / len(txt) >= 0.95 and letters / len(txt) >= 0.5 else None


def _b64(s: str) -> str | None:
    s = s.rstrip("=")
    for alt in (None, b"-_"):
        try:
            raw = base64.b64decode(s + "=" * (-len(s) % 4), altchars=alt, validate=True)
        except (binascii.Error, ValueError):
            continue
        txt = printable(raw)
        if txt:
            return txt
    return None


def decode_blobs(text: str) -> list[tuple[str, str]]:
    """[(kind, decoded text)] for base64 / base32 / base85 / hex runs that decode to printable text."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(kind: str, src: str, txt: str | None) -> None:
        if txt and src not in seen:
            seen.add(src)
            out.append((kind, txt))

    for m in _B64_RE.finditer(text):
        add("base64", m.group(0), _b64(m.group(0)))
    tokens = [t for t in _B64_TOKEN_RE.findall(text) if not t.isdigit()]
    for i in range(len(tokens)):  # chunks split across tokens: try adjacent concatenations
        for j in range(i + 2, min(len(tokens), i + 6) + 1):
            joined = "".join(t.rstrip("=") for t in tokens[i:j])
            add("base64", joined, _b64(joined))
    for m in _B32_RE.finditer(text):
        s = m.group(0)
        try:
            add("base32", s, printable(base64.b32decode(s + "=" * (-len(s.rstrip("=")) % 8))))
        except (binascii.Error, ValueError):
            pass
    for m in _B85_RE.finditer(text):
        s = m.group(0)
        if s in seen or re.fullmatch(r"[A-Za-z0-9+/=_.:-]+", s):
            continue  # plain words / base64 already handled
        for dec in (base64.b85decode, base64.a85decode):
            try:
                add("base85", s, printable(dec(s)))
            except (binascii.Error, ValueError):
                pass
    for m in _HEX_RE.finditer(text):
        s = m.group(0)[: len(m.group(0)) // 2 * 2]
        add("hex", s, printable(bytes.fromhex(s)))
    return out


def _identifiers(text: str, reg: Registry) -> dict[str, set[str]]:
    t = normalize(text)
    ib_reg, ico_reg = _registry_hits(t, reg)
    return {"iban_reg": ib_reg, "iban_other": _other_ibans(t, reg), "ico_reg": ico_reg,
            "card": _find_cards(t), "name": _find_names(t, reg)}


def _n_ids(ids: dict[str, set[str]]) -> int:
    return sum(len(ids[k]) for k in ("iban_reg", "iban_other", "ico_reg", "card"))


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
    reg = Registry(vendors)

    ids = _identifiers(text, reg)
    findings: list[dict[str, Any]] = []
    if ids["iban_reg"]:
        findings.append({"rule_id": "E-DLP-IBAN", "detail": "IBANs from vendor registry", "count": len(ids["iban_reg"])})
    if ids["iban_other"]:
        findings.append({"rule_id": "E-DLP-IBAN", "detail": "IBAN pattern (mod-97)", "count": len(ids["iban_other"])})
    if ids["ico_reg"]:
        findings.append({"rule_id": "E-DLP-ICO", "detail": "ICO from vendor registry", "count": len(ids["ico_reg"])})
    if len(ids["name"]) >= NAME_THRESHOLD:
        findings.append({"rule_id": "E-DLP-NAME", "detail": "several registry vendor names", "count": len(ids["name"])})
    if ids["card"]:
        findings.append({"rule_id": "E-DLP-CARD", "detail": "card number (IIN + Luhn)", "count": len(ids["card"])})
    n_ids = _n_ids(ids)
    if n_ids >= COUNT_THRESHOLD:
        findings.append({"rule_id": "E-DLP-COUNT", "detail": f"{n_ids} identifiers in one message", "count": n_ids})

    blobs = decode_blobs(normalize(text))
    if blobs:
        kinds = sorted({k for k, _ in blobs})
        hidden = sum(_n_ids(_identifiers(dec, reg)) for _, dec in blobs)
        detail = f"{'/'.join(kinds)} blob" + (f" hiding {hidden} identifiers" if hidden else "")
        findings.append({"rule_id": "E-ENCODED", "detail": detail, "count": len(blobs)})
    return findings


def order_rule_ids(findings: list[dict[str, Any]]) -> list[str]:
    ids = {f["rule_id"] for f in findings}
    return [r for r in RULE_ORDER if r in ids]
