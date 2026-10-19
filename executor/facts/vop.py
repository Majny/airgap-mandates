"""F-VOP: SIMULATED Verification of Payee responder with EPC codes. CONTRACTS.md v2 §2.1.

Reads data/vop_mock.json (`{"participants": {"<CC>": [bank codes]}, "accounts": {"<IBAN>": {"holder", "ico"?}}}`);
no real VoP scheme is called. MTCH -> INFO 'VOP MTCH'; CMTC -> WARN 'VOP CMTC'; NMTC -> BLOCK 'VOP NMTC';
NOAP -> WARN 'VOP NOAP'. Owner: WS-D.
"""
from __future__ import annotations

import os
import re
import unicodedata

from rapidfuzz import fuzz

from executor.facts import _util
from executor.models import Fact
from executor.render import BANK_CODE_LEN

LABEL = "Verification of Payee (simulated)"
CLOSE_RATIO = 85

_SEVERITY = {"MTCH": "INFO", "CMTC": "WARN", "NMTC": "BLOCK", "NOAP": "WARN"}
# Legal forms dropped before comparing (after punctuation removal): s.r.o., spol. s r.o., a.s., k.s., v.o.s., ...
_LEGAL_FORMS = {"sro", "spol", "as", "ks", "vos", "se", "zs", "ltd", "gmbh", "ag", "uab", "inc", "llc", "plc"}


def norm_iban(iban: str) -> str:
    return "".join(str(iban).split()).upper()


def bank_code(iban: str) -> str | None:
    s = norm_iban(iban)
    n = BANK_CODE_LEN.get(s[:2])
    return s[4 : 4 + n] if n else None


def _fold(name: str) -> str:
    """Lower-case, no diacritics, the Czech legal forms written out ("spol. s r.o.", "s. r. o.", "a. s.") collapsed to
    one token (sro / as). Letters without an ASCII decomposition (Cyrillic/Greek homoglyphs, ...) are kept."""
    s = unicodedata.normalize("NFKD", str(name))
    s = "".join(c for c in s if not unicodedata.combining(c)).lower()
    s = re.sub(r"\bspol\s*\.?\s*s\s*\.?\s*r\s*\.?\s*o\b\.?", " sro ", s)  # "spol. s r.o." -> sro
    s = re.sub(r"\bs\s*\.?\s*r\s*\.?\s*o\b\.?", " sro ", s)  # "s. r. o." -> sro
    s = re.sub(r"\ba\s*\.\s*s\b\.?", " as ", s)  # "a. s." -> as
    return s


def normalize_name(name: str) -> str:
    """Lower-case, no diacritics or punctuation, legal forms (s.r.o., a.s., sro, as, ...) removed: the core name the
    CMTC rule compares.

    Letters without an ASCII decomposition (Cyrillic/Greek homoglyphs, ...) are kept, not dropped, so a holder like
    "ACME \u0414\u0414" can never normalise to an exact "acme" match."""
    s = "".join(c if c.isalnum() else " " if c.isspace() else "" for c in _fold(name))
    return " ".join(t for t in s.split() if t not in _LEGAL_FORMS)


def exact_name(name: str) -> str:
    """The MTCH form: diacritics, case and whitespace folded and the legal form canonicalised (s.r.o. == sro ==
    spol. s r.o.) but KEPT, and punctuation a word separator (never deleted), so 'ACME a.s.' / 'ACME GmbH' (another
    legal entity) and 'A.C.M.E.' never equal 'ACME s.r.o.'."""
    return " ".join("".join(c if c.isalnum() else " " for c in _fold(name)).split())


def match_code(requested: str, holder: str) -> tuple[str, int]:
    """(EPC code, similarity 0..100) for the requested name vs the registered account holder. MTCH only for the same
    name with the same legal form; the same core name under another legal form (or punctuation) is at most CMTC."""
    a, b = normalize_name(requested), normalize_name(holder)
    if not a or not b:
        return "NMTC", 0
    if exact_name(requested) == exact_name(holder):
        return "MTCH", 100
    if a == b:
        return "CMTC", 100
    score = int(round(fuzz.token_sort_ratio(a, b)))
    # All of the requested (registered) name's tokens inside the holder name ("ACME SRO Trading" for "ACME s.r.o.")
    # is a close match too. Only this direction: a holder that is a fragment of the name ("Tisk" for "Gamma Tisk")
    # stays NMTC.
    contained = set(a.split()) <= set(b.split())
    return ("CMTC" if score >= CLOSE_RATIO or contained else "NMTC"), score


def vop_fact(iban: str, name: str, *, vop_path: str | os.PathLike[str]) -> Fact:
    """Simulated VoP request for (iban, name) against the mock snapshot; prov = its sha256."""
    mock, sha = _util.load_json(vop_path)
    s = norm_iban(iban)
    cc, code = s[:2], bank_code(s)
    participant = code is not None and code in (mock.get("participants") or {}).get(cc, [])
    account = (mock.get("accounts") or {}).get(s) if participant else None
    evidence: dict[str, object] = {"country": cc, "bank_code": code, "participant": participant,
                                   "account_found": account is not None}
    if account is None:
        epc, score, label = "NOAP", 0, f"{LABEL}: not applicable"
    else:
        epc, score = match_code(name, account.get("holder", ""))
        label = f"{LABEL}: {epc}"
        if epc == "CMTC":
            label = f"{LABEL}: close match, account holder is {account.get('holder', '')!r}"
            evidence["holder"] = account.get("holder", "")
        evidence["score"] = score
    evidence["code"] = epc
    return _util.make_fact("F-VOP", _SEVERITY[epc], label, f"VOP {epc}", evidence=evidence, prov=sha)
