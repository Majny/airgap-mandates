"""F-DOMAIN: sender domain vs the vendor master `domain` (homoglyphs, edit distance, hyphen/TLD tricks) plus the
MostlyRight warnings leg. CONTRACTS.md v2 §2.1.

Owner: WS-D.

exact or subdomain of the registry domain -> INFO "DOMAIN MATCH"; lookalike -> BLOCK "DOMAIN LOOKALIKE"; anything
else -> WARN "DOMAIN UNKNOWN". A sender domain listed in MostlyRight warnings (website_domain / email_domain) is
BLOCK "DOMAIN LOOKALIKE" with evidence warnlisted=true; prov is set only when that leg ran.
"""
from __future__ import annotations

import unicodedata
from os import PathLike
from typing import Any

from confusable_homoglyphs import confusables
from rapidfuzz.distance import Levenshtein

from executor.facts import _util
from executor.models import Fact

# Multi-character visual tricks applied after the per-character skeleton.
_SEQ_TRICKS = (("rn", "m"), ("vv", "w"), ("cl", "d"))
_CHAR_TRICKS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "|": "l"})
_MIN_CONTAIN = 4  # label length below which substring containment is too noisy to call a lookalike


def _normalize(domain: str) -> str:
    """Lower-case, strip dots/space, decode punycode (xn--) labels to Unicode."""
    d = (domain or "").strip().lower().rstrip(".")
    labels = []
    for label in d.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def _char_skeleton(ch: str) -> str:
    if ch.isascii():
        return ch
    hits = confusables.is_confusable(ch, greedy=True, preferred_aliases=["latin"])
    if hits:
        for h in hits[0]["homoglyphs"]:
            if h["c"].isascii():
                return h["c"].lower()
    stripped = "".join(c for c in unicodedata.normalize("NFKD", ch) if not unicodedata.combining(c))
    return stripped if stripped.isascii() else ch


def _skeleton(s: str) -> str:
    # Invisible characters (zero-width, soft hyphen, combining marks, spaces) are dropped before comparison so they
    # cannot inflate the edit distance of an otherwise identical label.
    s = "".join(c for c in unicodedata.normalize("NFKC", s) if unicodedata.category(c)[0] not in "CZ")
    out = "".join(_char_skeleton(c) for c in s).lower().translate(_CHAR_TRICKS)
    for seq, rep in _SEQ_TRICKS:
        out = out.replace(seq, rep)
    return out


def _split(domain: str) -> tuple[str, str]:
    """(registrable label, tld) of a normalized domain: 'mail.acme.cz' -> ('acme', 'cz')."""
    parts = domain.split(".")
    if len(parts) < 2:
        return domain, ""
    return parts[-2], parts[-1]


def _is_same(raw_candidate: str, candidate: str, reference: str) -> bool:
    """Exact (or subdomain) match; the raw sender domain must be ASCII (punycode allowed), so a Unicode spelling that
    lower-cases to the reference (e.g. KELVIN SIGN for k) is never a match."""
    if not (raw_candidate or "").isascii():
        return False
    return candidate == reference or candidate.endswith("." + reference)


def _lookalike_reason(candidate: str, reference: str) -> str | None:
    cand, ref = _normalize(candidate), _normalize(reference)
    if not cand or not ref or _is_same(candidate, cand, ref):
        return None
    ref_label, ref_tld = _split(ref)
    cand_label, _ = _split(cand)
    if _skeleton(cand_label) == _skeleton(ref_label):
        same_tld = _split(cand)[1] == ref_tld
        return "same_label_other_tld" if cand_label == ref_label and not same_tld else "homoglyph"
    flat_cand = _skeleton(cand.replace("-", "").replace(".", ""))
    flat_ref = _skeleton(ref_label + ref_tld)
    if flat_ref in flat_cand:
        return "embedded_reference"  # acme-cz.com, acme.cz.com, acmecz.net
    if len(ref_label) >= _MIN_CONTAIN and _skeleton(ref_label) in _skeleton(cand_label.replace("-", "")):
        return "embedded_label"  # acme-invoices.cz
    max_dist = 1 if len(ref_label) <= 5 else 2
    if Levenshtein.distance(_skeleton(cand_label), _skeleton(ref_label)) <= max_dist:
        return "edit_distance"
    return None


def is_lookalike(candidate: str, reference: str) -> bool:
    """True if candidate imitates reference (never for reference itself or its subdomains)."""
    return _lookalike_reason(candidate, reference) is not None


def domain_fact(from_domain: str, registry_domain: str, *, mr_path: str | PathLike[str] | None = None) -> Fact:
    """F-DOMAIN for a sender domain against the vendor master domain (+ MostlyRight warnings when mr_path)."""
    cand = _normalize(from_domain)
    ref = _normalize(registry_domain)
    evidence: dict[str, Any] = {"from_domain": from_domain, "registry_domain": registry_domain, "warnlisted": False}
    prov = None
    if mr_path is not None:
        from executor.facts import mostlyright

        hit = mostlyright.warning_domain_hit(from_domain, mr_path=mr_path)
        prov = mostlyright.snapshot_sha(mr_path)
        if hit:
            evidence.update({"match": "warnlisted", "warnlisted": True})
            return _util.make_fact("F-DOMAIN", "BLOCK",
                                   f"Sender domain {from_domain} is listed in a regulator warning",
                                   "DOMAIN LOOKALIKE", evidence=evidence, prov=prov)
    if cand and ref and _is_same(from_domain, cand, ref):
        evidence["match"] = "exact" if cand == ref else "subdomain"
        return _util.make_fact("F-DOMAIN", "INFO", f"Sender domain {from_domain} matches vendor domain {ref}",
                               "DOMAIN MATCH", evidence=evidence, prov=prov)
    reason = _lookalike_reason(from_domain, registry_domain) if ref else None
    if reason:
        evidence.update({"match": "lookalike", "reason": reason})
        return _util.make_fact("F-DOMAIN", "BLOCK",
                               f"Sender domain {from_domain} imitates vendor domain {ref} ({reason})",
                               "DOMAIN LOOKALIKE", evidence=evidence, prov=prov)
    evidence["match"] = "unknown"
    return _util.make_fact("F-DOMAIN", "WARN", f"Sender domain {from_domain} is not the vendor domain {ref or '-'}",
                           "DOMAIN UNKNOWN", evidence=evidence, prov=prov)
