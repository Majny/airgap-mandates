"""F-BANK: bank from IBAN (data/bank_codes.json). CONTRACTS.md v2 §2.1.

Domestic -> INFO 'BANK DOMESTIC'; foreign or EMI for a CZ vendor -> WARN 'BANK FOREIGN EMI'. A bank code missing
from the snapshot cannot be ruled out as an EMI ("absent != safe") and is WARN 'BANK FOREIGN EMI' too. Owner: WS-D.
Bank names stay in the label (UI only); the device line never carries a bank brand.
"""
from __future__ import annotations

import os

from executor.facts import _util
from executor.facts.vop import bank_code, norm_iban
from executor.models import Fact

LABEL = "Bank from IBAN"


def bank_fact(iban: str, vendor_country: str, *, bank_codes_path: str | os.PathLike[str]) -> Fact:
    """INFO when the IBAN is a bank in the vendor's own country, else WARN; prov = bank_codes sha256."""
    codes, sha = _util.load_json(bank_codes_path)
    s = norm_iban(iban)
    cc, code = s[:2], bank_code(s)
    entry = (codes.get(cc) or {}).get(code) if code else None
    kind = entry.get("kind") if isinstance(entry, dict) else None
    domestic = cc == str(vendor_country or "").upper() and kind == "bank"
    evidence = {"country": cc, "bank_code": code, "vendor_country": vendor_country, "found": entry is not None,
                "kind": kind}
    name = (entry.get("name") if isinstance(entry, dict) else None) or "unknown bank code"
    if domestic:
        return _util.make_fact("F-BANK", "INFO", f"{LABEL}: {name}", "BANK DOMESTIC", evidence=evidence, prov=sha)
    why = "foreign or EMI" if entry is not None else "not in bank-code list, EMI not ruled out"
    return _util.make_fact("F-BANK", "WARN", f"{LABEL}: {name} ({why})", "BANK FOREIGN EMI",
                           evidence=evidence, prov=sha)
