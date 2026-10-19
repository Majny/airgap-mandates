"""F-PSP: payee PSP in the MostlyRight SEPA Instant / VoP participant lists and licence registers. CONTRACTS.md v2 §2.1.

IBAN -> bank code (executor.render.BANK_CODE_LEN) -> data/bank_codes.json entry -> BIC -> MostlyRight rows by the
first 8 BIC characters (epc_scheme_registers payment_scheme rows carry in_sct_inst / in_vop / vop_status; licence
rows prove a licence). A `national_id` key on the bank_codes entry, if present, also matches licence rows (CNB
registers carry the ICO, not the BIC).
In SCT Inst + in VoP ("Ready for operations", ready dates not after and leaving dates after the snapshot date; with
no snapshot date a dated entry does not count) -> INFO 'PSP INST VOP OK';
listed but not (yet) both -> WARN 'PSP NO VOP'; absent -> WARN 'PSP UNKNOWN' ("absent != safe": the EBA PI/EMI
register and LT lists are not covered). prov = MostlyRight snapshot sha256. Owner: WS-D.
"""
from __future__ import annotations

import os
from typing import Any

from executor.facts import _util
from executor.facts import mostlyright as mr
from executor.facts.vop import bank_code, norm_iban
from executor.models import Fact

LABEL = "Payee PSP in SEPA Inst / VoP / licence lists"


def _flag(v: Any) -> bool:
    return str(v or "").strip().lower() in ("true", "1", "yes", "y")


def _in_force(ready: str, leaving: str, as_of: str) -> bool:
    """Ready date not after and leaving date (if any) after the snapshot date (ISO strings compare as dates). Without a
    snapshot date neither can be checked, so a dated entry does not count (fail toward WARN)."""
    if not as_of:
        return not ready and not leaving
    return (not ready or ready <= as_of) and (not leaving or leaving > as_of)


def _scheme_state(rows: list[dict[str, Any]], as_of: str) -> tuple[bool, bool]:
    """(in SCT Inst, in VoP) over all payment_scheme rows of the PSP."""
    inst = vop = False
    for r in rows:
        if r["record_type"] != "payment_scheme":
            continue
        inst |= _flag(r["in_sct_inst"]) and _in_force(r["sct_inst_ready_since"], r["sct_inst_leaving_date"], as_of)
        ready = r["vop_status"] == "" or r["vop_status"].lower().startswith("ready")
        vop |= _flag(r["in_vop"]) and ready and _in_force(r["vop_ready_since"], r["vop_leaving_date"], as_of)
    return inst, vop


def _licensed(rows: list[dict[str, Any]], as_of: str) -> bool:
    """A licence row whose `until` (if any) is after the snapshot date."""
    return any(r["record_type"] == "licence" and _in_force("", r["until"], as_of) for r in rows)


def psp_fact(iban: str, *, mr_path: str | os.PathLike[str] | None,
             bank_codes_path: str | os.PathLike[str]) -> Fact:
    """F-PSP for the payee IBAN; prov = MostlyRight snapshot sha256 (absent snapshot -> PSP UNKNOWN, no prov)."""
    s = norm_iban(iban)
    cc, code = s[:2], bank_code(s)
    codes, _ = _util.load_json(bank_codes_path)
    entry = (codes.get(cc) or {}).get(code) if code else None
    entry = entry if isinstance(entry, dict) else {}
    bic = str(entry.get("bic") or "").upper() or None
    evidence: dict[str, Any] = {"bank_code": code, "country": cc, "found": False, "bic8": bic[:8] if bic else None}
    if not mr.exists(mr_path):
        evidence["snapshot"] = "missing"
        return _util.make_fact("F-PSP", "WARN", f"{LABEL}: MostlyRight snapshot missing", "PSP UNKNOWN",
                               evidence=evidence)
    sha = mr.snapshot_sha(mr_path)
    rows = mr.psp_rows(mr_path, bic=bic, national_id=entry.get("national_id"))
    as_of = mr.meta(mr_path).get("as_of", "")
    inst, vop = _scheme_state(rows, as_of)
    licensed = _licensed(rows, as_of)
    scheme = any(r["record_type"] == "payment_scheme" for r in rows)
    evidence.update(found=bool(rows), licensed=licensed, scheme_listed=scheme, in_sct_inst=inst, in_vop=vop,
                    lists=sorted({r["source_list"] for r in rows}), record_ids=sorted({r["record_id"] for r in rows}))
    if not rows:
        return _util.make_fact("F-PSP", "WARN", f"{LABEL}: bank code {code} {cc} not listed (absent != safe)",
                               "PSP UNKNOWN", evidence=evidence, prov=sha)
    if inst and vop:
        return _util.make_fact("F-PSP", "INFO", f"{LABEL}: bank code {code} {cc} in SCT Inst and VoP",
                               "PSP INST VOP OK", evidence=evidence, prov=sha)
    what = "in SCT Inst, not in VoP" if inst else ("in VoP, not in SCT Inst" if vop else "not in SCT Inst / VoP")
    return _util.make_fact("F-PSP", "WARN", f"{LABEL}: bank code {code} {cc} listed, {what}", "PSP NO VOP",
                           evidence=evidence, prov=sha)
