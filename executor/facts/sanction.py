"""F-SANCTION: payee vs MostlyRight EU financial sanctions (entities). CONTRACTS.md v2 §2.1.

record_type 'sanction' rows (eu_financial_sanctions): national id == ICO, or name / alias match (rapidfuzz
token_sort_ratio >= 92 on legal-form-stripped names; length guard: names under 10 chars must match exactly
(>= 5 chars), longer ones within 85 % length).
Malformed (record_ok = 0) sanction rows match too. Hit -> BLOCK 'EU SANCTION HIT', else INFO 'SANCTIONS CLEAR';
prov = MostlyRight snapshot sha256. Missing snapshot, or one with unclassifiable rows -> WARN 'SANCTIONS N/A' (never
CLEAR without data). Owner: WS-D.
"""
from __future__ import annotations

import os
from typing import Any

from executor.facts import _util
from executor.facts import mostlyright as mr
from executor.facts.warnlist import clean
from executor.models import Fact

LABEL = "EU financial sanctions, entities (MostlyRight)"


def sanction_fact(name: str, ico: str, *, mr_path: str | os.PathLike[str] | None) -> Fact:
    evidence: dict[str, Any] = {"name": name, "ico": ico}
    if not mr.exists(mr_path):
        evidence["snapshot"] = "missing"
        return _util.make_fact("F-SANCTION", "WARN", f"{LABEL}: snapshot missing, not checked", "SANCTIONS N/A",
                               evidence=evidence)
    sha = mr.snapshot_sha(mr_path)
    hit = mr.sanction_hit(name, ico, mr_path=mr_path)
    if hit is None and mr.unclassified_rows(mr_path):
        evidence["snapshot"] = "partial"
        return _util.make_fact("F-SANCTION", "WARN", f"{LABEL}: snapshot has unreadable rows, not fully checked",
                               "SANCTIONS N/A", evidence=evidence, prov=sha)
    if hit is None:
        return _util.make_fact("F-SANCTION", "INFO", f"{LABEL}: no match", "SANCTIONS CLEAR", evidence=evidence,
                               prov=sha)
    evidence["hit"] = {k: clean(v) for k, v in hit.items()}
    return _util.make_fact("F-SANCTION", "BLOCK", f"{LABEL}: {clean(hit['listed_name'])} ({hit['match']})",
                           "EU SANCTION HIT", evidence=evidence, prov=sha)
