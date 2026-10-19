"""F-WARNLIST: payee name / domains vs MostlyRight regulator warning lists. CONTRACTS.md v2 §2.1.

record_type 'warning' rows (amf_blacklists, esma_non_compliant_casps, any other warning list): near-exact name match
(rapidfuzz token_sort_ratio >= 95 on legal-form-stripped names AND the same first token) or the payee domain (or a
parent of it) listed as website_domain / email_domain; malformed (record_ok = 0) warning rows match too. Hit -> BLOCK
'WARNLIST HIT', else INFO 'WARNLIST CLEAR'; prov = MostlyRight snapshot sha256. Missing snapshot, or one with
unclassifiable rows -> WARN 'WARNLIST N/A' (never CLEAR without data). Owner: WS-D.
"""
from __future__ import annotations

import os
from typing import Any

from executor.facts import _util
from executor.facts import mostlyright as mr
from executor.models import Fact

LABEL = "Regulator warning lists (MostlyRight)"


def clean(v: Any) -> Any:
    """Evidence strings without control characters (the source carries some)."""
    if isinstance(v, str):
        return " ".join("".join(c if c.isprintable() else " " for c in v).split())
    return v


def warnlist_fact(name: str, domains: list[str], *, mr_path: str | os.PathLike[str] | None) -> Fact:
    doms = sorted({d for d in (mr.norm_domain(x) for x in domains or []) if d})
    evidence: dict[str, Any] = {"name": name, "domains": doms}
    if not mr.exists(mr_path):
        evidence["snapshot"] = "missing"
        return _util.make_fact("F-WARNLIST", "WARN", f"{LABEL}: snapshot missing, not checked", "WARNLIST N/A",
                               evidence=evidence)
    sha = mr.snapshot_sha(mr_path)
    hit = mr.warning_name_hit(name, mr_path=mr_path)
    for d in doms:
        if hit is not None:
            break
        hit = mr.warning_domain_hit(d, mr_path=mr_path)
    if hit is None and mr.unclassified_rows(mr_path):
        evidence["snapshot"] = "partial"
        return _util.make_fact("F-WARNLIST", "WARN", f"{LABEL}: snapshot has unreadable rows, not fully checked",
                               "WARNLIST N/A", evidence=evidence, prov=sha)
    if hit is None:
        return _util.make_fact("F-WARNLIST", "INFO", f"{LABEL}: no name or domain match", "WARNLIST CLEAR",
                               evidence=evidence, prov=sha)
    evidence["hit"] = {k: clean(v) for k, v in hit.items()}
    what = f"domain {hit['domain']}" if hit["match"] == "domain" else f"name ~ {clean(hit['listed_name'])}"
    return _util.make_fact("F-WARNLIST", "BLOCK", f"{LABEL}: {what} ({hit['source_list']})", "WARNLIST HIT",
                           evidence=evidence, prov=sha)
