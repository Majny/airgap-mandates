"""F-ATTEST: k/3 distinct pinned issuer classes for the change (executor.attest.vc). CONTRACTS.md v2 §2.1, §11.

k >= 2 -> INFO 'ATT 2/3 ERP BANK'; break-glass -> INFO 'ATT BREAK-GLASS'; off-network -> INFO 'ATT OFF-NETWORK'
(F-CALLBACK carries the BLOCK there); k < 2 otherwise -> BLOCK 'ATT 1/3 ERP' / 'ATT 0/3'. Owner: WS-D.
"""
from __future__ import annotations

from typing import Any

from executor.facts import _util
from executor.models import AttestResult, Fact

LABEL = "Supplier attestations (distinct pinned classes)"
N_CLASSES = 3
REQUIRED = 2
# Fixed display order and short tags (CONTRACTS §11 issuer classes).
_TAGS = (("supplier-erp", "ERP"), ("supplier-bank", "BANK"), ("registry", "REG"))


def ok_classes(results: list[AttestResult] | list[dict[str, Any]]) -> list[str]:
    """Distinct issuer classes among ok results, in the fixed order erp, bank, registry."""
    seen = {r.get("issuer_class") for r in results or [] if r.get("ok")}
    return [cls for cls, _ in _TAGS if cls in seen]


def _line(classes: list[str]) -> str:
    tags = dict(_TAGS)
    line = " ".join([f"ATT {len(classes)}/{N_CLASSES}"] + [tags[c] for c in classes])
    return line if len(line) <= _util.DISPLAY_WIDTH else f"ATT {len(classes)}/{N_CLASSES} ALL"


def attest_fact(change: dict[str, Any], results: list[AttestResult] | list[dict[str, Any]]) -> Fact:
    """change: {in_network, break_glass}. R0: < 2 distinct classes in-network without break-glass is BLOCK.

    Fail closed: only a literal True break_glass and a literal False in_network leave the k-of-3 path; a missing or
    malformed flag (None, "false", ...) is treated as in-network without break-glass."""
    classes = ok_classes(results)
    k = len(classes)
    evidence: dict[str, Any] = {"k": k, "n": N_CLASSES}
    if classes:
        evidence["classes"] = ",".join(classes)
    if change.get("break_glass") is True:
        evidence["break_glass"] = True
        return _util.make_fact("F-ATTEST", "INFO", f"{LABEL}: break-glass", "ATT BREAK-GLASS", evidence=evidence)
    if change.get("in_network") is False:
        evidence["in_network"] = False
        return _util.make_fact("F-ATTEST", "INFO", f"{LABEL}: off-network (callback path)", "ATT OFF-NETWORK",
                               evidence=evidence)
    severity = "INFO" if k >= REQUIRED else "BLOCK"
    return _util.make_fact("F-ATTEST", severity, LABEL, _line(classes), evidence=evidence)
