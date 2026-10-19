"""F-AMOUNT-DOC: the proposed invoice must agree with the document it cites (invoice_ref). CONTRACTS.md v2 §2.1, §4.2
invoice_ref, §4.5.

Owner: WS-D.

The document is resolved by invoice.invoice_ref (doc_<16 hex of sha256(part bytes)>) among the parts of the raw inbox
email, read with WS-E's deterministic extractor (executor.docs.extract) and checked with the same
check_against_document() the tools λ uses (A2), so the agent and the facts engine can never disagree. Any rule it
returns maps to the CONTRACTS §2.1 values: match -> INFO "AMOUNT OK DOC"; partial (lower with reason_code PARTIAL)
-> INFO "AMOUNT PART DOC"; mismatch (T-AMOUNT-MISMATCH / T-DOC-MISMATCH) -> BLOCK "AMOUNT != DOC"; unavailable (no
raw email, an unresolvable invoice_ref, an extraction error or T-DOC-MISSING) -> BLOCK "AMOUNT DOC N/A" (fail
closed). evidence.mismatched = sorted comma-joined field names. prov = sha256 of the document part.
"""
from __future__ import annotations

from typing import Any

from executor.facts import _util
from executor.models import Fact

_OK_LINE = "AMOUNT OK DOC"  # match
_PART_LINE = "AMOUNT PART DOC"  # partial
_BLOCK_LINE = "AMOUNT != DOC"  # mismatch
_NA_LINE = "AMOUNT DOC N/A"  # unavailable


def _field(rule_id: str, reason: str) -> str:
    """Contract field name of one check_against_document() finding."""
    if rule_id == "T-AMOUNT-MISMATCH":
        return "amount"
    if "supplier ICO" in reason:
        return "ico"
    name = reason.split(" ", 1)[0]
    return "due_date" if name == "due" else name


def _claimed(invoice: dict[str, Any]) -> dict[str, Any]:
    return {"amount_minor": invoice["amount_minor"], "reason_code": invoice.get("reason_code"),
            "currency": invoice.get("currency"), "vs": invoice.get("vs"), "due_date": invoice.get("due_date"),
            "invoice_no": invoice.get("invoice_no")}


def _fact(severity: str, label: str, line: str, evidence: dict[str, Any]) -> Fact:
    return _util.make_fact("F-AMOUNT-DOC", severity, label, line, evidence=evidence,
                           prov=evidence["doc_sha256"] or None)


def amount_doc_fact(invoice: dict[str, Any], raw_eml: bytes | None, *, vendor_ico: str) -> Fact:
    """Invoice (proposal_create invoice object) vs the document invoice_ref names inside raw_eml."""
    from executor.docs import extract

    ref = invoice.get("invoice_ref")
    amount = invoice.get("amount_minor")
    evidence: dict[str, Any] = {
        "invoice_amount_minor": amount if isinstance(amount, int) and not isinstance(amount, bool) else None,
        "doc_amount_minor": None, "doc_sha256": None, "invoice_ref": ref if isinstance(ref, str) else None,
        "reason_code": invoice.get("reason_code") if isinstance(invoice.get("reason_code"), str) else None,
        "mismatched": "",
    }
    if not raw_eml:
        return _fact("BLOCK", "No source email for the invoice: amount cannot be checked against a document",
                     _NA_LINE, evidence)
    try:
        doc = next((d for d in extract.documents(raw_eml) if d["doc_id"] == ref), None) if ref else None
        if doc is None:
            return _fact("BLOCK", f"invoice_ref {ref} does not name a document of the source email", _NA_LINE,
                         evidence)
        evidence["doc_sha256"] = doc["sha256"]
        draft = extract.extract_draft(doc)
        doc_amount = draft["fields"]["amount_minor"]
        evidence["doc_amount_minor"] = doc_amount if isinstance(doc_amount, int) else None
        if evidence["invoice_amount_minor"] is None:
            raise ValueError("invoice amount_minor is not an integer")
        found = extract.check_against_document(draft, _claimed(invoice), vendor_ico)
    except Exception as e:  # noqa: BLE001 - any parse/extraction failure fails closed
        return _fact("BLOCK", f"Document could not be checked ({type(e).__name__})", _NA_LINE, evidence)
    if any(rid == "T-DOC-MISSING" for rid, _ in found):
        return _fact("BLOCK", "Document has no machine-readable amount/currency", _NA_LINE, evidence)
    if found:
        evidence["mismatched"] = ",".join(sorted({_field(rid, reason) for rid, reason in found}))
        reasons = "; ".join(reason for _, reason in found)
        return _fact("BLOCK", f"Invoice disagrees with the document: {reasons}"[:300], _BLOCK_LINE, evidence)
    if amount < doc_amount:
        return _fact("INFO", f"Partial payment {amount} of document {ref} ({doc_amount})", _PART_LINE, evidence)
    return _fact("INFO", f"Amount {amount} agrees with document {ref}", _OK_LINE, evidence)
