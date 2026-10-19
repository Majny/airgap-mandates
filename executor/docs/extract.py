"""Documents and deterministic InvoiceDraft extraction (CONTRACTS.md v2 §4.2 invoice_ref, §4.5). Pure, no I/O.

A document is one part of an inbox email: the text body or a text-like attachment (ISDOC XML, SPAYD/QR text, .txt).
doc_id = "doc_" + sha256(part bytes)[:16], so invoice_ref is a provenance hash of exactly what was extracted.

extract_draft() is the deterministic twin of the quarantined extractor (Qwen, no tools; agent/extractor.py): it reads
SPAYD (`SPD*1.0*ACC:...`), ISDOC tags and labelled plain-text fields. Free text never becomes a typed field: the
supplier name and the free-text note are returned only as opaque handles (`txt_<8 hex>`).

Owner: WS-E.
"""
from __future__ import annotations

import email
import email.policy
import hashlib
import re
from typing import Any

TEXT_TYPES = ("text/plain", "text/xml", "application/xml", "application/x-isdoc", "text/x-spayd")


def doc_id_of(data: bytes) -> str:
    return "doc_" + hashlib.sha256(data).hexdigest()[:16]


def handle_of(text: str) -> str:
    return "txt_" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]


def documents(raw: bytes) -> list[dict[str, Any]]:
    """[{doc_id, kind, name, sha256, text}] for the body and text-like attachments of one RFC 822 message."""
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    out: list[dict[str, Any]] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        name = part.get_filename() or ""
        if ctype not in TEXT_TYPES and not name.lower().endswith((".xml", ".isdoc", ".txt", ".spayd")):
            continue
        data = part.get_payload(decode=True)
        if not isinstance(data, bytes):
            data = b""
        text = data.decode(part.get_content_charset() or "utf-8", "replace")
        kind = "body" if not name and part.get_content_disposition() != "attachment" else "attachment"
        out.append({"doc_id": doc_id_of(data), "kind": kind, "name": name, "content_type": ctype,
                    "sha256": hashlib.sha256(data).hexdigest(), "text": text})
    return out


def headers(raw: bytes) -> dict[str, str]:
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    return {k: str(msg.get(k, "")) for k in ("From", "To", "Subject", "Date")}


# ---------------------------------------------------------------- extraction

_SPAYD_RE = re.compile(r"SPD\*1\.0\*[^\s]+")
_ISDOC = {
    "invoice_no": r"<ID>([^<]{1,64})</ID>",
    "issue_date": r"<IssueDate>(\d{4}-\d{2}-\d{2})</IssueDate>",
    "due_date": r"<PaymentDueDate>(\d{4}-\d{2}-\d{2})</PaymentDueDate>",
    "amount": r"<PayableAmount>([0-9]+(?:[.,][0-9]{1,2})?)</PayableAmount>",
    "currency": r"<LocalCurrencyCode>([A-Z]{3})</LocalCurrencyCode>",
    "vs": r"<VariableSymbol>([0-9]{1,10})</VariableSymbol>",
    "iban": r"<IBAN>([A-Z]{2}[0-9]{2}[A-Z0-9 ]{11,40})</IBAN>",
    "ico": r"<AccountingSupplierParty>.*?<ID>([0-9]{8})</ID>",
    "name": r"<AccountingSupplierParty>.*?<Name>([^<]{1,120})</Name>",
}
_TEXT = {
    "invoice_no": r"(?:invoice|faktura|fa[kc]tura [cč].|invoice no\.?|[cč]íslo faktury)\s*(?:no\.?|number|[cč].)?\s*[:#]?\s*([A-Z0-9][A-Z0-9/_-]{1,63})",
    "issue_date": r"(?:issue date|issued|datum vystaven[ií]|vystaveno)\s*:?\s*(\d{4}-\d{2}-\d{2}|\d{1,2}\.\s?\d{1,2}\.\s?\d{4})",
    "due_date": r"(?:due date|due|splatnost|datum splatnosti)\s*:?\s*(\d{4}-\d{2}-\d{2}|\d{1,2}\.\s?\d{1,2}\.\s?\d{4})",
    "amount": r"(?:amount|total|k úhradě|celkem|částka)\s*:?\s*([0-9][0-9 ]*(?:[.,][0-9]{1,2})?)\s*(CZK|EUR|Kč)?",
    "vs": r"(?:VS|variabiln[ií] symbol|variable symbol)\s*:?\s*([0-9]{1,10})\b",
    "iban": r"(?:IBAN)\s*:?\s*([A-Z]{2}[0-9]{2}(?:\s?[A-Z0-9]){11,30})",
    "ico": r"(?:I[CČ]O?|reg\.?\s*no\.?)\s*:?\s*([0-9]{8})\b",
}


def _date(s: str | None) -> str | None:
    if not s:
        return None
    s = s.replace(" ", "")
    m = re.fullmatch(r"(\d{1,2})\.(\d{1,2})\.(\d{4})", s)
    return f"{m.group(3)}-{int(m.group(2)):02d}-{int(m.group(1)):02d}" if m else s


def _minor(s: str | None) -> int | None:
    if not s:
        return None
    s = s.replace(" ", "").replace(",", ".")
    try:
        whole, _, frac = s.partition(".")
        return int(whole) * 100 + int((frac + "00")[:2])
    except ValueError:
        return None


def _spayd(text: str) -> dict[str, Any]:
    m = _SPAYD_RE.search(text)
    if not m:
        return {}
    kv = dict(p.split(":", 1) for p in m.group(0).split("*")[2:] if ":" in p)
    acc = kv.get("ACC", "").split("+")[0]
    dt = kv.get("DT")
    return {"iban": acc or None, "amount": kv.get("AM"), "currency": kv.get("CC"), "vs": kv.get("X-VS"),
            "due_date": f"{dt[:4]}-{dt[4:6]}-{dt[6:8]}" if dt and len(dt) == 8 else None, "note": kv.get("MSG")}


def extract_draft(doc: dict[str, Any]) -> dict[str, Any]:
    """InvoiceDraft {doc_id, sha256, source, fields{...}, handles{...}, missing[]} - typed fields only."""
    text = doc["text"]
    found: dict[str, Any] = {}
    source = "text"
    if "<Invoice" in text and "isdoc" in text.lower():
        source = "isdoc"
        for k, rx in _ISDOC.items():
            m = re.search(rx, text, re.S)
            if m:
                found[k] = m.group(1).strip()
    sp = _spayd(text)
    if sp:
        source = source if source == "isdoc" else "spayd"
        for k, v in sp.items():
            if v and k not in found:
                found[k] = v
    for k, rx in _TEXT.items():
        if k not in found:
            m = re.search(rx, text, re.I)
            if m:
                found[k] = m.group(1).strip()
                if k == "amount" and m.lastindex and m.lastindex >= 2 and m.group(2) and "currency" not in found:
                    found["currency"] = "CZK" if m.group(2) == "Kč" else m.group(2)

    iban = re.sub(r"\s", "", found["iban"]).upper() if found.get("iban") else None
    fields = {
        "invoice_no": found.get("invoice_no"),
        "issue_date": _date(found.get("issue_date")),
        "due_date": _date(found.get("due_date")),
        "amount_minor": _minor(found.get("amount")),
        "currency": (found.get("currency") or "").upper() or None,
        "vs": found.get("vs"),
        "iban": iban,
        "supplier_ico": found.get("ico"),
    }
    if fields["currency"] not in (None, "CZK", "EUR"):
        fields["currency"] = None
    handles = {}
    if found.get("name"):
        handles["supplier_name"] = handle_of(found["name"])
    if found.get("note"):
        handles["note"] = handle_of(found["note"])
    handles["body"] = handle_of(text)
    return {"doc_id": doc["doc_id"], "sha256": doc["sha256"], "source": source, "fields": fields,
            "handles": handles, "missing": sorted(k for k, v in fields.items() if v is None)}


def check_against_document(draft: dict[str, Any], claimed: dict[str, Any], vendor_ico: str | None
                           ) -> list[tuple[str, str]]:
    """[(rule_id, reason)] where `claimed` disagrees with the document. Empty = consistent.

    claimed keys (all optional except amount_minor): amount_minor, reason_code, currency, vs, due (or due_date),
    invoice_no. Rules: T-DOC-MISSING (no machine-readable amount/currency: fail closed); T-AMOUNT-MISMATCH (higher than
    the document, or lower without reason_code PARTIAL); T-DOC-MISMATCH (other field differs, or the document's
    supplier ICO is not the vendor's). Shared by the tools λ (A2) and the facts engine (F-AMOUNT-DOC, A3).
    """
    f = draft["fields"]
    if f["amount_minor"] is None or f["currency"] is None:
        return [("T-DOC-MISSING", "document has no machine-readable amount/currency")]
    out: list[tuple[str, str]] = []
    amount = int(claimed["amount_minor"])
    if amount > f["amount_minor"] or (amount < f["amount_minor"] and claimed.get("reason_code") != "PARTIAL"):
        out.append(("T-AMOUNT-MISMATCH", f"amount {amount} != document {f['amount_minor']}"))
    due = claimed.get("due") or claimed.get("due_date")
    for name, value, field in (("currency", claimed.get("currency"), "currency"), ("vs", claimed.get("vs"), "vs"),
                               ("due", due, "due_date"), ("invoice_no", claimed.get("invoice_no"), "invoice_no")):
        if value and f[field] and str(value) != str(f[field]):
            out.append(("T-DOC-MISMATCH", f"{name} {value!r} != document {f[field]!r}"))
    if f["supplier_ico"] and f["supplier_ico"] != vendor_ico:
        out.append(("T-DOC-MISMATCH", "document supplier ICO is not this vendor"))
    return out
