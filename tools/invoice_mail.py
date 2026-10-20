"""Source emails for demo/test invoices: a DKIM-signed invoice email (ISDOC attachment) for any invoice, so every
proposal can cite a real, provenance-hashed document ("no source document, no autopay", F-AMOUNT-DOC / F-DKIM).
CONTRACTS.md v2 §2.1, §4.1 #26 (POST /ingest). Owner: WS-D.

SIMULATED: fictitious vendors from data/vendors.json, signed with the DEMO-ONLY keys in data/dkim_keys (the same keys
data/dns_snapshot.json publishes), deterministic bytes per invoice. Used by demo scenes, e2e drivers and tests:

    raw = invoice_email(invoice)                       # invoice: proposal_create invoice object (vendor_id, ...)
    st, r = call("POST", "/ingest", ingest_body(raw), "ingest")
    invoice = cite(invoice, raw, r["email_id"])         # + email_id and invoice_ref = the attachment doc_id
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
from typing import Any

from tools.gen_emails import BUYER, SELECTOR, _sign

_VENDOR_CACHE: dict[str, dict[str, dict[str, Any]]] = {}


def _vendor(vendor_id: str, data_dir: str | Path) -> dict[str, Any]:
    key = str(Path(data_dir).resolve())
    if key not in _VENDOR_CACHE:
        rows = json.loads((Path(data_dir) / "vendors.json").read_text())
        _VENDOR_CACHE[key] = {v["vendor_id"]: v for v in rows}
    return _VENDOR_CACHE[key][vendor_id]


def _isdoc(inv: dict[str, Any], vendor: dict[str, Any]) -> str:
    minor = int(inv["amount_minor"])
    due = f"  <DueDate>{inv['due_date']}</DueDate>\n" if inv.get("due_date") else ""
    vs = f"<VariableSymbol>{inv['vs']}</VariableSymbol>" if inv.get("vs") else ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Invoice xmlns="http://isdoc.cz/namespace/2013" version="6.0.2">\n'
        "  <!-- ISDOC-like FICTITIOUS demo invoice (AirGap Mandates, tools/invoice_mail.py) -->\n"
        f"  <ID>{inv['invoice_no']}</ID>\n"
        f"  <IssueDate>{inv['issue_date']}</IssueDate>\n"
        f"{due}"
        f"  <Supplier><Name>{vendor['name']}</Name><ICO>{vendor['ico']}</ICO></Supplier>\n"
        f"  <PayableAmount currency=\"{inv.get('currency', 'CZK')}\">{minor // 100}.{minor % 100:02d}</PayableAmount>\n"
        f"  <Payment><IBAN>{vendor['iban']}</IBAN>{vs}</Payment>\n"
        "</Invoice>\n"
    )


def invoice_email(invoice: dict[str, Any], *, data_dir: str | Path = "data", sender: str = "fakturace") -> bytes:
    """DKIM-signed RFC 822 invoice email from the vendor's registered domain carrying `invoice` as an ISDOC
    attachment. Deterministic for a given invoice (Date = issue_date 08:00 UTC)."""
    vendor = _vendor(invoice["vendor_id"], data_dir)
    domain = vendor["domain"]
    date_iso = f"{invoice['issue_date']}T08:00:00Z"
    dt = datetime.fromisoformat(date_iso.replace("Z", "+00:00")).astimezone(timezone.utc)
    safe_no = "".join(c if c.isalnum() else "-" for c in str(invoice["invoice_no"]))
    boundary = f"=_airgap_inv_{safe_no}"
    minor = int(invoice["amount_minor"])
    body = (f"Dear colleagues,\n\nplease find attached invoice {invoice['invoice_no']}.\n\n"
            f"Amount: {invoice.get('currency', 'CZK')} {minor // 100}.{minor % 100:02d}\n"
            f"Kind regards,\n{vendor['name']}\n")
    headers = [
        f"From: {vendor['name']} <{sender}@{domain}>",
        f"To: {BUYER}",
        f"Subject: Invoice {invoice['invoice_no']}",
        f"Date: {format_datetime(dt)}",
        f"Message-ID: <inv-{safe_no}.{invoice['issue_date'].replace('-', '')}@{domain}>",
        "MIME-Version: 1.0",
        "X-AirGap-Fixture: synthetic; scenario=invoice",
        f"Content-Type: multipart/mixed; boundary=\"{boundary}\"",
    ]
    parts = [f"Content-Type: text/plain; charset=us-ascii\nContent-Transfer-Encoding: 7bit\n\n{body}",
             f"Content-Type: application/xml; name=\"{safe_no}.isdoc\"\n"
             f"Content-Disposition: attachment; filename=\"{safe_no}.isdoc\"\nContent-Transfer-Encoding: 7bit\n\n"
             f"{_isdoc(invoice, vendor)}"]
    raw = ("\n".join(headers) + "\n\n" + "".join(f"--{boundary}\n{p}\n" for p in parts)
           + f"--{boundary}--\n").encode("ascii")
    pem = (Path(data_dir) / "dkim_keys" / f"{domain}.{SELECTOR}.pem").read_bytes()
    return _sign(raw, domain, pem, date_iso)


def ingest_body(raw: bytes, received_at: str | None = None) -> dict[str, Any]:
    """POST /ingest request body (received_at is honoured only off AWS)."""
    body: dict[str, Any] = {"raw_b64": base64.b64encode(raw).decode("ascii")}
    if received_at:
        body["received_at"] = received_at
    return body


def attachment_doc_id(raw: bytes) -> str:
    """doc_id of the invoice attachment, as executor.docs.extract.documents() names it."""
    from executor.docs import extract

    return next(d for d in extract.documents(raw) if d["kind"] == "attachment")["doc_id"]


def cite(invoice: dict[str, Any], raw: bytes, email_id: str) -> dict[str, Any]:
    """The invoice citing its source email and document: + email_id, invoice_ref = attachment doc_id."""
    return {**invoice, "email_id": email_id, "invoice_ref": attachment_doc_id(raw)}


def new_invoice(vendor_id: str, amount_minor: int, *, invoice_no: str | None = None, due_date: str | None = None,
                now: datetime | None = None) -> dict[str, Any]:
    """A NEW legitimate invoice from a registered vendor, issued today: a fresh invoice number (INV-<MMDDHHMMSS>) and
    the caller's amount keep it clear of the duplicate check. Due today unless `due_date` (YYYY-MM-DD) says otherwise."""
    now = now or datetime.now(timezone.utc)
    return {"vendor_id": vendor_id, "invoice_no": invoice_no or f"INV-{now:%m%d%H%M%S}",
            "issue_date": f"{now:%Y-%m-%d}", "due_date": due_date or f"{now:%Y-%m-%d}",
            "amount_minor": int(amount_minor), "currency": "CZK", "reason_code": "DUE"}


def send_and_propose(call: Any, invoice: dict[str, Any], *, data_dir: str | Path | None = None,
                     agent: Any = None) -> tuple[int, Any]:
    """The one path for a new legitimate invoice: its DKIM-signed email is ingested (POST /ingest as "ingest"), then
    the bank's agent proposes it. Default agent step is scripted: POST /proposals as "tools" with the cited invoice
    (the path the agent uses). `agent(cited_invoice) -> (status, response)` replaces that step (e.g. the real agent
    Lambda on AWS). Returns the proposal response: (201, {"proposal", "decision", "tx"?}) or an error."""
    from executor import e2e

    cited = e2e.cite(call, invoice, data_dir=data_dir) if data_dir else e2e.cite(call, invoice)
    if agent is not None:
        return agent(cited)
    return call("POST", "/proposals", {"invoice": cited, "hints": []}, "tools")
