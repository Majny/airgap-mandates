"""pain.001.001.09 credit-transfer XML for one execution + C14N SHA-256. CONTRACTS.md v2 §3.2, §4.1 #23. Owner: WS-A.

Deterministic: the same ledger tx + msg_id always yields the same bytes and hash (no wall-clock, no randomness).
"""
from __future__ import annotations

import hashlib
from typing import Any

from lxml import etree

NS = "urn:iso:std:iso:20022:tech:xsd:pain.001.001.09"
FORMAT = "pain.001.001.09"

# Fictitious demo debtor (mod-97-valid CZ IBAN, bank code 0100). Not a real account.
DEBTOR: dict[str, str] = {"name": "AIRGAP DEMO TREASURY S.R.O.", "iban": "CZ2201000000002000145399"}


def format_amount(amount_minor: int) -> str:
    """Minor units -> 'units.cc' string without floats."""
    amount_minor = int(amount_minor)
    sign = "-" if amount_minor < 0 else ""
    a = abs(amount_minor)
    return f"{sign}{a // 100}.{a % 100:02d}"


def _sub(parent: etree._Element, tag: str, text: str | None = None, **attrib: str) -> etree._Element:
    el = etree.SubElement(parent, f"{{{NS}}}{tag}", attrib)
    if text is not None:
        el.text = text
    return el


def _path(parent: etree._Element, *tags: str, text: str | None = None) -> etree._Element:
    el = parent
    for t in tags:
        el = _sub(el, t)
    if text is not None:
        el.text = text
    return el


def build_pain001(tx: dict[str, Any], *, debtor: dict[str, Any], msg_id: str) -> tuple[str, str]:
    """Return (xml, xml_c14n_sha256) for one ledger tx (end-to-end id = tx_id)."""
    amount = format_amount(tx["amount_minor"])
    executed_at = str(tx["executed_at"])
    root = etree.Element(f"{{{NS}}}Document", nsmap={None: NS})
    init = _sub(root, "CstmrCdtTrfInitn")

    hdr = _sub(init, "GrpHdr")
    _sub(hdr, "MsgId", msg_id)
    _sub(hdr, "CreDtTm", executed_at)
    _sub(hdr, "NbOfTxs", "1")
    _sub(hdr, "CtrlSum", amount)
    _path(hdr, "InitgPty", "Nm", text=debtor["name"])

    pmt = _sub(init, "PmtInf")
    _sub(pmt, "PmtInfId", tx["tx_id"])
    _sub(pmt, "PmtMtd", "TRF")
    _sub(pmt, "NbOfTxs", "1")
    _sub(pmt, "CtrlSum", amount)
    _path(pmt, "ReqdExctnDt", "Dt", text=executed_at[:10])
    _path(pmt, "Dbtr", "Nm", text=debtor["name"])
    _path(pmt, "DbtrAcct", "Id", "IBAN", text=debtor["iban"])
    _path(pmt, "DbtrAgt", "FinInstnId", "Othr", "Id", text="NOTPROVIDED")

    cti = _sub(pmt, "CdtTrfTxInf")
    _path(cti, "PmtId", "EndToEndId", text=tx["tx_id"])
    _sub(_sub(cti, "Amt"), "InstdAmt", amount, Ccy=tx["currency"])
    _path(cti, "Cdtr", "Nm", text=str(tx.get("creditor_name") or tx["vendor_id"]))
    _path(cti, "CdtrAcct", "Id", "IBAN", text=tx["iban"])
    rmt = _sub(cti, "RmtInf")
    if tx.get("vs"):
        _path(rmt, "Strd", "CdtrRefInf", "Ref", text=str(tx["vs"]))
    else:
        _sub(rmt, "Ustrd", tx["tx_id"])

    xml = etree.tostring(root, xml_declaration=True, encoding="UTF-8", pretty_print=True).decode("utf-8")
    c14n = etree.tostring(root, method="c14n")
    return xml, hashlib.sha256(c14n).hexdigest()
