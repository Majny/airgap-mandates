"""Rail submission after commit; idempotency key = tx_id; rail_submitted leaf. CONTRACTS.md v2 §3.2. Owner: WS-A.

Mock rail; TSYS only if writes are confirmed. The mock accepts (ACTC) the first submission of a tx and answers DUPL
to every resubmission (exactly-once demo); each submission is recorded as a `rail_submitted` audit leaf.
"""
from __future__ import annotations

import json
from typing import Any

from executor.errors import ApiError, ErrorCode
from executor.rail.pain001 import DEBTOR, FORMAT, build_pain001
from executor.store import shims

ACCEPTED = ("ACTC", "ACSC")


def msg_id_for(tx_id: str) -> str:
    return "AG1-" + tx_id


def _with_creditor(row: dict[str, Any], store: Any) -> dict[str, Any]:
    """Ledger row + creditor_name from the registry (pain.001 only; the ledger schema has no name)."""
    if row.get("creditor_name"):
        return row
    vendor = store.get("registry", {"vendor_id": row["vendor_id"]})
    return {**row, "creditor_name": vendor["name"]} if vendor and vendor.get("name") else row


def submit(tx: dict[str, Any], *, store: Any, settings: Any) -> dict[str, Any]:
    """Write pain.001, submit to the mock rail (TSYS only if writes are confirmed), append rail_submitted leaf.

    Returns {status, xml_c14n_sha256, msg_id}; status ACTC on first acceptance, DUPL on resubmission."""
    tx_id = tx["tx_id"]
    row = store.get("ledger", {"tx_id": tx_id}) or tx
    msg_id = msg_id_for(tx_id)
    _, h = build_pain001(_with_creditor(row, store), debtor=DEBTOR, msg_id=msg_id)
    prev_rail = row.get("rail") or {"status": "PENDING", "xml_c14n_sha256": None}
    status = "DUPL"
    if prev_rail.get("status") not in ACCEPTED:
        new_rail = {"status": "ACTC", "xml_c14n_sha256": h}
        if store.update_if("ledger", {"tx_id": tx_id}, {"rail": new_rail}, {"rail": prev_rail}):
            status = "ACTC"
    shims.append(shims.make_event("rail_submitted", {"tx_id": tx_id, "format": FORMAT, "msg_id": msg_id,
                                                     "xml_c14n_sha256": h, "status": status},
                                  subject_id=tx_id, actor="rail", settings=settings),
                 store=store, settings=settings)
    return {"status": status, "xml_c14n_sha256": h, "msg_id": msg_id}


def submitted_tx_ids(*, store: Any) -> set[str]:
    """tx_ids that already have a rail_submitted leaf (any log)."""
    out: set[str] = set()
    for item in store.scan("audit"):
        raw = item.get("event")
        if not raw:
            continue
        ev = json.loads(raw)
        if ev.get("type") == "rail_submitted":
            out.add(ev["data"]["tx_id"])
    return out


def recover_unsubmitted(*, store: Any, settings: Any) -> list[str]:
    """Re-submit executions that have no rail_submitted leaf (crash recovery); returns tx_ids."""
    done = submitted_tx_ids(store=store)
    pending = sorted((r for r in store.scan("ledger")
                      if (r.get("rail") or {}).get("status") == "PENDING" and r["tx_id"] not in done),
                     key=lambda r: (r.get("seq", 0), r["tx_id"]))
    for row in pending:
        submit(row, store=store, settings=settings)
    return [r["tx_id"] for r in pending]


def pain001_export(tx_id: str, *, store: Any, settings: Any) -> dict[str, Any]:
    """GET /export/pain001/{tx_id} body (pain001.response): {tx_id, msg_id, xml, xml_c14n_sha256}."""
    row = store.get("ledger", {"tx_id": tx_id})
    if row is None:
        raise ApiError(ErrorCode.NOT_FOUND, f"no ledger row {tx_id}")
    msg_id = msg_id_for(tx_id)
    xml, h = build_pain001(_with_creditor(row, store), debtor=DEBTOR, msg_id=msg_id)
    return {"tx_id": tx_id, "msg_id": msg_id, "xml": xml, "xml_c14n_sha256": h}
