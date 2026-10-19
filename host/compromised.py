"""COMPROMISED switch: the UI lies (e.g. 'ACME OK, VoP OK'); never touches executor data. CONTRACTS.md §1.

Owner: WS-F. Attacker level H1 (ARCHITECTURE §11). The lie is applied to the host's *view model* only: what the
host shows a human. It cannot change what the executor stores, renders or signs.
"""
from __future__ import annotations

import copy
import os
import threading
from typing import Any

_lock = threading.Lock()
_state = {"on": os.environ.get("AIRGAP_COMPROMISED", "0") == "1"}


def is_compromised() -> bool:
    """Current switch state."""
    with _lock:
        return _state["on"]


def set_compromised(on: bool) -> None:
    with _lock:
        _state["on"] = bool(on)


def lie(view: dict[str, Any]) -> dict[str, Any]:
    """Rewrite a view model the way an attacker-controlled UI would.

    The attacker wants the human to approve: it shows the vendor master IBAN instead of the attacker's, the
    invoice amount the human expects, and green facts. Keys: kind, vendor_id, vendor_name, iban, registry_iban,
    amount_minor, expected_amount_minor, facts[{id, severity, display_line}], sender.
    """
    out = copy.deepcopy(view)
    if out.get("registry_iban"):
        out["iban"] = out["registry_iban"]
    if out.get("expected_amount_minor") is not None:
        out["amount_minor"] = out["expected_amount_minor"]
    if out.get("vendor_domain"):
        out["sender"] = f"fakturace@{out['vendor_domain']}"
    out["facts"] = [{"id": f.get("id", "F-?"), "severity": "INFO",
                     "display_line": _green(f.get("id", ""))} for f in out.get("facts", [])]
    out["banner"] = f"{(out.get('vendor_name') or 'VENDOR').upper()} OK, VoP OK"
    return out


def _green(fact_id: str) -> str:
    return {"F-DOMAIN": "DOMAIN MATCH", "F-DKIM": "DKIM PASS", "F-VOP": "VOP MTCH", "F-PSP": "PSP INST VOP OK",
            "F-ATTEST": "ATT 3/3", "F-BANK": "BANK DOMESTIC", "F-FIRSTSEEN": "IBAN SEEN 400D"}.get(fact_id, "OK")
