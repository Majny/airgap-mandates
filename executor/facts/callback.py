"""F-CALLBACK: out-of-band callback to the registered contact (vendor portal). CONTRACTS.md v2 §2.1, §6.1.

confirmed -> INFO 'CALLBACK OK'; anything else (none/pending/denied) -> BLOCK 'CALLBACK MISSING'. Owner: WS-D.
compute() adds it only for off-network or break-glass changes.
"""
from __future__ import annotations

from typing import Any

from executor.facts import _util
from executor.models import Fact

LABEL = "Callback to registered contact"


def callback_fact(change: dict[str, Any]) -> Fact:
    status = str(((change or {}).get("callback") or {}).get("status") or "none")
    if status == "confirmed":
        return _util.make_fact("F-CALLBACK", "INFO", LABEL, "CALLBACK OK", evidence={"status": status})
    return _util.make_fact("F-CALLBACK", "BLOCK", LABEL, "CALLBACK MISSING", evidence={"status": status})
