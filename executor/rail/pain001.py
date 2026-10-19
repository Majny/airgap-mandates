"""pain.001.001.09 credit-transfer XML for one execution + C14N SHA-256. CONTRACTS.md v2 §3.2, §4.1 #23. Owner: WS-A."""
from __future__ import annotations

from typing import Any


def build_pain001(tx: dict[str, Any], *, debtor: dict[str, Any], msg_id: str) -> tuple[str, str]:
    """Return (xml, xml_c14n_sha256) for one ledger tx (end-to-end id = tx_id)."""
    raise NotImplementedError("TODO WS-A")
