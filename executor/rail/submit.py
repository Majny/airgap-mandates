"""Rail submission after commit; idempotency key = tx_id; rail_submitted leaf. CONTRACTS.md v2 §3.2. Owner: WS-A."""
from __future__ import annotations

from typing import Any


def submit(tx: dict[str, Any], *, store: Any, settings: Any) -> dict[str, Any]:
    """Write pain.001, submit (mock or TSYS), append rail_submitted leaf; returns {status, xml_c14n_sha256}."""
    raise NotImplementedError("TODO WS-A")


def recover_unsubmitted(*, store: Any, settings: Any) -> list[str]:
    """Re-submit executions that have no rail_submitted leaf (crash recovery); returns tx_ids."""
    raise NotImplementedError("TODO WS-A")
