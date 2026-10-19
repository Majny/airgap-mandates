"""Self-contained receipt (tlog-proof style), shown as QR. CONTRACTS.md v2 §7.4. Owner: WS-B."""
from __future__ import annotations

from typing import Any


def receipt(tx_id: str, *, store: Any, settings: Any) -> dict[str, Any]:
    """{tx, entry, seq, leaf_hash, tree_size, inclusion_proof, checkpoint_note, key_ids, vkeys}."""
    raise NotImplementedError("TODO WS-B")


def verify_receipt(receipt: dict[str, Any]) -> bool:
    """Offline: leaf hash, inclusion proof against the note root, note signatures."""
    raise NotImplementedError("TODO WS-B")
