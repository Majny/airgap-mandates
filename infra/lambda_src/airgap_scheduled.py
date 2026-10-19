"""EventBridge Scheduler target (checkpointer role): {"action": "tick"|"anchor", "log_id": "audit"}. Owner: WS-E."""
from __future__ import annotations

from typing import Any


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    from executor.audit import anchor, log
    from executor.config import Settings
    from executor.store import get_store

    settings = Settings.from_env()
    store = get_store(settings)
    log_id = event.get("log_id", "audit")
    if event.get("action") == "anchor":
        return {"anchor": anchor.anchor(log_id, store=store, settings=settings)}
    return {"checkpoint": log.tick(log_id, store=store, settings=settings)}
