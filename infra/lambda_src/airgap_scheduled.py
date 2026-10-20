"""EventBridge Scheduler target (checkpointer role): {"action": "tick"|"anchor", "log_id": "audit"}. Owner: WS-E."""
from __future__ import annotations

from typing import Any

try:  # cold start; checkpoint / witness_refusal leaves get explained lines too
    from executor import oplog

    oplog.configure()
except Exception as _e:  # noqa: BLE001
    print(f"AIRGAP_OPLOG_DISABLED {type(_e).__name__}: {_e}"[:300])


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    from executor.audit import anchor, log
    from executor.config import Settings
    from executor.store import get_store

    settings = Settings.from_env()
    store = get_store(settings)
    log_id = event.get("log_id", "audit")
    if event.get("action") == "anchor":
        return {"anchor": anchor.anchor(log_id, store=store, settings=settings)}
    out = {"checkpoint": log.tick(log_id, store=store, settings=settings)}
    # W2 (litewitness on EC2, via SSM) cosigns every checkpoint not yet W2-cosigned; never raises, catches up later
    from witness import relay_w2

    w2 = relay_w2.after_tick(log_id, store=store, settings=settings)
    if w2 is not None:
        out["w2"] = w2
        if w2.get("error"):
            print(f"W2 relay: {w2['error']}")
            try:  # explained line: ATTACK for a fork / refusal, ERROR otherwise; never fails the tick
                from executor import oplog as _oplog

                _oplog.witness_error("W2", w2["error"])
            except Exception:  # noqa: BLE001
                pass
    return out
