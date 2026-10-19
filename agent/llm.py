"""Bedrock Converse client + Sonnet request budget. Owner: WS-E.

AIRGAP_SONNET_BUDGET is requests/min; the limiter is a per-process sliding window (the agent role has no DynamoDB
access, so a shared counter is not possible from inside the agent; WS-F's bench keeps its own share well below 50).
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any

_lock = threading.Lock()
_client: Any = None
_times: list[float] = []


def client() -> Any:
    global _client
    with _lock:
        if _client is None:
            import boto3
            from botocore.config import Config

            _client = boto3.client("bedrock-runtime", region_name=os.environ.get("AWS_REGION", "eu-central-1"),
                                   config=Config(retries={"max_attempts": 8, "mode": "adaptive"}, read_timeout=120))
        return _client


def gate(model: str, budget: int | None = None, *, clock: Any = time.time, sleep: Any = time.sleep) -> None:
    """Block until a request to `model` fits in the per-minute budget (Anthropic models only)."""
    if "anthropic" not in model:
        return
    budget = budget or int(os.environ.get("AIRGAP_SONNET_BUDGET", "50"))
    while True:
        with _lock:
            now = clock()
            _times[:] = [t for t in _times if now - t < 60]
            if len(_times) < budget:
                _times.append(now)
                return
            wait = 60 - (now - _times[0]) + 0.05
        sleep(wait)


def converse(model: str, *, bedrock: Any = None, **kw: Any) -> dict[str, Any]:
    gate(model)
    return (bedrock or client()).converse(modelId=model, **kw)
