"""Tools λ handler (POST /tools/{name}). CONTRACTS.md v2 §4.1 #18, §4.5. Owner: WS-E."""
from __future__ import annotations

from typing import Any


def call_tool(name: str, request: dict[str, Any], *, store: Any, settings: Any) -> dict[str, Any]:
    """Check manifest hash, evaluate the Cedar tool policy (A2), log a tool_call leaf, call the executor
    with the tools role (no token passthrough), mask IBANs to '..<last4>' in vendor.lookup results."""
    raise NotImplementedError("TODO WS-E")
