"""AP agent on Bedrock Converse (AIRGAP_BEDROCK_MODEL_ID) / Qwen; tools call the executor only. CONTRACTS.md §4, §9.

Owner: WS-C.
"""
from __future__ import annotations

from typing import Any


def run_agent(task: str, *, model: str | None = None, executor_url: str | None = None) -> dict[str, Any]:
    """Run one agent episode; returns transcript + proposals made."""
    raise NotImplementedError("TODO WS-C")


def tool_specs() -> list[dict[str, Any]]:
    """Tool definitions: read_inbox, read_email, propose_payment, request_payee_change, send_email (via egress)."""
    raise NotImplementedError("TODO WS-C")
