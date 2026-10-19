"""AP-Clerk agent: planner (Sonnet, AIRGAP_BEDROCK_MODEL_ID) + quarantined extractor (Qwen, no tools).

CONTRACTS.md v2 §4.5 (tool surface), §9 (AGENT_MODE, AIRGAP_SONNET_BUDGET). Owner: WS-E.
"""
from __future__ import annotations

from typing import Any


def run_agent(task: str, *, mode: str | None = None, model: str | None = None,
              tools_url: str | None = None) -> dict[str, Any]:
    """Run one agent episode against POST /tools/{name}; returns transcript, tool calls and proposals made."""
    raise NotImplementedError("TODO WS-E")


def extract_invoice(doc: bytes, *, model: str | None = None) -> dict[str, Any]:
    """Quarantined extractor: document -> typed InvoiceDraft (JSON schema output, no tools); free text as handles."""
    raise NotImplementedError("TODO WS-E")


def tool_specs() -> list[dict[str, Any]]:
    """Bedrock Converse tool specs generated from executor.tools.manifest.TOOL_MANIFEST."""
    raise NotImplementedError("TODO WS-E")
