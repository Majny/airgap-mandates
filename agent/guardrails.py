"""A1 input layer: Bedrock Guardrails ApplyGuardrail (prompt-attack filter) on untrusted tool output. Owner: WS-E.

Active when AIRGAP_GUARDRAIL_ID is set (the CDK stack creates `airgap-a1`; the agent λ and egress get its id).
Measured, not trusted: a miss is expected for adaptive payloads; the money gate is the executor (A3).
WS-F's bench uses the offline regex twin (bench/sanitize.py) for reproducible A1 runs.
"""
from __future__ import annotations

import os
from typing import Any

from agent import llm


def enabled() -> bool:
    return bool(os.environ.get("AIRGAP_GUARDRAIL_ID"))


def screen(text: str, *, source: str, bedrock: Any = None) -> tuple[str, dict[str, Any]]:
    """(text to show the planner, verdict). Intervened -> the content is replaced by a placeholder."""
    gid = os.environ.get("AIRGAP_GUARDRAIL_ID")
    if not gid or not text:
        return text, {"guardrail": "off"}
    resp = (bedrock or llm.client()).apply_guardrail(
        guardrailIdentifier=gid, guardrailVersion=os.environ.get("AIRGAP_GUARDRAIL_VERSION", "DRAFT"),
        source="INPUT", content=[{"text": {"text": text[:20000], "qualifiers": ["guard_content"]}}])
    action = resp.get("action", "NONE")
    verdict = {"guardrail": gid, "action": action,
               "filters": [f.get("type") for a in resp.get("assessments", [])
                           for f in (a.get("contentPolicy") or {}).get("filters", []) if f.get("action") == "BLOCKED"]}
    if action == "GUARDRAIL_INTERVENED":
        return f"[content from {source} withheld by A1 Guardrails: prompt attack]", verdict
    return text, verdict
