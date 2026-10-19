"""A2 tool scoping: cedarpy twin of the AgentCore Gateway Cedar policy (executor/tools/policies/tools.cedar).

Defence in depth only, never the money gate. Same policy text is uploaded to AgentCore Policy when the Gateway is used.

Owner: WS-E.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import cedarpy

POLICY_DIR = Path(__file__).resolve().parent / "policies"
_ID_RE = re.compile(r'@id\("([^"]+)"\)')


@lru_cache(maxsize=1)
def policy_text() -> str:
    return (POLICY_DIR / "tools.cedar").read_text()


@lru_cache(maxsize=1)
def schema() -> dict[str, Any]:
    return json.loads((POLICY_DIR / "tools.cedarschema.json").read_text())


def authorize(tool: str, *, effect: str, mode: str, session_id: str, context: dict[str, Any]) -> tuple[bool, list[str]]:
    """(allowed, sorted forbid @ids that determined the decision)."""
    text = policy_text()
    request = {"principal": f'Agent::"{session_id}"', "action": 'Action::"call"', "resource": f'Tool::"{tool}"',
               "context": context}
    entities = [{"uid": {"type": "Agent", "id": session_id}, "attrs": {"mode": mode}, "parents": []},
                {"uid": {"type": "Tool", "id": tool}, "attrs": {"effect": effect}, "parents": []}]
    r = cedarpy.is_authorized(request, text, entities, schema=schema())
    if r.diagnostics.errors:
        raise ValueError(f"cedar evaluation error: {list(r.diagnostics.errors)}")
    ids = _ID_RE.findall(text)
    hit = sorted({ids[int(p.removeprefix("policy"))] for p in r.diagnostics.reasons} - {"T-BASE"})
    return r.decision == cedarpy.Decision.Allow, hit
