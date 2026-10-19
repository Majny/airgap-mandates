"""Facts engine: FactSet for a proposal or a payee change, pure over content-hashed snapshots. CONTRACTS.md v2 §2.1.

Owner: WS-D.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from executor.models import Fact, FactSet


def compute(subject: dict[str, Any], state: dict[str, Any], now: datetime) -> FactSet:
    """subject: {"kind": "proposal"|"change", ...request fields}; state: {"payee", "mandate", "history",
    "snapshots": {name: path}, "tool_log", "change"}. Returns FactSet (F facts sorted by FACT_ORDER, then H facts;
    facts_digest over F facts only; prov on every snapshot-derived fact)."""
    raise NotImplementedError("TODO WS-D")


def facts_digest(facts: list[Fact]) -> str:
    """sha256(canonical_json([f for f in facts if f['kind'] == 'F'])) in canonical order."""
    raise NotImplementedError("TODO WS-D")


def hint_facts(hints: list[dict[str, Any]]) -> list[Fact]:
    """H-AGENT / H-UI facts, severity INFO; UI and log only, never on the device."""
    raise NotImplementedError("TODO WS-D")
