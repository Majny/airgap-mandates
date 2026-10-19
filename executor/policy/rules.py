"""Policy rules constant and policy hash (M4). Owner: WS-E. Implements CONTRACTS.md §8.1.

POLICY contains integers only (canonical JSON forbids floats). policy_hash = sha256(canonical_json(POLICY)).hex().
"""
from __future__ import annotations

from typing import Any

POLICY: dict[str, Any] = {
    "policy_v": 1,
    "rules": [
        {"id": "I-MANDATE", "params": {}},
        {"id": "I-EXP", "params": {}},
        {"id": "I-PER", "params": {}},
        {"id": "I-BUDGET", "params": {}},
        {"id": "I-COUNT", "params": {}},
        {"id": "I-PAYEE", "params": {}},
        {"id": "I-NONCE", "params": {}},
        {"id": "I-DUP", "params": {"dup_amount_bp": 50, "dup_days": 3}},
        {"id": "I-SPLIT", "params": {"split_window_hours": 24}},
        {"id": "I-Z", "params": {"z_threshold_milli": 3500}},
    ],
}


def rule_params(rule_id: str) -> dict[str, Any]:
    """Params of one rule from POLICY."""
    for r in POLICY["rules"]:
        if r["id"] == rule_id:
            return r["params"]
    raise KeyError(rule_id)


def policy_hash(policy: dict[str, Any] | None = None) -> str:
    """sha256(canonical_json(policy or POLICY)).hex() — 64 lowercase hex."""
    raise NotImplementedError("TODO WS-E")
