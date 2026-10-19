"""Policy material and policy_hash. Owner: WS-A. Implements CONTRACTS.md v2 §8.1.

Rules are Cedar policies (executor/policy/cedar/*.cedar) whose @id annotation is the rule id. This module holds
data only (policy text, schema, severity table, params) and the hash over it; evaluation lives in decide.py.
policy_hash = sha256(canonical_json(policy_material())).hex(); the material contains integers only.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from executor.canonical import canonical_json, sha256_hex

POLICY_V = 2
CEDAR_DIR = Path(__file__).resolve().parent / "cedar"
# Order matters: cedar_policies_text = these files LF-joined in this order.
POLICY_SET_FILES: list[str] = ["hard_deny.cedar", "mandate_allow.cedar", "change.cedar"]
SCHEMA_FILE = "schema.cedarschema.json"

# Non-Cedar parameters used when computing the Cedar context (ints only).
PARAMS: dict[str, dict[str, int]] = {
    "I-DUP": {"dup_amount_bp": 50, "dup_days": 3},
    "I-SPLIT": {"split_window_hours": 24},
    "I-Z": {"z_threshold_milli": 3500},
    "I-ANOM": {"default_max_anom": 40},
    "F-FIRSTSEEN": {"warn_hours": 72},
    "F-DOMAIN-AGE": {"warn_days": 30},
    "F-ATTEST": {"min_distinct_classes": 2, "kb_jwt_max_age_seconds": 900},
    "F-CALLBACK": {"max_attempts": 3},
}

# Fact id -> value -> severity (CONTRACTS §2.1). Producers must use exactly these severities.
FACT_SEVERITY: dict[str, dict[str, str]] = {
    "F-MANDATE": {"within": "INFO", "over_cap": "WARN", "no_mandate": "WARN"},
    "F-ATTEST": {"quorum": "INFO", "break_glass": "INFO", "insufficient": "BLOCK"},
    "F-CALLBACK": {"confirmed": "INFO", "not_required": "INFO", "missing": "BLOCK"},
    "F-DOMAIN": {"match": "INFO", "lookalike": "BLOCK"},
    "F-DKIM": {"pass": "INFO", "fail": "BLOCK"},
    "F-DOMAIN-AGE": {"old": "INFO", "young": "WARN"},
    "F-WARNLIST": {"clear": "INFO", "hit": "BLOCK"},
    "F-SANCTION": {"clear": "INFO", "hit": "BLOCK"},
    "F-VOP": {"MTCH": "INFO", "CMTC": "WARN", "NMTC": "BLOCK", "NOAP": "WARN"},
    "F-PSP": {"licensed_inst_vop": "INFO", "licensed_no_vop": "WARN", "unknown": "WARN"},
    "F-VAT": {"published": "INFO", "not_published": "WARN", "unreliable": "BLOCK"},
    "F-BANK": {"domestic": "INFO", "foreign_or_emi": "WARN"},
    "F-FIRSTSEEN": {"known": "INFO", "new": "WARN"},
    "F-DUP": {"duplicate": "BLOCK"},
    "F-SPLIT": {"split": "WARN"},
    "F-Z": {"outlier": "WARN"},
    "F-ANOM": {"low": "INFO", "high": "WARN"},
    "F-NAME-TRANSLIT": {"transliterated": "INFO"},
}


def cedar_policies_text() -> str:
    return "\n".join((CEDAR_DIR / f).read_text() for f in POLICY_SET_FILES)


def cedar_schema() -> dict[str, Any]:
    return json.loads((CEDAR_DIR / SCHEMA_FILE).read_text())


def policy_set_text(name: str) -> str:
    """Text of one policy set: 'hard_deny' | 'mandate_allow' | 'change'."""
    return (CEDAR_DIR / f"{name}.cedar").read_text()


_ID_RE = re.compile(r'@id\("([^"]+)"\)')


def policy_ids(text: str) -> list[str]:
    """@id annotations in file order; cedarpy's 'policy<N>' corresponds to policy_ids(text)[N]."""
    return _ID_RE.findall(text)


def policy_material() -> dict[str, Any]:
    from executor.render import TRANSLIT  # render owns the transliteration table

    return {
        "cedar_policies_text": cedar_policies_text(),
        "cedar_schema": cedar_schema(),
        "translit_table": TRANSLIT,
        "fact_severity_table": FACT_SEVERITY,
        "params": PARAMS,
        "policy_v": POLICY_V,
    }


@lru_cache(maxsize=1)
def policy_hash() -> str:
    """sha256(canonical_json(policy_material())).hex() - 64 lowercase hex."""
    return sha256_hex(canonical_json(policy_material()))


def rule_params(rule_id: str) -> dict[str, int]:
    """Params of one rule from PARAMS."""
    return PARAMS[rule_id]
