"""F-PSP fact (CONTRACTS.md v2 §2.1 table: source, values -> severity, display_line <= 18). Owner: WS-D."""
from __future__ import annotations

from typing import Any

from executor.models import Fact


def fact(subject: dict[str, Any], state: dict[str, Any]) -> Fact:
    """Compute F-PSP; set prov = sha256 of the snapshot used."""
    raise NotImplementedError("TODO WS-D")
