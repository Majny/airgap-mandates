"""F-VOP: Verification of Payee mock with EPC codes. CONTRACTS.md v2 §2.1.

MTCH -> INFO 'VOP MTCH'; CMTC -> WARN 'VOP CMTC'; NMTC -> BLOCK 'VOP NMTC'; NOAP -> WARN 'VOP NOAP'. Owner: WS-D.
"""
from __future__ import annotations

from typing import Any

from executor.models import Fact


def vop_fact(iban: str, name: str, *, snapshot: Any) -> Fact:
    """Look up the VoP mock snapshot; prov = its sha256."""
    raise NotImplementedError("TODO WS-D")
