"""SD-JWT VC + KB-JWT verifier for payee-binding attestations. CONTRACTS.md v2 §11 (S4). Owner: WS-D."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from executor.models import AttestResult


def verify_vc(vc: str, change: dict[str, Any], *, pins: list[dict[str, Any]], now: datetime) -> AttestResult:
    """Verify issuer signature against the pinned trust list (class from the pin, never from the VC), disclosures,
    KB-JWT (aud = change.aud, nonce = change.change_nonce, iat <= 15 min), disclosed iban == change.new_iban and
    ico == change.vendor_ico, not revoked. Errors: kb_jwt_invalid | issuer_not_pinned | break_glass_required."""
    raise NotImplementedError("TODO WS-D")


def distinct_classes(results: list[AttestResult]) -> int:
    """Number of distinct issuer classes among ok results (F-ATTEST k/3)."""
    raise NotImplementedError("TODO WS-D")
