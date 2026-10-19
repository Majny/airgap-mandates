"""SD-JWT VC issuance for the three simulated issuer classes. CONTRACTS.md v2 §11. Owner: WS-D."""
from __future__ import annotations

from typing import Any


def issue_vc(issuer_class: str, change: dict[str, Any], *, key: Any, holder_key: Any, now: Any) -> str:
    """PayeeBindingAttestation (vct urn:airgap:payee-binding:v1) + KB-JWT (aud, nonce = change_nonce, iat);
    returns the compact '<jwt>~<disclosures>~<kb-jwt>' string."""
    raise NotImplementedError("TODO WS-D")


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Issuer λ: issue for a change and POST /changes/{id}/attestations."""
    raise NotImplementedError("TODO WS-D")
