"""Pinned issuer trust list per vendor (registry.issuer_pins). CONTRACTS.md v2 §11. Owner: WS-D."""
from __future__ import annotations

from typing import Any


def pins_for(vendor_id: str, *, store: Any) -> list[dict[str, Any]]:
    """[{issuer_class, iss, jwk_thumbprint, pinned_at}] set at supplier enrolment; [] => not in network."""
    raise NotImplementedError("TODO WS-D")


def pin_issuer(vendor_id: str, issuer_class: str, iss: str, jwk: dict[str, Any], *, store: Any, settings: Any) -> None:
    """Enrolment-time pin (KYB pack); never callable by the agent or host roles."""
    raise NotImplementedError("TODO WS-D")
