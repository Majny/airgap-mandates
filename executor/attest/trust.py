"""Pinned issuer trust list per vendor (registry.issuer_pins). CONTRACTS.md v2 §11. Owner: WS-D.

A pin is `{issuer_class, iss, jwk_thumbprint, pinned_at}`. The verifier derives the issuer class from the pin whose
thumbprint matches the VC's signing key, never from the VC's own `issuer_class` claim.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from executor.attest.sdjwt import key_from_jwk, thumbprint
from executor.facts._util import data_dir

ISSUER_CLASSES = ("supplier-erp", "supplier-bank", "registry")


def pins_for(vendor_id: str, *, store: Any) -> list[dict[str, Any]]:
    """[{issuer_class, iss, jwk_thumbprint, pinned_at}] set at supplier enrolment; [] => not in network."""
    row = store.get("registry", {"vendor_id": vendor_id})
    return list((row or {}).get("issuer_pins") or [])


def make_pin(issuer_class: str, iss: str, jwk: dict[str, Any], *, pinned_at: str) -> dict[str, Any]:
    if issuer_class not in ISSUER_CLASSES:
        raise ValueError(f"unknown issuer class {issuer_class!r}")
    key_from_jwk(jwk)  # validates the public key
    return {"issuer_class": issuer_class, "iss": iss, "jwk_thumbprint": thumbprint(jwk), "pinned_at": pinned_at}


def pin_issuer(vendor_id: str, issuer_class: str, iss: str, jwk: dict[str, Any], *, store: Any, settings: Any,
               now: datetime | None = None) -> None:
    """Enrolment-time pin (KYB pack); never callable by the agent or host roles. Idempotent per thumbprint."""
    row = store.get("registry", {"vendor_id": vendor_id})
    if row is None:
        raise KeyError(f"unknown vendor {vendor_id}")
    at = (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")
    pin = make_pin(issuer_class, iss, jwk, pinned_at=at)
    old = list(row.get("issuer_pins") or [])
    if any(p.get("jwk_thumbprint") == pin["jwk_thumbprint"] for p in old):
        return
    if not store.update_if("registry", {"vendor_id": vendor_id}, {"issuer_pins": [*old, pin]},
                           {"issuer_pins": row.get("issuer_pins")}):
        raise RuntimeError("concurrent issuer_pins update")


def pins_from_keys(keys_dir: str | Path | None = None, *, classes: tuple[str, ...] = ISSUER_CLASSES,
                   pinned_at: str = "2024-03-01T00:00:00Z") -> list[dict[str, Any]]:
    """Pins for the DEMO-ONLY issuer keys in data/issuer_keys/<class>.jwk (seeding helper)."""
    d = Path(keys_dir) if keys_dir else data_dir() / "issuer_keys"
    pins = []
    for cls in classes:
        jwk = json.loads((d / f"{cls}.jwk").read_text())
        pins.append(make_pin(cls, jwk["iss"], jwk, pinned_at=pinned_at))
    return pins
