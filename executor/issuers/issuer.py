"""SD-JWT VC issuance for the three simulated issuer classes. CONTRACTS.md v2 §11. Owner: WS-D.

SIMULATED organisations, real cryptography: the keys in data/issuer_keys/ are DEMO-ONLY and the holder (supplier
wallet) key that signs the KB-JWT is held by the same simulated issuer process.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from executor.attest.sdjwt import (
    SD_ALG,
    disclosure_digest,
    jws_sign,
    kb_jwt,
    make_disclosure,
    presentation_prefix,
    private_key_from_jwk,
    public_jwk,
)
from executor.facts._util import data_dir, load_json, snapshot_path

VCT = "urn:airgap:payee-binding:v1"
VC_TTL = timedelta(hours=1)
SD_CLAIMS = ("legal_name", "iban", "ico")


class IssuerRefused(ValueError):
    """The issuer will not attest this binding (e.g. registry asked for a foreign or unpublished account)."""


def _ts(t: datetime) -> int:
    return int(t.timestamp())


def registry_check(change: dict[str, Any], *, adis_path: str | Path | None = None) -> None:
    """Registry witness only attests CZ accounts published in the ADIS cache for CZ<ico> (fails closed)."""
    iban = change["new_iban"]
    if not iban.startswith("CZ"):
        raise IssuerRefused("registry issuer never attests a foreign account")
    path = Path(adis_path) if adis_path else snapshot_path(None, "adis")
    try:
        adis, _ = load_json(path)
    except (OSError, ValueError) as e:
        raise IssuerRefused(f"ADIS cache unavailable: {e}") from e
    payer = (adis.get("payers") or {}).get(f"CZ{change['vendor_ico']}") or {}
    if payer.get("unreliable") or iban not in (payer.get("accounts") or []):
        raise IssuerRefused("IBAN not published in ADIS for this ICO")


def issue_sd_jwt(issuer_class: str, change: dict[str, Any], *, key: ec.EllipticCurvePrivateKey,
                 holder_key: ec.EllipticCurvePrivateKey, now: datetime, iss: str,
                 disclose: list[str] | None = None) -> tuple[str, list[str]]:
    """Issuer JWT + the disclosures chosen for presentation (default all of legal_name, iban, ico)."""
    values = {"legal_name": change.get("vendor_name", ""), "iban": change["new_iban"], "ico": change["vendor_ico"]}
    disclosures = {name: make_disclosure(name, values[name]) for name in SD_CLAIMS}
    payload = {
        "iss": iss, "vct": VCT, "iat": _ts(now), "exp": _ts(now + VC_TTL),
        "cnf": {"jwk": public_jwk(holder_key)},
        "_sd": sorted(disclosure_digest(d) for d in disclosures.values()), "_sd_alg": SD_ALG,
        "change_id": change["change_id"],
        "valid_from": change.get("valid_from") or now.date().isoformat(),
        "issuer_class": issuer_class,  # informational; the verifier derives the class from the pin
    }
    jwt = jws_sign({"typ": "dc+sd-jwt", "jwk": public_jwk(key)}, payload, key)
    chosen = SD_CLAIMS if disclose is None else disclose
    return jwt, [disclosures[n] for n in chosen]


def present(issuer_jwt: str, disclosures: list[str], *, holder_key: ec.EllipticCurvePrivateKey, aud: str,
            nonce: str, now: datetime) -> str:
    """Holder presentation '<jwt>~<d>...~<kb-jwt>' bound to the change (aud, nonce = change_nonce)."""
    kb = kb_jwt(holder_key, issuer_jwt=issuer_jwt, disclosures=disclosures, aud=aud, nonce=nonce, iat=_ts(now))
    return presentation_prefix(issuer_jwt, disclosures) + kb


def issue_vc(issuer_class: str, change: dict[str, Any], *, key: ec.EllipticCurvePrivateKey,
             holder_key: ec.EllipticCurvePrivateKey, now: datetime, iss: str | None = None,
             disclose: list[str] | None = None, adis_path: str | Path | None = None) -> str:
    """PayeeBindingAttestation (vct urn:airgap:payee-binding:v1) + KB-JWT (aud, nonce = change_nonce, iat);
    returns the compact '<jwt>~<disclosures>~<kb-jwt>' string. Raises IssuerRefused (registry class)."""
    if issuer_class == "registry":
        registry_check(change, adis_path=adis_path)
    jwt, ds = issue_sd_jwt(issuer_class, change, key=key, holder_key=holder_key, now=now,
                           iss=iss or ISSUER_URLS[issuer_class], disclose=disclose)
    return present(jwt, ds, holder_key=holder_key, aud=change["aud"], nonce=change["change_nonce"], now=now)


ISSUER_URLS = {
    "supplier-erp": "https://issuer.acme.example/erp",
    "supplier-bank": "https://issuer.bank0300.example/accounts",
    "registry": "https://registry.airgap.example",
}


def _keys_dir() -> Path:
    return data_dir() / "issuer_keys"


def _read_jwk(name: str, env: str) -> dict[str, Any]:
    raw = os.environ.get(env)
    return json.loads(raw) if raw else json.loads((_keys_dir() / f"{name}.jwk").read_text())


def load_issuer_key(issuer_class: str) -> tuple[ec.EllipticCurvePrivateKey, str]:
    """(DEMO-ONLY private key, iss) from data/issuer_keys/<class>.jwk; env AIRGAP_ISSUER_KEY_<CLASS> (JWK JSON)
    overrides."""
    if issuer_class not in ISSUER_URLS:
        raise ValueError(f"unknown issuer class {issuer_class!r}")
    jwk = _read_jwk(issuer_class, "AIRGAP_ISSUER_KEY_" + issuer_class.upper().replace("-", "_"))
    return private_key_from_jwk(jwk), jwk.get("iss") or ISSUER_URLS[issuer_class]


def load_holder_key(vendor_ico: str) -> ec.EllipticCurvePrivateKey:
    """DEMO-ONLY holder (supplier wallet) key data/issuer_keys/holder-<ico>.jwk; env AIRGAP_HOLDER_KEY_<ICO>."""
    if not (isinstance(vendor_ico, str) and vendor_ico.isascii() and vendor_ico.isdigit() and len(vendor_ico) == 8):
        raise ValueError("vendor_ico must be 8 ASCII digits")
    return private_key_from_jwk(_read_jwk(f"holder-{vendor_ico}", f"AIRGAP_HOLDER_KEY_{vendor_ico}"))


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Issuer λ: issue for {change_id} (class from event or AIRGAP_ISSUER_CLASS) and POST
    /changes/{id}/attestations on AIRGAP_EXECUTOR_URL."""
    import httpx

    issuer_class = event.get("issuer_class") or os.environ["AIRGAP_ISSUER_CLASS"]
    base = os.environ.get("AIRGAP_EXECUTOR_URL", "http://127.0.0.1:8000").rstrip("/")
    headers = {"X-Client": "issuer"}
    change_id = event["change_id"]
    with httpx.Client(timeout=10.0) as http:
        r = http.get(f"{base}/changes/{change_id}", headers=headers)
        r.raise_for_status()
        change = r.json()
        change = change.get("change", change)
        key, iss = load_issuer_key(issuer_class)
        try:
            vc = issue_vc(issuer_class, change, key=key, holder_key=load_holder_key(change["vendor_ico"]),
                          now=datetime.now().astimezone(), iss=iss)
        except IssuerRefused as e:
            return {"statusCode": 422, "body": json.dumps({"error": "issuer_refused", "message": str(e)})}
        r = http.post(f"{base}/changes/{change_id}/attestations", headers=headers,
                      json={"vc": vc, "issuer_class": issuer_class})
    return {"statusCode": r.status_code, "body": r.text}
