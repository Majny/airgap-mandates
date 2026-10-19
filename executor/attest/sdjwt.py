"""Minimal hand-rolled SD-JWT (RFC 9901) + ES256 JWS with `cryptography`. CONTRACTS.md v2 §11. Owner: WS-D.

Only what the payee-binding VC needs: strict base64url, ES256 compact JWS (raw r||s signatures), EC P-256 JWK
conversion, RFC 7638 thumbprints, disclosures `b64url(json([salt, name, value]))` with sha-256 `_sd` digests, and
the KB-JWT (`typ: kb+jwt`, `sd_hash`). Parsing is strict (canonical base64url, no duplicate JSON keys, ES256 only)
and ECDSA signatures are low-s only, so that any byte flip in a presentation is rejected and a presentation
has exactly one valid encoding.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

ALG = "ES256"
SD_ALG = "sha-256"
KB_TYP = "kb+jwt"
VC_TYPS = ("dc+sd-jwt", "vc+sd-jwt")
_B64U = re.compile(r"^[A-Za-z0-9_-]*$")
_COORD = 32
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # P-256 group order


class SdJwtError(ValueError):
    """Malformed or unverifiable SD-JWT / JWS input."""


# --- base64url / JSON ---------------------------------------------------------------------------------------------

def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    """Strict: alphabet only, no padding, and canonical (re-encodes to the same text; no stray low bits)."""
    if not isinstance(s, str) or not _B64U.match(s) or len(s) % 4 == 1:
        raise SdJwtError("bad base64url")
    try:
        raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError) as e:
        raise SdJwtError("bad base64url") from e
    if b64u_encode(raw) != s:
        raise SdJwtError("non-canonical base64url")
    return raw


def _no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    d: dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise SdJwtError(f"duplicate JSON key {k!r}")
        d[k] = v
    return d


def json_loads_strict(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_dupes)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise SdJwtError("bad JSON") from e


def _json_b64(obj: Any) -> str:
    return b64u_encode(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def sha256_b64u(text: str) -> str:
    return b64u_encode(hashlib.sha256(text.encode("ascii")).digest())


# --- keys / JWK ---------------------------------------------------------------------------------------------------

def generate_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def public_jwk(key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) -> dict[str, str]:
    pub = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    nums = pub.public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64u_encode(nums.x.to_bytes(_COORD, "big")),
            "y": b64u_encode(nums.y.to_bytes(_COORD, "big"))}


def private_jwk(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    d = key.private_numbers().private_value.to_bytes(_COORD, "big")
    return {**public_jwk(key), "d": b64u_encode(d)}


def _coord(jwk: dict[str, Any], name: str) -> int:
    raw = b64u_decode(jwk.get(name, ""))
    if len(raw) != _COORD:
        raise SdJwtError(f"jwk {name} must be {_COORD} bytes")
    return int.from_bytes(raw, "big")


def key_from_jwk(jwk: Any) -> ec.EllipticCurvePublicKey:
    """P-256 public key from a JWK (point validated by `cryptography`)."""
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise SdJwtError("jwk must be EC P-256")
    try:
        return ec.EllipticCurvePublicNumbers(_coord(jwk, "x"), _coord(jwk, "y"), ec.SECP256R1()).public_key()
    except ValueError as e:
        raise SdJwtError("jwk point not on curve") from e


def private_key_from_jwk(jwk: dict[str, Any]) -> ec.EllipticCurvePrivateKey:
    key = ec.derive_private_key(_coord(jwk, "d"), ec.SECP256R1())
    if public_jwk(key) != {k: jwk[k] for k in ("kty", "crv", "x", "y")}:
        raise SdJwtError("jwk d does not match x/y")
    return key


def thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 JWK thumbprint (SHA-256, base64url) over the required EC members."""
    req = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
    return b64u_encode(hashlib.sha256(json.dumps(req, separators=(",", ":"), sort_keys=True).encode()).digest())


# --- ES256 JWS ----------------------------------------------------------------------------------------------------

def jws_sign(header: dict[str, Any], payload: dict[str, Any], key: ec.EllipticCurvePrivateKey) -> str:
    signing_input = f"{_json_b64({**header, 'alg': ALG})}.{_json_b64(payload)}"
    r, s = decode_dss_signature(key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256())))
    s = min(s, _N - s)  # low-s: one valid signature per message (no (r, n-s) twin)
    return f"{signing_input}.{b64u_encode(r.to_bytes(_COORD, 'big') + s.to_bytes(_COORD, 'big'))}"


def jws_parse(compact: str) -> tuple[dict[str, Any], dict[str, Any], str, bytes]:
    """(header, payload, signing_input, raw signature); rejects any alg other than ES256 (none, HS256, ...)."""
    parts = compact.split(".")
    if len(parts) != 3:
        raise SdJwtError("JWS must have 3 parts")
    header, payload = json_loads_strict(b64u_decode(parts[0])), json_loads_strict(b64u_decode(parts[1]))
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise SdJwtError("JWS header/payload must be objects")
    if header.get("alg") != ALG or "crit" in header:
        raise SdJwtError(f"alg {header.get('alg')!r} not allowed")
    sig = b64u_decode(parts[2])
    if len(sig) != 2 * _COORD:
        raise SdJwtError("ES256 signature must be 64 bytes")
    return header, payload, f"{parts[0]}.{parts[1]}", sig


def es256_verify(pub: ec.EllipticCurvePublicKey, signing_input: str, sig: bytes) -> bool:
    """Raw r||s ES256 check; high-s signatures are rejected so a JWS (and its sha256, used for revocation) is not
    malleable."""
    if len(sig) != 2 * _COORD:
        return False
    r, s = int.from_bytes(sig[:_COORD], "big"), int.from_bytes(sig[_COORD:], "big")
    if not (0 < r < _N and 0 < s <= _N // 2):
        return False
    try:
        pub.verify(encode_dss_signature(r, s), signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


# --- disclosures / SD-JWT -----------------------------------------------------------------------------------------

def make_disclosure(name: str, value: Any, salt: str | None = None) -> str:
    return _json_b64([salt or b64u_encode(secrets.token_bytes(16)), name, value])


def disclosure_digest(disclosure: str) -> str:
    return sha256_b64u(disclosure)


def parse_disclosure(disclosure: str) -> tuple[str, Any]:
    arr = json_loads_strict(b64u_decode(disclosure))
    if not (isinstance(arr, list) and len(arr) == 3 and all(isinstance(x, str) for x in arr[:2])):
        raise SdJwtError("disclosure must be [salt, name, value]")
    if arr[1] in ("_sd", "...", "_sd_alg"):
        raise SdJwtError("reserved claim name in disclosure")
    return arr[1], arr[2]


def sd_hash(issuer_jwt: str, disclosures: list[str]) -> str:
    """b64url(sha256(ascii('<jwt>~<d1>~...~<dn>~'))) per RFC 9901 §4.3.1."""
    return sha256_b64u(presentation_prefix(issuer_jwt, disclosures))


def presentation_prefix(issuer_jwt: str, disclosures: list[str]) -> str:
    return "~".join([issuer_jwt, *disclosures]) + "~"


def kb_jwt(holder_key: ec.EllipticCurvePrivateKey, *, issuer_jwt: str, disclosures: list[str], aud: str, nonce: str,
           iat: int) -> str:
    return jws_sign({"typ": KB_TYP}, {"aud": aud, "nonce": nonce, "iat": iat,
                                      "sd_hash": sd_hash(issuer_jwt, disclosures)}, holder_key)


def split_presentation(vc: str) -> tuple[str, list[str], str]:
    """'<jwt>~<d1>~...~<dn>~<kb-jwt>' -> (jwt, disclosures, kb_jwt). A KB-JWT is mandatory here."""
    if not isinstance(vc, str) or not vc.isascii():
        raise SdJwtError("presentation must be ASCII")
    parts = vc.split("~")
    if len(parts) < 2 or not parts[0] or not parts[-1] or any(not d for d in parts[1:-1]):
        raise SdJwtError("presentation must be <jwt>~<disclosures>~<kb-jwt>")
    return parts[0], parts[1:-1], parts[-1]
