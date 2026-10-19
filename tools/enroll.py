"""Enrolment ceremony (ARCHITECTURE §3.3): authenticate_device, GetFirmwareHash, get_address, EIP-191 over ENROLL.

The tool (never the host) sets device = GENUINE | EMULATOR; writes enrolled_signers + enroll leaf. CONTRACTS.md v2 §6.
Owner: WS-C.

    python -m tools.enroll clerk                               # physical device over USB
    python -m tools.enroll treasury --transport udp:127.0.0.1:21324   # emulator, labelled EMULATOR
    python -m tools.enroll clerk --out data/enrollment.json --official-fw .local/fw/trezor-t2b1-2.12.0.bin

GENUINE requires all of: Optiga authenticity proof verified against the Trezor root (built into trezorlib),
fw_vendor != EMULATOR, bootloader locked, and (when an official image is given) the device's challenge-keyed
firmware hash equal to the one computed from the official release image.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from executor import render
from executor.sig import verify_eip191
from host.signer import ROLE_PATHS, TrezorDriver, resolve_path

BANK_ROLES = ("clerk", "treasury")
DEFAULT_OUT = "data/enrollment.json"


class EnrollError(RuntimeError):
    pass


def firmware_area_hash(image: bytes, challenge: bytes, area_size: int) -> bytes:
    """Hash as computed by core firmware for GetFirmwareHash on T2B1/T2T1: blake2s keyed with the challenge over
    the whole firmware flash area (the image followed by erased 0xFF flash)."""
    h = hashlib.blake2s(key=challenge)
    h.update(image)
    h.update(b"\xff" * (area_size - len(image)))
    return h.digest()


# internal_model -> firmware area size in bytes (measured at H0 against the official image; docs/device/measurements.md)
FIRMWARE_AREA = {"T2B1": 13 * 128 * 1024}


def check_official_fw(image_path: str | Path, challenge: bytes, device_hash: bytes, model: str) -> bool:
    image = Path(image_path).read_bytes()
    area = FIRMWARE_AREA.get(model)
    if area is None:
        raise EnrollError(f"no firmware area size known for {model}")
    return secrets.compare_digest(firmware_area_hash(image, challenge, area), device_hash)


def authenticate(session: Any) -> str:
    """Optiga authenticity proof (physical only; asks for on-device confirmation). Returns sha256 of the chain."""
    from trezorlib import authentication, device

    ch = os.urandom(32)
    resp = device.authenticate(session, ch)
    authentication.verify_authentication_response(ch, resp.optiga_signature, resp.optiga_certificates,
                                                  allowlist=None)  # raises DeviceNotAuthentic
    return hashlib.sha256(b"".join(resp.optiga_certificates)).hexdigest()


def enroll(role: str, *, transport: str | None = None, path: str = "m/44'/60'/0'/0/0", settings: Any = None,
           official_fw: str | None = None, label: str | None = None, nonce: str | None = None,
           timeout: float = 300.0) -> dict:
    """Run the ceremony for one role; returns the enrolled_signers row (with the enroll leaf data under `leaf`)."""
    from trezorlib import firmware

    if role not in BANK_ROLES:
        raise EnrollError(f"role must be one of {BANK_ROLES}")
    deployment = getattr(settings, "deployment_id", None) or render.DEFAULT_DEPLOYMENT
    path = resolve_path(path)
    drv = TrezorDriver(transport)
    info = drv.info()
    emulator = info["fw_vendor"] == "EMULATOR"
    session = drv._connect()

    cert_chain_sha256: str | None = None
    auth_note = "emulator: no Optiga"
    if not emulator:
        cert_chain_sha256 = authenticate(session)
        auth_note = "optiga chain verified"

    fw_challenge = os.urandom(32)
    fw_hash = firmware.get_hash(session, fw_challenge)
    fw_ok: bool | None = None
    if official_fw:
        fw_ok = check_official_fw(official_fw, fw_challenge, fw_hash, info["internal_model"])
        if not fw_ok and not emulator:
            raise EnrollError("firmware hash does not match the official release image")

    genuine = (not emulator) and cert_chain_sha256 is not None and bool(info["bootloader_locked"]) \
        and fw_ok is not False
    device_flag = "GENUINE" if genuine else "EMULATOR"
    if not emulator and not genuine:
        raise EnrollError("physical device failed a GENUINE check; refusing to enrol it")

    address = drv.get_address(path)
    nonce = nonce or secrets.token_hex(4).upper()
    text = render.render_enroll(role=role, nonce=nonce, deployment=deployment)
    signed_addr, sig = drv.sign_text(text, path, timeout)
    if signed_addr != address or verify_eip191(text, sig) != address:
        raise EnrollError("ENROLL signature does not recover to the enrolled address")
    drv.close()

    label = label or f"{role.capitalize()} (Trezor {info['model']}{', emulator' if emulator else ''})"
    leaf = {
        "address": address, "role": role, "label": label, "device": device_flag,
        "device_model": info["internal_model"], "firmware_version": info["firmware_version"],
        "cert_chain_sha256": cert_chain_sha256, "fw_hash": fw_hash.hex(), "derivation_path": path,
        "enroll_sig": sig,
    }
    return {
        "pk": f"signer#{address}", "sk": "0", **leaf, "active": True,
        "enrolled_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "leaf": leaf,
        "ceremony": {"nonce": nonce, "text": text, "fw_challenge": fw_challenge.hex(), "fw_official_match": fw_ok,
                     "authenticity": auth_note, "transport": info["transport"],
                     "bootloader_locked": info["bootloader_locked"]},
    }


def write_row(row: dict, out: str | Path) -> None:
    """Upsert the row into the enrollment snapshot (replaces any previous signer with the same role)."""
    p = Path(out)
    doc = json.loads(p.read_text()) if p.exists() else {"version": 1, "signers": []}
    doc["signers"] = [s for s in doc.get("signers", []) if s.get("role") != row["role"]] + [row]
    p.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    ap.add_argument("role", choices=BANK_ROLES)
    ap.add_argument("--transport", default=None, help="usb (default) or udp:127.0.0.1:21324")
    ap.add_argument("--path", default=None, help="derivation path (default per role)")
    ap.add_argument("--official-fw", default=None, help="official release image to check the firmware hash against")
    ap.add_argument("--out", default=DEFAULT_OUT, help="enrollment snapshot to upsert (use - for stdout only)")
    ap.add_argument("--label", default=None)
    a = ap.parse_args(argv)
    try:
        row = enroll(a.role, transport=a.transport, path=a.path or ROLE_PATHS[a.role], official_fw=a.official_fw,
                     label=a.label)
    except EnrollError as e:
        print(f"ENROLMENT REFUSED: {e}", file=sys.stderr)
        return 2
    print(json.dumps(row, indent=1))
    if a.out != "-":
        write_row(row, a.out)
        print(f"written to {a.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
