"""Signer worker: physical Trezor over USB (clerk) and trezor-user-env emulator over UDP (treasury, labelled EMULATOR).

EIP-191 ethereum.sign_message; the human holds to confirm exactly the executor-rendered text. CONTRACTS.md v2 §6.
Owner: WS-C.

Transport notes (measured at H0, docs/device/measurements.md):
- USB on macOS: trezorlib talks WebUSB directly through libusb. Trezor Suite and trezord (Bridge) must be closed, or
  they hold the interface. No Bridge is needed.
- Emulator: `udp:127.0.0.1:21324` (trezor-user-env; see docs/device/emulator.md).
- Timeout: the sign call runs in a worker thread; on timeout the host sends Cancel, the device returns to its
  homescreen and `TimeoutError` is raised. A rejection on the device raises `SignerCancelled`.
"""
from __future__ import annotations

import hashlib
import logging
import threading
from typing import Any, Protocol

from executor.models import Approval
from executor.sig import verify_eip191

LOG = logging.getLogger(__name__)

USB = "usb"
EMULATOR_PATH = "udp:127.0.0.1:21324"
DEFAULT_TIMEOUT = 300.0  # = AIRGAP_CHALLENGE_TTL_SECONDS

# One path per approver (CONTRACTS §6). Distinct indices keep clerk != treasury even if both run on one seed.
ROLE_PATHS = {
    "clerk": "m/44'/60'/0'/0/0",
    "treasury": "m/44'/60'/0'/0/1",
    "director": "m/44'/60'/0'/0/2",
    "accountant": "m/44'/60'/0'/0/3",
    "finance": "m/44'/60'/0'/0/4",
}

# internal_model -> display profile its screen matches (H0 measurements). Safe 3 has two hardware revisions.
DEVICE_PROFILES = {"T3T1": "safe5-mono-18x7", "T2B1": "safe3-mono-18x4", "T3B1": "safe3-mono-18x4"}


class SignerCancelled(RuntimeError):
    """The human rejected on the device (or the action was cancelled)."""


class SignerDriver(Protocol):
    def sign(self, challenge: dict, key_ref: str, timeout: float) -> Approval:
        """Show challenge['text'] on the device (key_ref = derivation path or role), wait for hold-to-confirm,
        return Approval {nonce, address, sig, displayed_text, device}. Raises TimeoutError / RuntimeError."""
        ...

    def get_address(self, key_ref: str) -> str:
        """Lowercase address for enrolment."""
        ...


def resolve_path(key_ref: str) -> str:
    """Role name or explicit BIP-32 path -> path string."""
    if key_ref in ROLE_PATHS:
        return ROLE_PATHS[key_ref]
    if key_ref.startswith("m/"):
        return key_ref
    raise ValueError(f"unknown key_ref {key_ref!r} (role or m/... path)")


def challenge_text(challenge: dict) -> str:
    """The exact text to sign, after checking it is canonical ASCII and matches `text_sha256` when present."""
    text = challenge.get("text")
    if not isinstance(text, str) or not text:
        raise ValueError("challenge has no text")
    if not all(" " <= c <= "~" or c == "\n" for c in text):
        raise ValueError("challenge text is not printable ASCII + LF; refusing to send it to the device")
    want = challenge.get("text_sha256")
    if want and hashlib.sha256(text.encode("ascii")).hexdigest() != want:
        raise ValueError("challenge text does not match text_sha256")
    return text


class TrezorDriver:
    """SignerDriver over trezorlib. `path` = 'usb' / None (autodetect USB) or 'udp:host:port' (emulator)."""

    def __init__(self, path: str | None = None, *, app_name: str = "airgap-mandates"):
        # 'usb' means the physical device: prefix-match WebUSB so a running emulator is never picked by autodetect.
        self.path = "webusb" if path in (None, "", USB) else path
        self.app_name = app_name
        self._client: Any = None
        self._session: Any = None

    # -- connection ---------------------------------------------------------------------------------------------
    def _connect(self) -> Any:
        if self._session is None:
            from trezorlib.client import PassphraseSetting, get_default_client

            self._client = get_default_client(self.app_name, self.path)
            # Passphrase policy (CONTRACTS §6): off, or entered on the device. Never typed on the host.
            f = self._client.features
            pp = PassphraseSetting.STANDARD_WALLET
            if f.passphrase_protection and f.passphrase_always_on_device:
                pp = PassphraseSetting.ON_DEVICE
            self._session = self._client.get_session(passphrase=pp)
        return self._session

    def close(self) -> None:
        try:
            if self._session is not None:
                self._session.close()
        except Exception:  # best effort
            pass
        self._session = self._client = None

    @property
    def features(self) -> Any:
        self._connect()
        return self._client.features

    @property
    def is_emulator(self) -> bool:
        return self.features.fw_vendor == "EMULATOR"

    @property
    def device_label(self) -> str:
        """Diagnostic only; the authoritative GENUINE/EMULATOR flag is set by tools/enroll.py."""
        return "EMULATOR" if self.is_emulator else "GENUINE"

    @property
    def profile(self) -> str | None:
        return DEVICE_PROFILES.get(self.features.internal_model)

    def info(self) -> dict:
        f = self.features
        return {
            "model": f.model,
            "internal_model": f.internal_model,
            "firmware_version": f"{f.major_version}.{f.minor_version}.{f.patch_version}",
            "fw_vendor": f.fw_vendor,
            "bootloader_locked": f.bootloader_locked,
            "passphrase_protection": f.passphrase_protection,
            "device": self.device_label,
            "profile": self.profile,
            "transport": USB if self.path == "webusb" else self.path,
        }

    # -- SignerDriver -------------------------------------------------------------------------------------------
    def get_address(self, key_ref: str) -> str:
        from trezorlib import ethereum, tools

        s = self._connect()
        return ethereum.get_address(s, tools.parse_path(resolve_path(key_ref)), show_display=False).lower()

    def sign_text(self, text: str, key_ref: str, timeout: float = DEFAULT_TIMEOUT) -> tuple[str, str]:
        """Raw EIP-191 sign of `text` (ASCII) -> (lowercase address, '0x' sig). Verifies the recovery locally."""
        from trezorlib import ethereum, exceptions, tools

        s = self._connect()
        n = tools.parse_path(resolve_path(key_ref))
        out: dict[str, Any] = {}

        def work() -> None:
            try:
                out["r"] = ethereum.sign_message(s, n, text.encode("ascii"))
            except BaseException as e:  # re-raised on the caller's thread
                out["e"] = e

        t = threading.Thread(target=work, name="trezor-sign", daemon=True)
        t.start()
        t.join(timeout)
        if t.is_alive():
            LOG.warning("signing timed out after %.0fs; cancelling on device", timeout)
            try:
                s.cancel()
            finally:
                t.join(10)
                self.close()
            raise TimeoutError(f"no confirmation on the device within {timeout:.0f}s")
        if "e" in out:
            e = out["e"]
            if isinstance(e, exceptions.Cancelled):
                raise SignerCancelled("rejected on the device") from e
            if isinstance(e, exceptions.TrezorFailure) and "cancel" in str(e).lower():
                raise SignerCancelled(str(e)) from e
            raise RuntimeError(f"device error: {e!r}") from e
        r = out["r"]
        sig = "0x" + r.signature.hex()
        address = r.address.lower()
        recovered = verify_eip191(text, sig)
        if recovered != address:
            raise RuntimeError(f"device returned address {address} but signature recovers to {recovered}")
        return address, sig

    def sign(self, challenge: dict, key_ref: str, timeout: float = DEFAULT_TIMEOUT) -> Approval:
        text = challenge_text(challenge)
        want = challenge.get("profile")
        if want and self.profile and want != self.profile:
            LOG.warning("challenge profile %s does not match this device's screen (%s)", want, self.profile)
        address, sig = self.sign_text(text, key_ref, timeout)
        return Approval(nonce=challenge["nonce"], address=address, sig=sig, displayed_text=text,
                        device=self.device_label)


def get_driver(transport: str | None = None) -> SignerDriver:
    """'usb' (physical device, default) or 'udp:127.0.0.1:21324' (emulator). None -> AIRGAP_TREZOR_PATH, then USB."""
    if transport is None:
        from executor.config import Settings

        transport = Settings.from_env().trezor_path
    return TrezorDriver(transport)


def sign_challenge(nonce: str, role: str, *, executor_url: str | None = None, transport: str | None = None,
                   timeout: float = DEFAULT_TIMEOUT) -> dict:
    """GET /challenges/{nonce}, driver.sign(), POST /signatures; returns the signature_submit.response."""
    import httpx

    if executor_url is None:
        from executor.config import Settings

        executor_url = Settings.from_env().executor_url
    base = executor_url.rstrip("/")
    with httpx.Client(timeout=30) as http:
        r = http.get(f"{base}/challenges/{nonce}")
        r.raise_for_status()
        challenge = r.json()
        if challenge.get("role") and challenge["role"] != role:
            raise ValueError(f"challenge is for role {challenge['role']}, not {role}")
        driver = get_driver(transport)
        try:
            approval = driver.sign(challenge, role, timeout)
        finally:
            close = getattr(driver, "close", None)
            if close:
                close()
        r = http.post(f"{base}/signatures", json={
            "nonce": approval["nonce"], "role": role, "sig": approval["sig"],
            "address": approval["address"], "displayed_text": approval["displayed_text"],
        })
        r.raise_for_status()
        return r.json()
