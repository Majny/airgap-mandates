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
DEVICE_PROFILES = {"T3T1": "safe5-mono-18x7", "T2B1": "safe3-mono-16x4", "T3B1": "safe3-mono-16x4"}


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


def executor_call(executor_url: str | None = None) -> Any:
    """call(method, path, body, who) -> (status, json) for the executor at `executor_url`. The AWS regional API
    (execute-api) is SigV4-signed with the principal's IAM role (airgap-<who>, via infra.aws_e2e); any other URL is
    plain HTTP with X-Client (local `make dev`)."""
    if executor_url is None:
        from executor.config import Settings

        executor_url = Settings.from_env().executor_url
    base = executor_url.rstrip("/")
    if ".execute-api." in base:
        from infra.aws_e2e import signed_call

        return signed_call(base)
    import httpx

    client = httpx.Client(base_url=base, timeout=30)

    def call(m: str, p: str, b: Any, who: str) -> tuple[int, Any]:
        r = client.request(m, p, json=b, headers={"X-Client": who})
        return r.status_code, r.json() if "json" in r.headers.get("content-type", "") else r.text

    return call


def sign_challenge(nonce: str, role: str, *, executor_url: str | None = None, transport: str | None = None,
                   timeout: float = DEFAULT_TIMEOUT) -> dict:
    """GET /challenges/{nonce}, driver.sign(), POST /signatures; returns the signature_submit.response."""
    call = executor_call(executor_url)
    st, challenge = call("GET", f"/challenges/{nonce}", None, "host")
    if st != 200:
        raise RuntimeError(f"GET /challenges/{nonce} -> {st} {challenge}")
    if challenge.get("role") and challenge["role"] != role:
        raise ValueError(f"challenge is for role {challenge['role']}, not {role}")
    driver = get_driver(transport)
    try:
        approval = driver.sign(challenge, role, timeout)
    finally:
        close = getattr(driver, "close", None)
        if close:
            close()
    st, r = call("POST", "/signatures", {"nonce": approval["nonce"], "role": role, "sig": approval["sig"],
                                         "address": approval["address"],
                                         "displayed_text": approval["displayed_text"]}, "host")
    if st != 200:
        raise RuntimeError(f"POST /signatures -> {st} {r}")
    return r


# --------------------------------------------------------------------------- demo harness and fallback kit

EMULATOR_DEBUG = "127.0.0.1:21325"  # trezor-user-env debuglink
BANNER_EMULATOR = "*** FALLBACK MODE: CLERK SIGNS ON THE EMULATOR (T3B1), NOT THE PHYSICAL DEVICE ***"


def emulator_only(settings: Any = None) -> bool:
    """The one switch: AIRGAP_TREZOR_PATH=udp:... puts the clerk on the emulator (fallback kit)."""
    if settings is None:
        from executor.config import Settings

        settings = Settings.from_env()
    return bool(settings.trezor_path and str(settings.trezor_path).startswith("udp:"))


class AutoConfirm:
    """Simulated human for EMULATOR signers only (labelled as such): pages through the message at a readable pace
    via debuglink, then holds CONFIRM. Never used with a physical device (debuglink does not exist there)."""

    def __init__(self, debug: str = EMULATOR_DEBUG, *, page_s: float = 1.2, hold_ms: int = 1500):
        self.debug, self.page_s, self.hold_ms = debug, page_s, hold_ms

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self._run, name="emulator-autoconfirm", daemon=True)
        t.start()
        return t

    def _run(self) -> None:
        import time

        from trezorlib import models
        from trezorlib.debuglink import DebugLink
        from trezorlib.transport.udp import UdpTransport

        d = DebugLink(UdpTransport(self.debug))
        d.model = models.T3B1
        try:
            self._drive(d, time)
        finally:
            d.close()

    def _drive(self, d: Any, time: Any) -> None:
        deadline = time.monotonic() + 60
        while d.read_layout(wait=False).title() not in ("Signing address", "Confirm message"):
            if time.monotonic() > deadline:  # the sign request never reached the emulator
                return
            time.sleep(0.2)
        for _ in range(40):
            lay = d.read_layout(wait=True)
            comps = lay.all_components()
            time.sleep(self.page_s)
            if "HoldToConfirm" in comps and lay.active_page() >= lay.page_count() - 1:
                # Write the hold without the trailing GetState: its reply can arrive after the workflow ends and
                # would then be read by the next debuglink session, shifting every later exchange by one.
                from trezorlib import messages

                d._write(messages.DebugLinkDecision(physical_button=messages.DebugPhysicalButton.RIGHT_BTN,
                                                    hold_ms=self.hold_ms + 200))
                return
            d.press_right(wait=True)


class DeviceSigner:
    """eth_account-like signer backed by a Trezor, so executor.e2e.run() and WS-F scenes can sign on hardware:
    `.address` and `.sign_message(encode_defunct(text=...)).signature`."""

    def __init__(self, driver: TrezorDriver, key_ref: str, *, auto_confirm: bool = False,
                 log: Any = print, name: str = ""):
        if auto_confirm and not driver.is_emulator:
            raise ValueError("auto-confirm is for EMULATOR signers only")
        self.driver, self.key_ref, self.auto_confirm, self.log = driver, key_ref, auto_confirm, log
        self.name = name or key_ref
        self.address = driver.get_address(key_ref)
        self.device = driver.device_label
        self._sigs: dict[str, str] = {}

    def sign_message(self, signable: Any) -> Any:
        from types import SimpleNamespace

        text = bytes(signable.body).decode("ascii")
        if text in self._sigs:  # a replay re-sends the captured signature; the human is not asked again
            self.log(f"--> {self.name}: replaying the captured signature (no device interaction)")
            return SimpleNamespace(signature=bytes.fromhex(self._sigs[text][2:]))
        where = f"{self.driver.info()['model']} {self.device}"
        self.log(f"--> {self.name} on {where}: " + ("auto-confirm (simulated human)" if self.auto_confirm
                                                     else "read every page, then HOLD the right button"))
        if self.auto_confirm:
            AutoConfirm().start()
        _, sig = self.driver.sign_text(text, self.key_ref)
        self._sigs[text] = sig
        return SimpleNamespace(signature=bytes.fromhex(sig[2:]))


def demo_signers(*, settings: Any = None, auto_treasury: bool = True, auto_clerk: bool | None = None,
                 log: Any = print) -> tuple[DeviceSigner, DeviceSigner]:
    """(clerk, treasury) for the demo. Default: physical Safe 3 over USB = clerk, T3B1 emulator = treasury.
    Fallback (AIRGAP_TREZOR_PATH=udp:...): both on the emulator, clerk path m/.../0, treasury m/.../1."""
    fallback = emulator_only(settings)
    emu = TrezorDriver(EMULATOR_PATH)
    clerk_drv = emu if fallback else TrezorDriver(USB)
    if auto_clerk is None:
        auto_clerk = fallback
    if fallback:
        log(BANNER_EMULATOR)
    clerk = DeviceSigner(clerk_drv, "clerk", auto_confirm=auto_clerk, log=log, name="CLERK")
    treasury = DeviceSigner(emu, "treasury", auto_confirm=auto_treasury, log=log, name="TREASURY")
    return clerk, treasury


def run_s1(*, auto_treasury: bool = True, auto_clerk: bool | None = None, url: str | None = None) -> dict:
    """Demo beat S1 with real device signatures: in-process on the memory backend (rehearsal), or against a running
    executor at `url` (the AWS regional API: SigV4 as airgap-host / airgap-tools; the device addresses must already
    be enrolled there, see data/enrollment.json)."""
    from datetime import datetime, timezone

    from executor import e2e

    clerk, treasury = demo_signers(auto_treasury=auto_treasury, auto_clerk=auto_clerk)
    if url:
        call = executor_call(url)
        st, health = call("GET", "/health", None, "host")
        print(f"executor {url}: {st} backend={health.get('backend')} profile={health.get('render_profile')}")
        print(f"clerk    {clerk.address}  {clerk.device}\ntreasury {treasury.address}  {treasury.device}\n")
        return e2e.run(call, clerk, treasury, now=datetime.now(timezone.utc))

    from executor import handler
    from executor.config import Settings
    from executor.store import seed
    from executor.store.memory import MemoryStore

    # Same setup as executor.e2e.in_process(), with device addresses enrolled instead of software keys.
    s = Settings(backend="memory", data_dir=seed.dev_data_dir())
    ctx = handler.Context(s, MemoryStore(s))
    seed.seed_registry(ctx.store)
    seed.enroll_signer(ctx.store, clerk.address, "clerk", device=clerk.device, label=f"clerk ({clerk.device})",
                       settings=s)
    seed.enroll_signer(ctx.store, treasury.address, "treasury", device=treasury.device,
                       label=f"treasury ({treasury.device})", settings=s)
    print(f"clerk    {clerk.address}  {clerk.device}\ntreasury {treasury.address}  {treasury.device}\n")
    call = lambda m, p, b, who: handler.dispatch(m, p, None, b, principal=who, ctx=ctx)
    return e2e.run(call, clerk, treasury, now=datetime.now(timezone.utc))


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(description="Device signer: demo S1 with hardware, or sign one challenge.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s1 = sub.add_parser("s1", help="run demo beat S1 in-process with real device signatures (rehearsal)")
    s1.add_argument("--manual-treasury", action="store_true", help="operate the treasury emulator by hand")
    s1.add_argument("--manual-clerk", action="store_true", help="fallback mode: operate the clerk emulator by hand")
    s1.add_argument("--url", default=None, help="drive a running executor (e.g. the AWS regional API) instead")
    sc = sub.add_parser("sign", help="GET /challenges/{nonce}, sign on the device, POST /signatures")
    sc.add_argument("nonce")
    sc.add_argument("role", choices=sorted(ROLE_PATHS))
    sc.add_argument("--url", default=None)
    sc.add_argument("--transport", default=None)
    sub.add_parser("info", help="show the connected devices and the mode")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.WARNING)
    if a.cmd == "s1":
        run_s1(auto_treasury=not a.manual_treasury, auto_clerk=False if a.manual_clerk else None, url=a.url)
        print("\nS1 WITH DEVICES OK" + (" (FALLBACK: EMULATOR CLERK)" if emulator_only() else ""))
    elif a.cmd == "sign":
        print(json.dumps(sign_challenge(a.nonce, a.role, executor_url=a.url, transport=a.transport), indent=1))
    else:
        print("mode:", "FALLBACK (emulator clerk)" if emulator_only() else "physical clerk over USB")
        for p in (USB, EMULATOR_PATH):
            try:
                print(json.dumps(TrezorDriver(p).info()))
            except Exception as e:
                print(f"{p}: not available ({type(e).__name__}: {e})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
