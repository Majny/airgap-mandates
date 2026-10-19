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

            self._client = self._open_client(get_default_client)
            # Passphrase policy (CONTRACTS §6): off, or entered on the device. Never typed on the host.
            f = self._client.features
            pp = PassphraseSetting.STANDARD_WALLET
            if f.passphrase_protection and f.passphrase_always_on_device:
                pp = PassphraseSetting.ON_DEVICE
            self._session = self._client.get_session(passphrase=pp)
        return self._session

    def _open_client(self, get_default_client: Any) -> Any:
        """The emulator can miss trezorlib's short UDP ping right after a workflow ends: retry a few times."""
        import time

        from trezorlib.transport import TransportException

        tries = 5 if self.path and self.path.startswith("udp:") else 1
        for i in range(tries):
            try:
                return get_default_client(self.app_name, self.path)
            except TransportException:
                if i == tries - 1:
                    raise
                time.sleep(1.0)

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


def run_scene(name: str, *, auto_treasury: bool = True, auto_clerk: bool | None = None,
              url: str | None = None) -> dict:
    """WS-A's demo beats S2/S3 (executor.scenes) with device signers in place of the software keys.

    In-process (memory backend, WS-D's seed): the seed enrols data/enrollment.json; a device address not active there
    (the fallback emulator clerk) is enrolled for this rehearsal only. With `url` (the AWS regional API, AwsEnv): the
    device addresses must already be active in the deployment (fallback clerk: `infra.reset_state --fallback-clerk`);
    nothing is enrolled from here."""
    from executor import scenes
    from executor.store import seed

    env = scenes.AwsEnv(url) if url else scenes.DemoEnv()
    clerk, treasury = demo_signers(auto_treasury=auto_treasury, auto_clerk=auto_clerk)
    active = {(r["address"], r["role"]) for r in env.store.scan("enrolled_signers") if r.get("active")}
    for signer, role in ((clerk, "clerk"), (treasury, "treasury")):
        if (signer.address, role) in active:
            continue
        if url:
            raise SystemExit(f"{role} {signer.address} ({signer.device}) is not active on {url}: ask the AWS owner "
                             f"for a reset{' with --fallback-clerk' if signer.device == 'EMULATOR' else ''}")
        seed.enroll_signer(env.store, signer.address, role, device=signer.device,
                           label=f"{role} ({signer.device}, rehearsal)", settings=env.settings)
    env.clerk, env.treasury = clerk, treasury
    print(f"clerk    {clerk.address}  {clerk.device}\ntreasury {treasury.address}  {treasury.device}\n")
    return scenes.scene_s2(env) if name == "s2" else scenes.scene_s3(env)


def _post_sig(call: Any, ch: dict, signer: "DeviceSigner") -> tuple[int, Any]:
    from eth_account.messages import encode_defunct

    sig = "0x" + signer.sign_message(encode_defunct(text=ch["text"])).signature.hex()
    return call("POST", "/signatures", {"nonce": ch["nonce"], "role": ch["role"], "sig": sig,
                                        "displayed_text": ch["text"]}, "host")


def create_mandate(call: Any, clerk: "DeviceSigner", treasury: "DeviceSigner", *, log: Any = print) -> dict:
    """Stage S1 part 1: the mandate (same terms as executor.e2e: 80000 per payment, 250000 total, 20 payments,
    existing payees, 24 h), signed by the clerk device and then the treasury device (2/2)."""
    from datetime import datetime, timedelta, timezone

    until = (datetime.now(timezone.utc) + timedelta(days=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    st, r = call("POST", "/mandates", {"max_per_payment_minor": 8_000_000, "max_total_minor": 25_000_000,
                                       "max_count": 20, "payee_scope": "existing_only", "valid_until": until,
                                       "currency": "CZK"}, "host")
    if st != 201:
        raise RuntimeError(f"POST /mandates -> {st} {r}")
    log(f"mandate {r['mandate']['mandate_id']}: sig_required={r['mandate']['sig_required']}\n{r['challenge']['text']}\n")
    st, r = _post_sig(call, r["challenge"], clerk)
    if st != 200:
        raise RuntimeError(f"clerk signature -> {st} {r}")
    log(f"clerk signed -> {r['effect']['state']}")
    if r.get("challenge"):
        st, r = _post_sig(call, r["challenge"], treasury)
        if st != 200:
            raise RuntimeError(f"treasury signature -> {st} {r}")
    m = r["mandate"]
    log(f"mandate {m['mandate_id']} -> {m['status']}")
    return m


def pay_up(call: Any, clerk: "DeviceSigner", *, vendor_id: str | None = None, replay: bool = True,
           log: Any = print) -> list[dict]:
    """Stage S1 part 3: every PENDING_SIG proposal (optionally one vendor's) is exact-signed on the clerk device;
    then the captured signature is re-sent once to show the replay refusal (nonce_reused)."""
    q = "/proposals?status=PENDING_SIG" + (f"&vendor_id={vendor_id}" if vendor_id else "")
    st, r = call("GET", q, None, "host")
    if st != 200:
        raise RuntimeError(f"GET {q} -> {st} {r}")
    pending = r.get("proposals", [])
    if not pending:
        log("no proposal is waiting for a signature (nothing to step up)")
    out = []
    for p in sorted(pending, key=lambda p: p["proposal_no"]):
        st, ch = call("GET", f"/challenges/{p['challenge_nonce']}", None, "host")
        if st != 200:
            raise RuntimeError(f"GET /challenges/{p['challenge_nonce']} -> {st} {ch}")
        inv = p.get("invoice", {})
        log(f"proposal {p['proposal_id']} {inv.get('vendor_id')} {inv.get('amount_minor', 0) / 100:.2f} "
            f"{inv.get('currency')} -> step-up; device shows:\n{ch['text']}\n")
        st, res = _post_sig(call, ch, clerk)
        if st != 200:
            raise RuntimeError(f"step-up signature -> {st} {res}")
        eff = res.get("effect", {})
        log(f"clerk held to confirm -> {eff.get('type')} {eff.get('tx_id', '')}")
        if replay:
            st, e = _post_sig(call, ch, clerk)
            log(f"replay of the same signature -> {st} {e.get('error') if isinstance(e, dict) else e}")
            if (st, e.get("error") if isinstance(e, dict) else None) != (403, "nonce_reused"):
                raise RuntimeError(f"replay was not refused: {st} {e}")
        out.append(res)
    return out


def run_agent_s1(*, log: Any = print) -> dict:
    """Stage S1 part 2: WS-E's agent beat on AWS (`python -m agent run --scenario s1`, agent λ in the no-NAT VPC)."""
    import json
    import subprocess
    import sys as _sys

    p = subprocess.run([_sys.executable, "-m", "agent", "run", "--scenario", "s1", "--json"], capture_output=True,
                       text=True, timeout=400)
    if p.returncode != 0:
        raise RuntimeError(f"agent beat failed ({p.returncode}): {p.stderr.strip()[-400:]}")
    try:
        out = json.loads(p.stdout)
    except ValueError:
        out = {"raw": p.stdout.strip()[-800:]}
    log("agent beat done")
    return out


def run_stage_s1(url: str, *, with_agent: bool = True, auto_treasury: bool = True, auto_clerk: bool | None = None,
                 vendor_id: str | None = None) -> dict:
    """The stage S1 beat as one: mandate (device 2/2) -> the real agent pays under it -> device step-up -> replay."""
    clerk, treasury = demo_signers(auto_treasury=auto_treasury, auto_clerk=auto_clerk)
    call = executor_call(url)
    print(f"clerk    {clerk.address}  {clerk.device}\ntreasury {treasury.address}  {treasury.device}\n")
    m = create_mandate(call, clerk, treasury)
    agent = run_agent_s1() if with_agent else None
    props = (agent or {}).get("proposals") or []
    for pr in props:
        what = ("ALLOW (paid under the mandate) " + str(pr.get("tx_id"))) if pr.get("decision") == "allow" else (
            f"{str(pr.get('decision')).upper()} {pr.get('rule_ids')} {pr.get('proposal_id')}")
        print(f"agent PAY {pr.get('vendor_id')} {pr.get('invoice_no')} {pr.get('amount_minor', 0) / 100:.2f} "
              f"{pr.get('currency')} -> {what}")
    if agent is not None and (agent.get("error") or not props):
        raise RuntimeError(f"agent beat produced no proposals: {agent.get('error') or agent.get('final')}")
    challenged = [pr for pr in props if pr.get("decision") == "challenge"]
    if with_agent and vendor_id is None and len({pr.get("vendor_id") for pr in challenged}) == 1:
        vendor_id = challenged[0]["vendor_id"]  # step up exactly what the agent could not pay
    st, led = call("GET", "/ledger", None, "host")
    paid = [t for t in (led.get("txs", []) if st == 200 else []) if (t.get("authorization") or {}).get("kind") == "mandate"]
    print(f"paid under the mandate (ledger): {len(paid)}")
    steps = pay_up(call, clerk, vendor_id=vendor_id)
    st, mm = call("GET", "/mandates/active", None, "host")
    if st == 200:
        print(f"mandate spent {mm['spent_minor'] / 100:.2f} CZK in {mm['count']} payments (the step-up is outside it)")
    return {"mandate": m["mandate_id"], "paid_under_mandate": len(paid), "stepups": len(steps), "agent": agent}


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(description="Device signer: demo S1 with hardware, or sign one challenge.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s1 = sub.add_parser("s1", help="run demo beat S1 in-process with real device signatures (rehearsal)")
    s1.add_argument("--manual-treasury", action="store_true", help="operate the treasury emulator by hand")
    s1.add_argument("--manual-clerk", action="store_true", help="fallback mode: operate the clerk emulator by hand")
    s1.add_argument("--url", default=None, help="drive a running executor (e.g. the AWS regional API) instead")
    s1.add_argument("--with-agent", action="store_true",
                    help="stage S1: mandate on the device, the real agent pays (make agent-s1), device step-up")
    md = sub.add_parser("mandate", help="stage S1 part 1: create the mandate and sign it on the devices (2/2)")
    md.add_argument("--url", default=None)
    pu = sub.add_parser("payup", help="stage S1 part 3: exact-sign every PENDING_SIG proposal on the clerk device")
    pu.add_argument("--url", default=None)
    pu.add_argument("--vendor", default=None, help="only this vendor_id's pending proposals")
    pu.add_argument("--no-replay", action="store_true", help="skip the replay-refused demonstration")
    sc = sub.add_parser("sign", help="GET /challenges/{nonce}, sign on the device, POST /signatures")
    sc.add_argument("nonce")
    sc.add_argument("role", choices=sorted(ROLE_PATHS))
    sc.add_argument("--url", default=None)
    sc.add_argument("--transport", default=None)
    scn = sub.add_parser("scene", help="run demo beat S2 or S3 in-process with device signers (rehearsal)")
    scn.add_argument("name", choices=["s2", "s3"])
    scn.add_argument("--manual-treasury", action="store_true")
    scn.add_argument("--manual-clerk", action="store_true")
    scn.add_argument("--url", default=None, help="the AWS regional API (AwsEnv) instead of in-process")
    sub.add_parser("info", help="show the connected devices and the mode")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.WARNING)
    if a.cmd == "s1" and a.with_agent:
        if not a.url:
            ap.error("--with-agent needs --url (the agent beat runs on AWS)")
        run_stage_s1(a.url, auto_treasury=not a.manual_treasury, auto_clerk=False if a.manual_clerk else None)
        print("\nSTAGE S1 OK" + (" (FALLBACK: EMULATOR CLERK)" if emulator_only() else ""))
    elif a.cmd == "mandate":
        clerk, treasury = demo_signers()
        create_mandate(executor_call(a.url), clerk, treasury)
    elif a.cmd == "payup":
        clerk, _ = demo_signers()
        pay_up(executor_call(a.url), clerk, vendor_id=a.vendor, replay=not a.no_replay)
    elif a.cmd == "s1":
        run_s1(auto_treasury=not a.manual_treasury, auto_clerk=False if a.manual_clerk else None, url=a.url)
        print("\nS1 WITH DEVICES OK" + (" (FALLBACK: EMULATOR CLERK)" if emulator_only() else ""))
    elif a.cmd == "scene":
        run_scene(a.name, auto_treasury=not a.manual_treasury, auto_clerk=False if a.manual_clerk else None,
                  url=a.url)
        print(f"\n{a.name.upper()} WITH DEVICES OK" + (" (FALLBACK: EMULATOR CLERK)" if emulator_only() else ""))
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
