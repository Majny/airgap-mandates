"""host/signer.py logic that needs no device (always runs in CI). Owner: WS-C."""
import hashlib

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from executor.config import Settings
from executor.sig import verify_eip191
from host import signer


def _challenge(text: str, **kw) -> dict:
    return {"nonce": "0C55A1E7", "text": text, "text_sha256": hashlib.sha256(text.encode()).hexdigest(), **kw}


def test_challenge_text_checks_ascii_and_hash():
    assert signer.challenge_text(_challenge("AG1/DEMO PAY 1\nX")) == "AG1/DEMO PAY 1\nX"
    with pytest.raises(ValueError):
        signer.challenge_text(_challenge("AG1/DEMO PAY 1\nPŘ"))
    bad = _challenge("AG1/DEMO PAY 1\nX")
    bad["text"] = "AG1/DEMO PAY 2\nX"
    with pytest.raises(ValueError):
        signer.challenge_text(bad)


def test_role_paths_distinct_and_resolvable():
    assert signer.resolve_path("clerk") != signer.resolve_path("treasury")
    assert signer.resolve_path("m/44'/60'/0'/0/7") == "m/44'/60'/0'/0/7"
    with pytest.raises(ValueError):
        signer.resolve_path("cfo")


def test_usb_never_matches_the_emulator():
    assert signer.TrezorDriver("usb").path == "webusb" == signer.TrezorDriver(None).path
    assert signer.TrezorDriver(signer.EMULATOR_PATH).path == signer.EMULATOR_PATH


def test_one_switch_fallback_mode():
    assert not signer.emulator_only(Settings.from_env({}))
    assert signer.emulator_only(Settings.from_env({"AIRGAP_TREZOR_PATH": "udp:127.0.0.1:21324"}))


class FakeDriver:
    """Software key standing in for a device: sign_text must return (address, sig)."""

    def __init__(self, emulator: bool = True):
        self.acct, self.is_emulator, self.calls = Account.create(), emulator, 0
        self.device_label = "EMULATOR" if emulator else "GENUINE"

    def get_address(self, key_ref):
        return self.acct.address.lower()

    def info(self):
        return {"model": "Safe 3"}

    def sign_text(self, text, key_ref, timeout=None):
        self.calls += 1
        return self.acct.address.lower(), "0x" + self.acct.sign_message(encode_defunct(text=text)).signature.hex()


def test_device_signer_replays_captured_signature_without_device():
    drv = FakeDriver()
    s = signer.DeviceSigner(drv, "clerk", log=lambda *_: None)
    a = s.sign_message(encode_defunct(text="AG1/DEMO PAY 4\nX")).signature
    b = s.sign_message(encode_defunct(text="AG1/DEMO PAY 4\nX")).signature
    assert a == b and drv.calls == 1
    assert verify_eip191("AG1/DEMO PAY 4\nX", "0x" + a.hex()) == s.address


def test_auto_confirm_refused_for_physical_device():
    with pytest.raises(ValueError):
        signer.DeviceSigner(FakeDriver(emulator=False), "clerk", auto_confirm=True, log=lambda *_: None)
