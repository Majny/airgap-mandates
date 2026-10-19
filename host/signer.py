"""Signer worker: Trezor Safe 5 over USB (clerk) and trezor-user-env emulator over UDP (treasury, labelled EMULATOR).

EIP-191 ethereum.sign_message; the human holds to confirm exactly the executor-rendered text. CONTRACTS.md v2 §6.
Owner: WS-C.
"""
from __future__ import annotations

from typing import Protocol

from executor.models import Approval


class SignerDriver(Protocol):
    def sign(self, challenge: dict, key_ref: str, timeout: float) -> Approval:
        """Show challenge['text'] on the device (key_ref = derivation path or role), wait for hold-to-confirm,
        return Approval {nonce, address, sig, displayed_text, device}. Raises TimeoutError / RuntimeError."""
        ...

    def get_address(self, key_ref: str) -> str:
        """Lowercase address for enrolment."""
        ...


def get_driver(transport: str | None = None) -> SignerDriver:
    """'usb' (physical Safe 5, default) or 'udp:127.0.0.1:21324' (emulator)."""
    raise NotImplementedError("TODO WS-C")


def sign_challenge(nonce: str, role: str, *, executor_url: str | None = None, transport: str | None = None) -> dict:
    """GET /challenges/{nonce}, driver.sign(), POST /signatures; returns the signature_submit.response."""
    raise NotImplementedError("TODO WS-C")
