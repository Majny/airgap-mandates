"""Trezor signer: trezorlib ethereum.sign_message on device or emulator (AIRGAP_TREZOR_PATH). CONTRACTS.md §6.

Owner: WS-A.
"""
from __future__ import annotations

from typing import Any


def sign_text(text: str, *, path: str = "m/44'/60'/0'/0/0", transport: str | None = None) -> tuple[str, str]:
    """Return (address lowercase, '0x'+130 hex signature)."""
    raise NotImplementedError("TODO WS-A")


def get_address(*, path: str = "m/44'/60'/0'/0/0", transport: str | None = None) -> str:
    """Address for enrollment."""
    raise NotImplementedError("TODO WS-A")


def sign_challenge(nonce: str, role: str, *, executor_url: str | None = None, transport: str | None = None) -> dict[str, Any]:
    """GET /challenges/{nonce}, sign text, POST /signatures."""
    raise NotImplementedError("TODO WS-A")
