"""Enrolment ceremony (ARCHITECTURE §3.3): authenticate_device, GetFirmwareHash, get_address, EIP-191 over ENROLL.

The tool (never the host) sets device = GENUINE | EMULATOR; writes enrolled_signers + enroll leaf. CONTRACTS.md v2 §6.
Owner: WS-C.
"""
from __future__ import annotations

from typing import Any


def enroll(role: str, *, transport: str | None = None, path: str = "m/44'/60'/0'/0/0", settings: Any = None) -> dict:
    """Run the ceremony for one role; returns the enrolled_signers row."""
    raise NotImplementedError("TODO WS-C")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    raise NotImplementedError("TODO WS-C")


if __name__ == "__main__":
    raise SystemExit(main())
