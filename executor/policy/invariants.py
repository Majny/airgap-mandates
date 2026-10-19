"""In-mandate invariants I-* (pure functions). CONTRACTS.md §8.1.

Owner: WS-E.
"""
from __future__ import annotations

from typing import Any


def check_mandate(invoice: dict[str, Any], mandate: dict[str, Any] | None, *, now: Any) -> list[str]:
    """Violated ids among I-MANDATE, I-EXP, I-PER, I-BUDGET, I-COUNT."""
    raise NotImplementedError("TODO WS-E")


def check_payee(invoice: dict[str, Any], vendor: dict[str, Any] | None) -> list[str]:
    """['I-PAYEE'] if vendor unknown or iban != vendor.iban."""
    raise NotImplementedError("TODO WS-E")


def check_dup(invoice: dict[str, Any], history: list[dict[str, Any]]) -> list[str]:
    """['I-DUP'] per normalized invoice no or (vendor, amount +-50 bp, date +-3 d)."""
    raise NotImplementedError("TODO WS-E")


def check_split(invoice: dict[str, Any], history: list[dict[str, Any]], mandate: dict[str, Any] | None, *, now: Any) -> list[str]:
    """['I-SPLIT'] if 24 h vendor sum + amount > max_per_payment_minor."""
    raise NotImplementedError("TODO WS-E")


def check_z(invoice: dict[str, Any], history: list[dict[str, Any]]) -> list[str]:
    """['I-Z'] if robust z-score (median/MAD) > 3.5."""
    raise NotImplementedError("TODO WS-E")


def normalize_invoice_no(invoice_no: str) -> str:
    """Uppercase, strip non-alphanumerics, strip leading zeros of numeric runs."""
    raise NotImplementedError("TODO WS-E")
