"""F-DOMAIN: sender domain vs vendors.domain (Levenshtein, confusables, TLD/hyphen tricks). CONTRACTS.md §2.1.

Owner: WS-E.
"""
from __future__ import annotations

from typing import Any


def domain_fact(from_domain: str, registry_domain: str) -> dict[str, Any]:
    """F-DOMAIN fact, BLOCK on lookalike, e.g. 'DKIM acme-cz.com != acme.cz'."""
    raise NotImplementedError("TODO WS-E")


def is_lookalike(candidate: str, reference: str) -> bool:
    """True if candidate imitates reference."""
    raise NotImplementedError("TODO WS-E")
