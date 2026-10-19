"""Offline audit verifier (`python -m tools.verify_audit bundle.json [--replay] [--receipt r.json]`).

CONTRACTS.md v2 §7.5. Owner: WS-B.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Report:
    ok: bool
    problems: list[str] = field(default_factory=list)
    checked: dict[str, int] = field(default_factory=dict)


def verify(bundle: dict[str, Any], *, replay: bool = True) -> Report:
    """Leaf hashes, seq gaps, roots vs checkpoints, inclusion + consistency, log/W1/W2 note signatures,
    re-render + signer recovery for every accepted signature, decide() replay at policy_hash (S12),
    2/2 distinctness, cooling-off ordering, ledger <-> execution leaves."""
    raise NotImplementedError("TODO WS-B")


def main(argv: list[str] | None = None) -> int:
    """CLI; exit 1 on any problem."""
    raise NotImplementedError("TODO WS-B")


if __name__ == "__main__":
    raise SystemExit(main())
