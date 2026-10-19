"""AgentPayBench runner, arms A0-A3. `python -m bench.run_bench --out bench/results`. CONTRACTS.md §1.

Owner: WS-D.
"""
from __future__ import annotations

from typing import Any


def run(arm: str, tasks: list[dict[str, Any]], *, out: str) -> list[dict[str, Any]]:
    """Run tasks on one arm, write jsonl."""
    raise NotImplementedError("TODO WS-D")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    raise NotImplementedError("TODO WS-D")


if __name__ == "__main__":
    raise SystemExit(main())
