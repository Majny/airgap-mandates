"""Generate 60 attacks + 50 benign tasks (Qwen-assisted). CONTRACTS.md §1.

Owner: WS-D.
"""
from __future__ import annotations

from typing import Any


def generate(out_dir: str, *, seed: int = 42) -> list[dict[str, Any]]:
    """Write attack/benign task files."""
    raise NotImplementedError("TODO WS-D")
