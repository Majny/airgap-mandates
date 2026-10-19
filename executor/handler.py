"""Lambda entry point + single router. Implements CONTRACTS.md §4 (all endpoints), §4.3 order, §4.4 error mapping.

Owner: WS-A.
"""
from __future__ import annotations

from typing import Any


def dispatch(method: str, path: str, query: dict[str, str] | None = None, body: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any] | bytes]:
    """Route a request to the endpoint implementation; ApiError -> (status, error body). Used by Lambda, FastAPI app, bench and tests."""
    raise NotImplementedError("TODO WS-A")


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """API Gateway HTTP API (payload v2) adapter around dispatch()."""
    raise NotImplementedError("TODO WS-A")
