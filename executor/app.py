"""FastAPI wrapper around handler.dispatch() for local dev (`make dev`). Implements CONTRACTS.md §9 local mode.

`app` is created at import time from Settings.from_env(); FastAPI is imported lazily inside create_app.

Owner: WS-A.
"""
from __future__ import annotations

from typing import Any


def create_app(settings: Any = None) -> Any:
    """Build a FastAPI app with a catch-all route forwarding to dispatch()."""
    raise NotImplementedError("TODO WS-A")


app: Any = None  # TODO WS-A: app = create_app() (lazy FastAPI import inside create_app)
