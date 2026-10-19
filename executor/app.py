"""FastAPI wrapper around handler.dispatch() for local dev (`make dev`). Implements CONTRACTS.md §9 local mode.

`app` is created at import time from Settings.from_env(); FastAPI is imported lazily inside create_app.
Local dev only: the caller principal comes from the informational X-Client header (no IAM locally); with no header
the caller checks are skipped. memory backend seeds the canonical demo registry (executor.store.seed).

Owner: WS-A.
"""
from __future__ import annotations

import json
from typing import Any

from executor import handler
from executor.config import Settings


def create_app(settings: Any = None) -> Any:
    """Build a FastAPI app with a catch-all route forwarding to dispatch()."""
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse, Response

    settings = settings or Settings.from_env()
    ctx = handler.configure(settings)
    if settings.backend == "memory":
        from executor.store import seed

        seed.seed_demo(ctx.store)
    app = FastAPI(title="AirGap Mandates executor (local dev)", docs_url=None, redoc_url=None)

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    async def catch_all(path: str, request: Request) -> Any:
        raw = await request.body()
        body: Any = None
        if raw:
            if "json" in request.headers.get("content-type", "application/json"):
                try:
                    body = json.loads(raw)
                except ValueError:
                    return JSONResponse({"error": "invalid_request", "message": "body is not JSON"}, 400)
            else:
                body = raw
        principal = request.headers.get("x-client") or None
        status, out = handler.dispatch(request.method, "/" + path, dict(request.query_params), body,
                                       dict(request.headers), principal=principal, ctx=ctx)
        if isinstance(out, bytes):
            return Response(bytes(out), status, media_type=getattr(out, "content_type", "text/plain"))
        return JSONResponse(out, status)

    return app


def _lazy_app() -> Any:
    try:
        return create_app()
    except ImportError:  # fastapi not installed (Lambda image)
        return None


app: Any = _lazy_app()
