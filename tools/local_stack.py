"""A seeded in-memory executor served over HTTP, so the bank console (port 8501) and the attacker console (port 8502)
share one executor state end to end without AWS. `make local-stack`.

It seeds exactly like the demo (executor.scenes.DemoEnv: registry, enrolled software clerk + treasury, a fake clock),
creates one ACTIVE deterministic mandate, and by default replays scenes S2 and S3 so the bank console opens on a full
story (blocked attacks, a legitimate change gone ACTIVE, accepted hardware approvals). It then serves that same store
over HTTP at a fixed clock, so live attacks from the attacker console and reads from the bank console hit one state.

It does NOT modify executor policy code: it composes executor.handler.dispatch over a pre-seeded MemoryStore, the same
way executor.app does for `make dev`. Development only; the real demo runs on AWS.

    python -m tools.local_stack [--host 127.0.0.1] [--port 8000] [--no-scenes]
"""
import argparse
import dataclasses
import json
import sys
from datetime import timedelta

from executor import handler


def build_env(*, scenes: bool = True, log=print):
    """Seed a DemoEnv, create an ACTIVE mandate, optionally replay S2/S3, and return (settings, store) pinned at a
    fixed clock after the scenes."""
    from executor.scenes import DemoEnv, T0, _z, scene_s2, scene_s3

    env = DemoEnv()
    if scenes:
        try:
            scene_s2(env, log=lambda m: log(f"  seed {m}"))
            scene_s3(env, log=lambda m: log(f"  seed {m}"))
        except AssertionError as e:  # never block the stack from starting
            log(f"  scene replay skipped ({type(e).__name__}: {str(e)[:120]}); seeding a mandate only")
            env = DemoEnv()
            env.active_mandate()
    else:
        env.active_mandate()
    # pin the served clock after the scenes but well inside the mandate validity (T0 + 1 day)
    settings = dataclasses.replace(env.settings, fake_now=_z(T0 + timedelta(seconds=300)))
    return settings, env.store


def build_app(settings, store):
    """A minimal FastAPI app forwarding to handler.dispatch over the given (pre-seeded) store. Mirrors
    executor.app.create_app but never re-seeds and never rebuilds the store."""
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse, Response

    ctx = handler.Context(settings, store)
    handler.configure(settings, store)  # also set the process-wide context
    app = FastAPI(title="AirGap Mandates executor (local stack)", docs_url=None, redoc_url=None)

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    async def catch_all(path: str, request: Request):  # noqa: ANN202
        raw = await request.body()
        body = None
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


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-scenes", action="store_true", help="seed only an ACTIVE mandate (no S2/S3 backdrop)")
    a = ap.parse_args(argv)
    import uvicorn

    settings, store = build_env(scenes=not a.no_scenes)
    print(f"local stack: seeded memory executor on http://{a.host}:{a.port}  (backend=memory, fixed clock)",
          file=sys.stderr)
    uvicorn.run(build_app(settings, store), host=a.host, port=a.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
