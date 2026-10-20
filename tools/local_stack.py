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
import os
import sys
from datetime import timedelta

from executor import handler

DELTA_VENDOR = "ven_77665546"
DELTA_OVERCAP_MINOR = 12_500_050  # 125,000.50 CZK, over the 80,000 per-payment cap -> waits for a human on the Trezor


def seed_pending_overcap(call, now, *, vendor_id=DELTA_VENDOR, amount_minor=DELTA_OVERCAP_MINOR, data_dir=None):
    """Create one over-cap payment left PENDING_SIG (challenge purpose PAY), so the 'malware on the clerk PC' demo
    (attack h, host.implant) has a legitimate payment waiting for approval. The attacker cannot create this; the normal
    day did. Returns the proposal_id, or None if it could not be created. Idempotent-ish: skips if one already waits."""
    from executor import e2e

    st, r = call("GET", "/proposals?status=PENDING_SIG", None, "host")
    existing = [p for p in r.get("proposals", []) if p.get("vendor_id") == vendor_id] if st == 200 else []
    if existing:
        return existing[0]["proposal_id"]
    inv = {"vendor_id": vendor_id, "invoice_no": "DS-2026-0777", "issue_date": now.strftime("%Y-%m-%d"),
           "due_date": now.strftime("%Y-%m-%d"), "amount_minor": amount_minor, "currency": "CZK", "reason_code": "DUE"}
    try:
        cited = e2e.cite(call, inv, data_dir=data_dir) if data_dir else e2e.cite(call, inv)
    except Exception:  # noqa: BLE001 - never block the stack from starting
        return None
    st, r = call("POST", "/proposals", {"invoice": cited, "hints": []}, "tools")
    if st != 201 or (r.get("decision", {}) if isinstance(r, dict) else {}).get("decision") != "challenge":
        return None
    return r["proposal"]["proposal_id"]


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
    # test/visual only: enrol the deterministic software clerk so the bank console's "Approve on Trezor" can sign
    # without a physical device (loopback stack only; never AWS). Gated so a real demo is never polluted.
    if os.environ.get("AIRGAP_TEST_SOFTWARE_CLERK") == "1":
        from executor.store import seed
        from host.signer import software_clerk_account
        acct = software_clerk_account()
        seed.enroll_signer(env.store, acct.address, "clerk", device="GENUINE",
                           label="clerk (software key, test)", settings=env.settings)
        log(f"  enrolled software clerk (test) {acct.address}")
    # pin the served clock after the scenes but well inside the mandate validity (T0 + 1 day)
    pinned_now = T0 + timedelta(seconds=300)
    settings = dataclasses.replace(env.settings, fake_now=_z(pinned_now))
    pinned_call = lambda m, p, b, who: handler.dispatch(m, p, None, b, principal=who,  # noqa: E731
                                                        ctx=handler.Context(settings, env.store))
    pid = seed_pending_overcap(pinned_call, pinned_now, data_dir=env.settings.data_dir)
    log(f"  seed pending over-cap payment (Delta) -> {pid or 'skipped'}")
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
