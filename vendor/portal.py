"""Vendor portal (portal role only): tripwire notices, callback codes, break-glass. CONTRACTS.md v2 §3.1, §4.1 #9/#12/#14,
§6.1.

Owner: WS-D.

The portal writes only its own `portal_notifications` table (airgap-portal). A callback code is stored ONLY as its
SHA-256 (`code_hash`, max 3 attempts); the plaintext goes out through a SIMULATED SMS outbox to the phone registered
at enrolment (in-memory list, plus `.local/sms_outbox.jsonl` when AIRGAP_SMS_OUTBOX_FILE is set). Inbound calls are
never an input. `create_app()` is a small FastAPI app serving portal.html and relaying the vendor's actions to the
executor with `X-Client: vendor_portal`.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from executor.config import iso

MAX_ATTEMPTS = 3
SMS_LABEL = "SIMULATED SMS to registered phone"
SMS_OUTBOX: list[dict[str, Any]] = []  # SIMULATED: in-memory "phone" of every vendor
_HTML = Path(__file__).resolve().parent / "portal.html"
_TABLE = "portal_notifications"
_CHANGE_ID = re.compile(r"chg_[0-9]{1,12}")


def _code_hash(code: str) -> str:
    return hashlib.sha256(code.encode("ascii")).hexdigest()


def _new_code() -> str:
    return f"{secrets.randbelow(10**6):06d}"


def _notif_id(now: datetime) -> str:
    return f"{iso(now)}#{secrets.token_hex(3)}"


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _deliver_sms(phone: str, text: str, *, change_id: str, now: datetime) -> None:
    """SIMULATED SMS: never a real gateway. Optional jsonl copy (git-ignored .local/) for the demo phone view."""
    msg = {"label": SMS_LABEL, "to": phone, "text": text, "change_id": change_id, "at": iso(now)}
    SMS_OUTBOX.append(msg)
    path = os.environ.get("AIRGAP_SMS_OUTBOX_FILE")
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(msg) + "\n")


def send_tripwire(vendor: dict[str, Any], change: dict[str, Any], *, store: Any, settings: Any,
                  now: datetime) -> dict[str, Any]:
    """Tripwire to the contact registered at enrolment, on EVERY change request (§6.1)."""
    row = {
        "ico": vendor["ico"], "notif_id": _notif_id(now), "kind": "tripwire", "change_id": change["change_id"],
        "new_iban_last4": change["new_iban"][-4:], "state": change["state"], "created_at": iso(now),
    }
    store.put(_TABLE, row)
    return row


def issue_callback(vendor: dict[str, Any], change: dict[str, Any], *, store: Any, settings: Any,
                   now: datetime) -> dict[str, Any]:
    """New 6-digit code: only its hash is stored; plaintext via the SIMULATED SMS outbox. Returns {code_exp, notif_id}."""
    code = _new_code()
    code_exp = iso(now + timedelta(seconds=settings.callback_code_ttl_seconds))
    row = {
        "ico": vendor["ico"], "notif_id": _notif_id(now), "kind": "callback", "change_id": change["change_id"],
        "code_hash": _code_hash(code), "code_exp": code_exp, "attempts": 0, "used": False, "created_at": iso(now),
    }
    store.put(_TABLE, row)
    _deliver_sms(vendor.get("phone", ""), f"AirGap: bank details change {change['change_id']} to account "
                 f"..{change['new_iban'][-4:]}. Code {code}. If this was not you, press NOT US in the portal.",
                 change_id=change["change_id"], now=now)
    del code
    return {"code_exp": code_exp, "notif_id": row["notif_id"]}


def _callback_row(ico: str, change_id: str, store: Any) -> dict[str, Any] | None:
    rows = [r for r in store.query(_TABLE, ("ico", ico)) if r.get("kind") == "callback" and r["change_id"] == change_id]
    return max(rows, key=lambda r: r["notif_id"]) if rows else None


def check_callback_code(ico: str, change_id: str, code: str, *, store: Any, settings: Any,
                        now: datetime) -> tuple[bool, int]:
    """(ok, attempts). A wrong or expired code costs one attempt (max 3); a used or exhausted code never matches."""
    row = _callback_row(ico, change_id, store)
    if row is None:
        return (False, 0)
    attempts = int(row.get("attempts", 0))
    if attempts >= MAX_ATTEMPTS or row.get("used"):
        return (False, attempts)
    key = {"ico": ico, "notif_id": row["notif_id"]}
    good = (isinstance(code, str) and len(code) == 6 and code.isdigit()
            and hmac.compare_digest(_code_hash(code), row["code_hash"]) and now < _parse(row["code_exp"]))
    if good:
        if not store.update_if(_TABLE, key, {"used": True, "used_at": iso(now)}, {"attempts": attempts, "used": False}):
            return (False, attempts)
        return (True, attempts)
    store.update_if(_TABLE, key, {"attempts": attempts + 1}, {"attempts": attempts})
    return (False, attempts + 1)


def list_notifications(ico: str, *, store: Any) -> list[dict[str, Any]]:
    """Portal inbox for one vendor, newest first; `code_hash` is never returned."""
    rows = store.query(_TABLE, ("ico", ico), reverse=True)
    return [{k: v for k, v in r.items() if k != "code_hash"} for r in rows]


def create_app(settings: Any, *, store: Any = None, http: Any = None) -> Any:
    """FastAPI app for the vendor portal (SIMULATED supplier side). `http` is an httpx.Client towards the executor
    (default: settings.executor_url); every relayed call carries X-Client: vendor_portal."""
    import httpx
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse, JSONResponse

    app = FastAPI(title="AirGap vendor portal (SIMULATED)")
    client = http or httpx.Client(base_url=settings.executor_url, timeout=10.0)

    def _store() -> Any:
        if store is not None:
            return store
        from executor.store import get_store

        return get_store(settings)

    def _relay(change_id: str, path: str, body: dict[str, Any]) -> JSONResponse:
        if not _CHANGE_ID.fullmatch(change_id):  # never splice a raw path/query into the executor URL
            raise HTTPException(400, "change_id must look like chg_<n>")
        r = client.post(path, json=body, headers={"X-Client": "vendor_portal"})
        try:
            payload = r.json()
        except ValueError:
            payload = {"error": "internal_error", "message": r.text[:200]}
        return JSONResponse(payload, status_code=r.status_code)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return _HTML.read_text(encoding="utf-8")

    @app.get("/api/notifications")
    def notifications(ico: str) -> dict[str, Any]:
        if not (len(ico) == 8 and ico.isdigit()):
            raise HTTPException(400, "ico must be 8 digits")
        return {"ico": ico, "notifications": list_notifications(ico, store=_store())}

    @app.get("/api/sms")
    def sms() -> dict[str, Any]:
        return {"label": SMS_LABEL, "messages": list(reversed(SMS_OUTBOX[-20:]))}

    @app.post("/api/changes/{change_id}/not-us")
    def not_us(change_id: str, body: dict[str, Any]) -> JSONResponse:
        return _relay(change_id, f"/changes/{change_id}/reject", {"reason": str(body.get("reason") or "not us")[:200]})

    @app.post("/api/callbacks/{change_id}")
    def callback(change_id: str, body: dict[str, Any]) -> JSONResponse:
        return _relay(change_id, f"/callbacks/{change_id}",
                      {"code": str(body.get("code", "")),
                       "outcome": "deny" if body.get("outcome") == "deny" else "confirm"})

    @app.post("/api/changes/{change_id}/break-glass")
    def break_glass(change_id: str, body: dict[str, Any]) -> JSONResponse:
        return _relay(change_id, f"/changes/{change_id}/break-glass",
                      {"reason": str(body.get("reason", ""))[:200], "declared_by": str(body.get("declared_by", ""))})

    return app


def main() -> None:
    """`python -m vendor.portal` -> http://127.0.0.1:8100 (dev only; SMS outbox copied to .local/)."""
    import uvicorn

    from executor.config import Settings

    os.environ.setdefault("AIRGAP_SMS_OUTBOX_FILE", ".local/sms_outbox.jsonl")
    uvicorn.run(create_app(Settings.from_env()), host="127.0.0.1", port=8100)


if __name__ == "__main__":
    main()
