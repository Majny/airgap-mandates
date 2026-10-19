"""Vendor portal: tripwire, hash-only callback codes (3 attempts), SIMULATED SMS, FastAPI relay. Owner: WS-D.

CONTRACTS §3.1 (portal_notifications: no plaintext code), §4.1 #9/#12/#14 (vendor-portal-only endpoints).
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from executor.config import Settings
from tests.fakes import FakeStore
from vendor import portal

T0 = datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc)
VENDOR = {"vendor_id": "ven_87654321", "ico": "87654321", "name": "Beta Servis a.s.", "phone": "+420 600 000 002"}
CHANGE = {"change_id": "chg_7", "new_iban": "CZ7501000000001155443322", "state": "CALLBACK_PENDING"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch):
    portal.SMS_OUTBOX.clear()
    monkeypatch.delenv("AIRGAP_SMS_OUTBOX_FILE", raising=False)
    yield
    portal.SMS_OUTBOX.clear()


def _code() -> str:
    return re.search(r"Code (\d{6})", portal.SMS_OUTBOX[-1]["text"]).group(1)


def _issue(store: FakeStore, now: datetime = T0) -> str:
    portal.issue_callback(VENDOR, CHANGE, store=store, settings=Settings(), now=now)
    return _code()


def test_issue_callback_stores_hash_only_and_sends_simulated_sms():
    store = FakeStore()
    out = portal.issue_callback(VENDOR, CHANGE, store=store, settings=Settings(), now=T0)
    code = _code()
    assert out["code_exp"] == "2026-10-19T12:10:00Z" and set(out) == {"code_exp", "notif_id"}
    (row,) = store.scan("portal_notifications")
    assert row["kind"] == "callback" and row["attempts"] == 0 and row["change_id"] == "chg_7"
    assert row["code_hash"] == hashlib.sha256(code.encode()).hexdigest()
    assert code not in json.dumps(row)
    (sms,) = portal.SMS_OUTBOX
    assert sms["label"] == "SIMULATED SMS to registered phone" and sms["to"] == VENDOR["phone"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z#[0-9a-f]{6}", row["notif_id"])


def test_check_code_attempts_and_single_use():
    store, s = FakeStore(), Settings()
    code = _issue(store)
    wrong = f"{(int(code) + 1) % 10**6:06d}"
    assert portal.check_callback_code("87654321", "chg_7", wrong, store=store, settings=s, now=T0) == (False, 1)
    assert portal.check_callback_code("87654321", "chg_7", "12ab56", store=store, settings=s, now=T0) == (False, 2)
    assert portal.check_callback_code("87654321", "chg_7", code, store=store, settings=s, now=T0) == (True, 2)
    assert portal.check_callback_code("87654321", "chg_7", code, store=store, settings=s, now=T0) == (False, 2)
    assert portal.check_callback_code("87654321", "chg_99", code, store=store, settings=s, now=T0) == (False, 0)


def test_three_failures_exhaust_the_code():
    store, s = FakeStore(), Settings()
    code = _issue(store)
    wrong = f"{(int(code) + 1) % 10**6:06d}"
    for i in (1, 2, 3):
        assert portal.check_callback_code("87654321", "chg_7", wrong, store=store, settings=s, now=T0) == (False, i)
    assert portal.check_callback_code("87654321", "chg_7", code, store=store, settings=s, now=T0) == (False, 3)
    assert store.scan("portal_notifications")[0]["attempts"] == 3


def test_expired_code_is_a_failed_attempt():
    store, s = FakeStore(), Settings()
    code = _issue(store)
    late = T0 + timedelta(seconds=s.callback_code_ttl_seconds)
    assert portal.check_callback_code("87654321", "chg_7", code, store=store, settings=s, now=late) == (False, 1)


def test_latest_code_wins_after_reissue(monkeypatch: pytest.MonkeyPatch):
    codes = iter(["111111", "222222"])
    monkeypatch.setattr(portal, "_new_code", lambda: next(codes))
    store, s = FakeStore(), Settings()
    first = _issue(store)
    second = _issue(store, T0 + timedelta(seconds=1))
    assert (first, second) == ("111111", "222222")
    assert portal.check_callback_code("87654321", "chg_7", first, store=store, settings=s,
                                      now=T0 + timedelta(seconds=2)) == (False, 1)
    assert portal.check_callback_code("87654321", "chg_7", second, store=store, settings=s,
                                      now=T0 + timedelta(seconds=2))[0] is True


def test_tripwire_and_list_notifications_hide_code_hash():
    store = FakeStore()
    portal.send_tripwire(VENDOR, CHANGE, store=store, settings=Settings(), now=T0)
    _issue(store, T0 + timedelta(seconds=1))
    notes = portal.list_notifications("87654321", store=store)
    assert [n["kind"] for n in notes] == ["callback", "tripwire"]
    assert all("code_hash" not in n for n in notes)
    assert notes[1]["new_iban_last4"] == "3322" and portal.list_notifications("12345678", store=store) == []


def test_sms_outbox_file_is_opt_in(tmp_path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "sms_outbox.jsonl"
    monkeypatch.setenv("AIRGAP_SMS_OUTBOX_FILE", str(path))
    _issue(FakeStore())
    (line,) = path.read_text().splitlines()
    assert json.loads(line)["label"].startswith("SIMULATED SMS")


def _app(store: FakeStore):
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        if req.url.path.endswith("/callbacks/chg_7") and json.loads(req.content)["code"] == "000000":
            return httpx.Response(403, json={"error": "callback_code_invalid", "message": "bad"})
        return httpx.Response(200, json={"change_id": "chg_7", "state": "REJECTED"})

    http = httpx.Client(base_url="http://executor.test", transport=httpx.MockTransport(handler))
    return TestClient(portal.create_app(Settings(), store=store, http=http)), seen


def test_app_serves_page_and_inbox():
    store = FakeStore()
    portal.send_tripwire(VENDOR, CHANGE, store=store, settings=Settings(), now=T0)
    client, _ = _app(store)
    page = client.get("/")
    assert page.status_code == 200 and "SIMULATED" in page.text and "/api/callbacks/" in page.text
    assert page.text.isascii()
    assert client.get("/api/notifications", params={"ico": "8765"}).status_code == 400
    body = client.get("/api/notifications", params={"ico": "87654321"}).json()
    assert [n["kind"] for n in body["notifications"]] == ["tripwire"]
    _issue(store)
    sms = client.get("/api/sms").json()
    assert sms["label"].startswith("SIMULATED") and len(sms["messages"]) == 1


def test_app_relays_with_vendor_portal_client_header():
    client, seen = _app(FakeStore())
    r = client.post("/api/changes/chg_7/not-us", json={"reason": "not us"})
    assert r.status_code == 200 and r.json()["state"] == "REJECTED"
    r = client.post("/api/callbacks/chg_7", json={"code": "000000", "outcome": "confirm"})
    assert r.status_code == 403 and r.json()["error"] == "callback_code_invalid"
    client.post("/api/changes/chg_7/break-glass", json={"reason": "lost keys", "declared_by": "office@beta.example"})
    assert [q.url.path for q in seen] == ["/changes/chg_7/reject", "/callbacks/chg_7", "/changes/chg_7/break-glass"]
    assert all(q.headers["X-Client"] == "vendor_portal" for q in seen)
    assert json.loads(seen[0].content) == {"reason": "not us"}
    assert json.loads(seen[2].content) == {"reason": "lost keys", "declared_by": "office@beta.example"}


@pytest.mark.parametrize("bad", ["chg_7%3Fx=1", "chg_7%23", "..", "ven_1", "chg_"])
def test_app_refuses_non_change_ids_without_relaying(bad: str):
    client, seen = _app(FakeStore())
    for path in (f"/api/changes/{bad}/not-us", f"/api/callbacks/{bad}", f"/api/changes/{bad}/break-glass"):
        assert client.post(path, json={"code": "123456", "reason": "x"}).status_code in (400, 404, 405)
    assert seen == []
