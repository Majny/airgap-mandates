"""Payee-change FSM v2 guards end to end over the real MemoryStore, audit log and challenge issuer (CONTRACTS §6.1,
§3.1, §7.2). Owner: WS-D.

verify_vc and compute() are replaced by deterministic fakes (machine references them as module attributes); one
integration test uses the real modules and skips while they are unavailable; one test drives the flow through
executor.handler.dispatch with real EIP-191 signatures.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from executor.change import machine as M
from executor.config import Settings, iso
from executor.errors import ApiError
from executor.facts import compute as real_compute
from executor.models import ChangeEvent, ChangeState
from executor.store import KEY_SCHEMA
from executor.store.memory import MemoryStore
from vendor import portal

S, E = ChangeState, ChangeEvent
T0 = datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc)
CLERK = "0x" + "11" * 20
TREASURY = "0x" + "22" * 20
NEW_IBAN = "CZ2003000000002001234567"
PINS = [{"issuer_class": c, "iss": f"https://{c}.example", "jwk_thumbprint": f"tp-{c}",
         "pinned_at": "2024-03-01T00:00:00Z"} for c in ("supplier-erp", "supplier-bank", "registry")]
ACME = {
    "vendor_id": "ven_12345678", "ico": "12345678", "name": "ACME s.r.o.", "domain": "acme.cz",
    "iban": "CZ6508000000192000145399", "country": "CZ", "phone": "+420 600 000 001",
    "contact_email": "finance@acme.example", "registered_since": "2024-03-01", "in_network": True,
    "issuer_pins": PINS, "iban_history": [{"iban": "CZ6508000000192000145399", "from": "2024-03-01", "to": None,
                                           "change_id": None}],
}
BETA = {
    "vendor_id": "ven_87654321", "ico": "87654321", "name": "Beta Servis a.s.", "domain": "betaservis.cz",
    "iban": "CZ6203000000000123456789", "country": "CZ", "phone": "+420 600 000 002",
    "contact_email": "office@betaservis.example", "registered_since": "2024-05-01", "in_network": False,
    "issuer_pins": [], "iban_history": [{"iban": "CZ6203000000000123456789", "from": "2024-05-01", "to": None,
                                         "change_id": None}],
}
VOP_OK = {"id": "F-VOP", "kind": "F", "severity": "INFO", "label": "VoP", "display_line": "VOP MTCH"}
DOMAIN_BLOCK = {"id": "F-DOMAIN", "kind": "F", "severity": "BLOCK", "label": "lookalike",
                "display_line": "DOMAIN LOOKALIKE"}


class RecordingStore(MemoryStore):
    """MemoryStore that records committed transactions touching `changes` / `registry` (the activation tx)."""

    def __init__(self, settings: Any) -> None:
        super().__init__(settings)
        self.transactions: list[list[Any]] = []

    def transact(self, ops: list[Any], client_request_token: str | None = None) -> bool:
        ok = super().transact(ops, client_request_token)
        if ok and any(op.table in ("changes", "registry") for op in ops):
            self.transactions.append(list(ops))
        return ok

    def all_rows(self) -> list[tuple[str, dict]]:
        return [(t, r) for t in KEY_SCHEMA for r in self.scan(t)]


class AuditView:
    """Reads the leaves the real audit log wrote to the store (logs `audit` and `attest`)."""

    def __init__(self, store: MemoryStore) -> None:
        self.store = store

    @property
    def leaves(self) -> list[dict]:
        return [json.loads(r["event"]) for log_id in ("audit", "attest")
                for r in self.store.query("audit", ("log_id", log_id))]

    def of_type(self, type: str, subject_id: str | None = None) -> list[dict]:
        return [x for x in self.leaves if x["type"] == type and (subject_id is None or x["subject_id"] == subject_id)]

    def events(self, subject_id: str | None = None) -> list[str]:
        """change_event kinds in order."""
        return [x["data"]["event"] for x in self.of_type("change_event", subject_id)]

    def transitions(self, subject_id: str | None = None) -> list[tuple[str | None, str, str]]:
        return [(x["data"]["from"], x["data"]["to"], x["data"]["event"])
                for x in self.of_type("state_transition", subject_id)]


def _fact(fid: str, sev: str, line: str) -> dict:
    return {"id": fid, "kind": "F", "severity": sev, "label": fid, "display_line": line}


class Env:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, settings: Settings):
        self.settings = settings
        self.store = RecordingStore(settings)
        self.audit = AuditView(self.store)
        self.extra: list[dict] = [VOP_OK]
        monkeypatch.setattr(M._compute, "compute", self.fake_compute)
        monkeypatch.setattr(M._vc, "verify_vc", self.fake_verify)
        portal.SMS_OUTBOX.clear()
        for v in (ACME, BETA):
            self.store.put("registry", json.loads(json.dumps(v)))
        self.store.put("registry", {"vendor_id": M.META_KEY, "registry_version": 1, "registry_hash": "0" * 64})

    # -- fakes ---------------------------------------------------------------------------------------------
    def fake_compute(self, subject: dict, state: dict, now: datetime) -> dict:
        payee, change = state["payee"], state.get("change") or {}  # the handler's first pass has change None
        in_net, bg = bool(payee.get("in_network")), bool(change.get("break_glass"))
        k = len({r["issuer_class"] for r in state.get("attest_results") or [] if r["ok"]})
        if bg:
            facts = [_fact("F-ATTEST", "INFO", "ATT BREAK-GLASS")]
        elif not in_net:
            facts = [_fact("F-ATTEST", "INFO", "ATT OFF-NETWORK")]
        else:
            facts = [_fact("F-ATTEST", "INFO", "ATT 2/3 ERP BANK") if k >= 2 else _fact("F-ATTEST", "BLOCK",
                                                                                         f"ATT {k}/3")]
        if not in_net or bg:
            ok = (change.get("callback") or {}).get("status") == "confirmed"
            facts.append(_fact("F-CALLBACK", "INFO", "CALLBACK OK") if ok else _fact("F-CALLBACK", "BLOCK",
                                                                                     "CALLBACK MISSING"))
        ordered = real_compute.order_facts(facts + [dict(f) for f in self.extra])
        return {"subject_id": subject.get("subject_id", ""), "computed_at": "x", "facts": ordered,
                "facts_digest": real_compute.facts_digest(ordered), "snapshots": {},
                "max_severity": real_compute.max_severity(ordered)}

    @staticmethod
    def fake_verify(vc: str, change: dict, *, pins: list, now: datetime, revoked=None) -> dict:
        kind, _, val = vc.replace("~", ":").partition(":")  # "~" form passes vc_submit.request
        sha = hashlib.sha256(vc.encode()).hexdigest()
        if kind == "ok":
            return {"ok": True, "issuer_class": val, "iss": f"https://{val}.example", "error": None,
                    "disclosed": {"iban": change["new_iban"], "ico": change["vendor_ico"], "legal_name": "ACME"},
                    "vc_sha256": sha}
        return {"ok": False, "issuer_class": None, "iss": None, "error": val, "disclosed": {}, "vc_sha256": sha}

    # -- helpers -------------------------------------------------------------------------------------------
    def create(self, vendor: dict = ACME, new_iban: str = NEW_IBAN, now: datetime = T0) -> dict:
        v = self.store.get("registry", {"vendor_id": vendor["vendor_id"]})
        req = {"vendor_id": v["vendor_id"], "new_iban": new_iban, "hints": []}
        fs = M.compute_change_facts(req, v, store=self.store, settings=self.settings, now=now)
        return M.create(req, fs, v, store=self.store, settings=self.settings, now=now)

    def tr(self, change: dict, event: ChangeEvent, payload: dict | None = None, now: datetime = T0, **kw) -> dict:
        return M.transition(change["change_id"], event, payload=payload, store=self.store, settings=self.settings,
                            now=now, **kw)

    def sign(self, change: dict, role: str, address: str, nonce: str | None = None, now: datetime = T0) -> dict:
        row = self.get(change)
        nonce = nonce or (row["pending_challenge"] or {}).get("nonce", "00000000")
        return M.on_signature(row, role=role, signer_address=address, nonce=nonce, store=self.store,
                              settings=self.settings, now=now)

    def get(self, change: dict) -> dict:
        return self.store.get("changes", {"change_id": change["change_id"]})

    def advance(self, change: dict, now: datetime) -> dict:
        return M.advance(self.get(change), store=self.store, settings=self.settings, now=now)

    def code(self, change_id: str) -> str:
        msgs = [m for m in portal.SMS_OUTBOX if m["change_id"] == change_id]
        return re.search(r"Code (\d{6})", msgs[-1]["text"]).group(1)

    def cooling(self, now: datetime = T0) -> dict:
        ch = self.create(now=now)
        self.tr(ch, E.VC_RECEIVED, {"vc": "ok:supplier-erp"}, now=now)
        return self.tr(ch, E.VC_RECEIVED, {"vc": "ok:supplier-bank"}, now=now)

    def sig_clerk(self) -> dict:
        ch = self.cooling()
        return self.advance(ch, T0 + timedelta(seconds=self.settings.cooling_seconds))


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> Env:
    return Env(monkeypatch, Settings())


def _wrong(code: str) -> str:
    return f"{(int(code) + 1) % 10**6:06d}"


def _err(fn, *a, **kw) -> str:
    with pytest.raises(ApiError) as ei:
        fn(*a, **kw)
    return ei.value.code


# --------------------------------------------------------------------------- create


def test_create_rejected_on_domain_block_no_challenge(env: Env):
    env.extra = [DOMAIN_BLOCK, VOP_OK]
    ch = env.create()
    assert ch["state"] == "REJECTED" and M.create_decision(ch) == "deny"
    assert ch["pending_challenge"] is None and env.store.scan("nonces") == []
    assert env.audit.of_type("challenge") == []
    assert env.audit.transitions(ch["change_id"]) == [(None, "REJECTED", "CREATE")]
    assert "F-DOMAIN" in ch["history"][0]["reason"]
    assert [n["kind"] for n in portal.list_notifications("12345678", store=env.store)] == ["tripwire"]


def test_create_in_network_pending_attest_with_tripwire(env: Env):
    ch = env.create()
    assert ch["change_id"] == "chg_1" and ch["change_no"] == 1
    assert ch["state"] == "PENDING_ATTEST" and M.create_decision(ch) == "pending"
    assert ch["aud"] == "AG1/DEMO/changes/chg_1" and re.fullmatch(r"[0-9a-f]{32}", ch["change_nonce"])
    assert ch["old_iban"] == ACME["iban"] and ch["old_since"] == "2024-03-01"
    assert ch["expires_at"] == "2026-10-19T13:00:00Z" and ch["tripwire_sent_at"] == "2026-10-19T12:00:00Z"
    assert ch["callback"] == {"status": "none", "code_exp": None, "attempts": 0}
    att = next(f for f in ch["facts"] if f["id"] == "F-ATTEST")
    assert att["severity"] == "BLOCK"
    notes = portal.list_notifications("12345678", store=env.store)
    assert [(n["kind"], n["change_id"]) for n in notes] == [("tripwire", "chg_1")]
    assert env.audit.events("chg_1") == ["facts_computed", "tripwire_sent"]
    assert env.audit.transitions("chg_1") == [(None, "PENDING_ATTEST", "CREATE")]
    assert portal.SMS_OUTBOX == []  # no callback in network
    assert env.create(new_iban="CZ7501000000001155443322")["change_id"] == "chg_2"


def test_create_rejects_same_iban(env: Env):
    assert _err(env.create, new_iban=ACME["iban"]) == "invalid_request"


# --------------------------------------------------------------------------- attestations


def test_one_vc_stays_pending_attest_no_challenge(env: Env):
    ch = env.create()
    out = env.tr(ch, E.VC_RECEIVED, {"vc": "ok:supplier-erp"})
    assert out["state"] == "PENDING_ATTEST" and out["attest_count"] == 1
    assert next(f for f in out["facts"] if f["id"] == "F-ATTEST")["severity"] == "BLOCK"
    assert out["pending_challenge"] is None and env.store.scan("nonces") == []
    # a second VC of the SAME class does not count
    out = env.tr(ch, E.VC_RECEIVED, {"vc": "ok:supplier-erp"})
    assert out["state"] == "PENDING_ATTEST" and out["attest_count"] == 1
    # lazy advance never issues a challenge in PENDING_ATTEST
    assert env.advance(ch, T0 + timedelta(minutes=30))["state"] == "PENDING_ATTEST"
    assert env.audit.of_type("challenge") == []
    rows = env.store.query("attestations", ("change_id", ch["change_id"]))
    assert [(r["n"], r["sk"]) for r in rows] == [(1, "vc#000001"), (2, "vc#000002")]
    assert all(re.fullmatch(r"[0-9a-f]{64}", r["commitment"]) for r in rows)
    att_leaves = env.audit.of_type("attestation")
    assert att_leaves and all(x["log_id"] == "attest" and "iban" not in x["data"] for x in att_leaves)


def test_two_distinct_vcs_to_cooling(env: Env):
    ch = env.cooling()
    assert ch["state"] == "COOLING" and ch["attest_count"] == 2
    assert ch["not_before"] == "2026-10-19T12:00:20Z"
    assert next(f for f in ch["facts"] if f["id"] == "F-ATTEST")["display_line"] == "ATT 2/3 ERP BANK"
    assert [a["issuer_class"] for a in ch["attestations"]] == ["supplier-erp", "supplier-bank"]
    assert env.audit.events(ch["change_id"])[-3:] == ["vc_received", "vc_received", "cooling_scheduled"]
    assert env.audit.transitions(ch["change_id"])[-1] == ("PENDING_ATTEST", "COOLING", "VC_RECEIVED")


def test_bad_vc_rejected_with_code(env: Env):
    ch = env.create()
    assert _err(env.tr, ch, E.VC_RECEIVED, {"vc": "bad:kb_jwt_invalid"}) == "kb_jwt_invalid"
    assert _err(env.tr, ch, E.VC_RECEIVED, {"vc": "bad:issuer_not_pinned"}) == "issuer_not_pinned"
    assert _err(env.tr, ch, E.VC_RECEIVED, {"vc": "bad:binding_mismatch"}) == "attestation_insufficient"
    row = env.get(ch)
    assert row["state"] == "PENDING_ATTEST" and row["attest_count"] == 0
    assert env.audit.events(ch["change_id"]).count("vc_rejected") == 3
    assert [r["verified"] for r in env.store.query("attestations", ("change_id", ch["change_id"]))] == [False] * 3


def test_vc_for_off_network_vendor_requires_break_glass(env: Env):
    ch = env.create(BETA, new_iban="CZ7501000000001155443322")
    assert ch["state"] == "CALLBACK_PENDING"
    with pytest.raises(M.ForbiddenTransition):
        env.tr(ch, E.VC_RECEIVED, {"vc": "ok:supplier-erp"})  # no VC_RECEIVED edge out of CALLBACK_PENDING
    acme = env.create()
    env.store.update_if("registry", {"vendor_id": ACME["vendor_id"]}, {"issuer_pins": []}, {})
    assert _err(env.tr, acme, E.VC_RECEIVED, {"vc": "ok:supplier-erp"}) == "break_glass_required"


# --------------------------------------------------------------------------- signatures and cooling


def test_signature_in_pending_attest_is_attestation_insufficient(env: Env):
    ch = env.create()
    assert _err(env.sign, ch, "clerk", CLERK, "ABCDEF01") == "attestation_insufficient"


def test_signature_in_cooling_is_cooling_off(env: Env):
    ch = env.cooling()
    assert _err(env.sign, ch, "clerk", CLERK, "ABCDEF01", now=T0 + timedelta(seconds=5)) == "cooling_off"


def test_advance_before_not_before_is_noop_then_sig_clerk(env: Env):
    ch = env.cooling()
    before = env.advance(ch, T0 + timedelta(seconds=19))
    assert before["state"] == "COOLING" and before["pending_challenge"] is None
    assert env.store.scan("nonces") == []
    after = env.advance(ch, T0 + timedelta(seconds=20))
    assert after["state"] == "SIG_CLERK"
    pc = after["pending_challenge"]
    assert pc["role"] == "clerk" and pc["purpose"] == "CHG" and re.fullmatch(r"[0-9A-F]{8}", pc["nonce"])
    assert "ROLE CLERK 1/2" in pc["text"] or "CLERK 1/2" in pc["text"]
    row = env.store.get("nonces", {"nonce": pc["nonce"]})
    assert row["used"] is False and row["text"] == pc["text"] and len(row["nonce_secret"]) == 32
    assert "nonce_secret" not in pc
    assert env.audit.of_type("challenge")[-1]["data"]["nonce"] == pc["nonce"]
    again = env.advance(ch, T0 + timedelta(seconds=40))  # idempotent
    assert again["pending_challenge"]["nonce"] == pc["nonce"] and len(env.store.scan("nonces")) == 1


def test_dual_control_to_active_updates_registry(env: Env):
    ch = env.sig_clerk()
    t1 = T0 + timedelta(seconds=30)
    assert _err(env.sign, ch, "treasury", TREASURY, now=t1) == "sigs_insufficient"  # treasury before clerk
    clerk_nonce = env.get(ch)["pending_challenge"]["nonce"]
    assert _err(env.sign, ch, "clerk", CLERK, "00000000", now=t1) == "state_conflict"  # not the pending nonce
    out = env.sign(ch, "clerk", CLERK, now=t1)
    assert out["state"] == "SIG_TREASURY"
    pc = out["pending_challenge"]
    assert pc["role"] == "treasury" and pc["nonce"] != clerk_nonce and "2/2" in pc["text"]
    assert out["signatures"] == [{"role": "clerk", "address": CLERK, "nonce": clerk_nonce,
                                  "signed_at": "2026-10-19T12:00:30Z"}]
    assert _err(env.sign, ch, "treasury", CLERK, now=t1) == "sigs_insufficient"  # same address
    assert _err(env.sign, ch, "clerk", CLERK, now=t1) == "sigs_insufficient"  # wrong order
    done = env.sign(ch, "treasury", TREASURY, now=t1)
    assert done["state"] == "ACTIVE" and done["pending_challenge"] is None and len(done["signatures"]) == 2
    reg = env.store.get("registry", {"vendor_id": ACME["vendor_id"]})
    assert reg["iban"] == NEW_IBAN
    assert reg["iban_history"] == [
        {"iban": ACME["iban"], "from": "2024-03-01", "to": "2026-10-19", "change_id": None},
        {"iban": NEW_IBAN, "from": "2026-10-19", "to": None, "change_id": ch["change_id"]},
    ]
    meta = env.store.get("registry", {"vendor_id": M.META_KEY})
    assert meta["registry_version"] == 2 and meta["registry_hash"] != "0" * 64
    assert len(env.store.transactions) == 1 and len(env.store.transactions[0]) == 3
    assert env.audit.transitions(ch["change_id"])[-2:] == [("SIG_CLERK", "SIG_TREASURY", "CLERK_SIGNED"),
                                                           ("SIG_TREASURY", "ACTIVE", "TREASURY_SIGNED")]
    assert _err(env.sign, ch, "treasury", TREASURY, now=t1) == "state_conflict"


def test_prod_profile_requires_genuine_treasury(monkeypatch: pytest.MonkeyPatch):
    env = Env(monkeypatch, Settings(demo_profile="prod"))
    ch = env.sig_clerk()
    env.sign(ch, "clerk", CLERK, now=T0 + timedelta(seconds=30))
    env.store.put("enrolled_signers", {"address": TREASURY, "role": "treasury", "device": "EMULATOR", "active": True})
    assert _err(env.sign, ch, "treasury", TREASURY, now=T0 + timedelta(seconds=31)) == "emulator_not_allowed"
    env.store.put("enrolled_signers", {"address": TREASURY, "role": "treasury", "device": "GENUINE", "active": True})
    assert env.sign(ch, "treasury", TREASURY, now=T0 + timedelta(seconds=32))["state"] == "ACTIVE"


def test_activation_conflict_writes_nothing(env: Env):
    ch = env.sig_clerk()
    env.sign(ch, "clerk", CLERK, now=T0 + timedelta(seconds=30))
    env.store.update_if("registry", {"vendor_id": M.META_KEY}, {"registry_version": 7}, {})
    real = env.store.transact
    env.store.transact = lambda ops, client_request_token=None: (  # a racing writer
        False if any(op.table == "changes" for op in ops) else real(ops, client_request_token))
    assert _err(env.sign, ch, "treasury", TREASURY, now=T0 + timedelta(seconds=31)) == "state_conflict"
    assert env.get(ch)["state"] == "SIG_TREASURY"
    assert env.store.get("registry", {"vendor_id": ACME["vendor_id"]})["iban"] == ACME["iban"]


def test_optimistic_concurrency_state_conflict(env: Env):
    ch = env.create()
    real = env.store.update_if
    env.store.update_if = lambda t, k, s, e: False if t == "changes" else real(t, k, s, e)
    assert _err(env.tr, ch, E.TRIPWIRE_NOT_US, {"reason": "x"}) == "state_conflict"
    env.store.update_if = real
    assert env.get(ch)["state"] == "PENDING_ATTEST"


# --------------------------------------------------------------------------- callback path


def test_off_network_callback_attempts_exceeded(env: Env):
    ch = env.create(BETA, new_iban="CZ7501000000001155443322")
    assert ch["state"] == "CALLBACK_PENDING" and ch["callback"]["status"] == "pending"
    assert env.audit.events(ch["change_id"]) == ["facts_computed", "tripwire_sent", "callback_issued"]
    assert _err(env.sign, ch, "clerk", CLERK, "ABCDEF01") == "missing_callback_attestation"
    code = env.code(ch["change_id"])
    for i in (1, 2):
        assert _err(env.tr, ch, E.CALLBACK_CONFIRM, {"code": _wrong(code)}) == "callback_code_invalid"
        row = env.get(ch)
        assert row["state"] == "CALLBACK_PENDING" and row["callback"]["attempts"] == i
    assert _err(env.tr, ch, E.CALLBACK_CONFIRM, {"code": _wrong(code)}) == "callback_code_invalid"
    assert env.get(ch)["state"] == "REJECTED" and env.get(ch)["callback"]["attempts"] == 3
    assert _err(env.tr, ch, E.CALLBACK_CONFIRM, {"code": code}) == "callback_attempts_exceeded"
    assert env.get(ch)["state"] == "REJECTED"
    assert env.audit.transitions(ch["change_id"])[-1] == ("CALLBACK_PENDING", "REJECTED",
                                                          "CALLBACK_ATTEMPTS_EXCEEDED")


def test_off_network_right_code_to_cooling(env: Env):
    ch = env.create(BETA, new_iban="CZ7501000000001155443322")
    assert _err(env.tr, ch, E.CALLBACK_CONFIRM, {"code": _wrong(env.code(ch["change_id"]))}) == "callback_code_invalid"
    out = env.tr(ch, E.CALLBACK_CONFIRM, {"code": env.code(ch["change_id"])})
    assert out["state"] == "COOLING" and out["callback"] == {"status": "confirmed",
                                                             "code_exp": "2026-10-19T12:10:00Z", "attempts": 1}
    assert out["not_before"] == "2026-10-19T12:00:20Z"
    assert next(f for f in out["facts"] if f["id"] == "F-CALLBACK")["display_line"] == "CALLBACK OK"
    assert env.advance(ch, T0 + timedelta(seconds=20))["state"] == "SIG_CLERK"


def test_callback_deny_rejects(env: Env):
    ch = env.create(BETA, new_iban="CZ7501000000001155443322")
    assert env.tr(ch, E.CALLBACK_DENY, {"code": "000000"})["state"] == "REJECTED"
    assert env.get(ch)["callback"]["status"] == "denied"


def test_break_glass_from_pending_attest(monkeypatch: pytest.MonkeyPatch):
    env = Env(monkeypatch, Settings(break_glass_cooling_seconds=60))
    ch = env.create()
    env.tr(ch, E.VC_RECEIVED, {"vc": "ok:supplier-erp"})
    assert _err(env.tr, ch, E.BREAK_GLASS, {"reason": "lost keys"}, actor="host") == "caller_not_allowed"
    out = env.tr(ch, E.BREAK_GLASS, {"reason": "ERP key lost", "declared_by": "finance@acme.example"})
    assert out["state"] == "CALLBACK_PENDING" and out["break_glass"] is True
    assert out["callback"]["status"] == "pending"
    assert {f["id"]: f["display_line"] for f in out["facts"]}["F-ATTEST"] == "ATT BREAK-GLASS"
    assert env.audit.events(ch["change_id"])[-2:] == ["break_glass", "callback_issued"]
    assert env.audit.transitions(ch["change_id"])[-1] == ("PENDING_ATTEST", "CALLBACK_PENDING", "BREAK_GLASS")
    done = env.tr(ch, E.CALLBACK_CONFIRM, {"code": env.code(ch["change_id"])})
    assert done["state"] == "COOLING" and done["not_before"] == "2026-10-19T12:01:00Z"
    assert env.advance(ch, T0 + timedelta(seconds=59))["state"] == "COOLING"
    assert env.advance(ch, T0 + timedelta(seconds=60))["state"] == "SIG_CLERK"


# --------------------------------------------------------------------------- reject / expire


@pytest.mark.parametrize("state", ["PENDING_ATTEST", "CALLBACK_PENDING", "COOLING", "SIG_CLERK", "SIG_TREASURY"])
def test_tripwire_not_us_rejects_from_any_non_terminal(env: Env, state: str):
    if state == "PENDING_ATTEST":
        ch = env.create()
    elif state == "CALLBACK_PENDING":
        ch = env.create(BETA, new_iban="CZ7501000000001155443322")
    elif state == "COOLING":
        ch = env.cooling()
    else:
        ch = env.sig_clerk()
        if state == "SIG_TREASURY":
            env.sign(ch, "clerk", CLERK, now=T0 + timedelta(seconds=21))
    assert env.get(ch)["state"] == state
    t = T0 + timedelta(seconds=5)  # before not_before: a COOLING change stays COOLING
    out = env.tr(ch, E.TRIPWIRE_NOT_US, {"reason": "not us"}, now=t)
    assert out["state"] == "REJECTED" and out["pending_challenge"] is None
    assert out["history"][-1] == {"from": state, "to": "REJECTED", "at": "2026-10-19T12:00:05Z", "reason": "not us",
                                  "actor": "vendor_portal"}
    leaf = env.audit.of_type("state_transition", ch["change_id"])[-1]
    assert leaf["actor"] == "vendor_portal" and leaf["data"]["event"] == "TRIPWIRE_NOT_US"
    with pytest.raises(M.ForbiddenTransition):
        env.tr(ch, E.TRIPWIRE_NOT_US, {"reason": "again"}, now=t)


def test_clerk_reject_signed_and_vc_revoked_carry_actor(env: Env):
    a, b = env.create(), env.create(new_iban="CZ7501000000001155443322")
    assert env.tr(a, E.CLERK_REJECT_SIGNED, {"reason": "clerk"})["history"][-1]["actor"] == "host"
    assert env.tr(b, E.VC_REVOKED)["history"][-1]["actor"] == "executor"


def test_expire_lazily(env: Env):
    ch = env.cooling()
    late = T0 + timedelta(seconds=3600)
    assert _err(env.tr, ch, E.EXPIRE, now=late - timedelta(seconds=1)) == "state_conflict"
    assert env.advance(ch, late - timedelta(seconds=1))["state"] == "SIG_CLERK"
    with pytest.raises(M.ForbiddenTransition):
        env.tr(ch, E.TRIPWIRE_NOT_US, now=late)  # advance() expires it first
    row = env.get(ch)
    assert row["state"] == "EXPIRED" and row["pending_challenge"] is None
    assert env.audit.transitions(ch["change_id"])[-1] == ("SIG_CLERK", "EXPIRED", "EXPIRE")
    assert _err(env.sign, ch, "clerk", CLERK, now=late) == "state_conflict"


# --------------------------------------------------------------------------- audit + privacy


def test_every_transition_has_a_state_transition_leaf(env: Env):
    ch = env.sig_clerk()
    env.sign(ch, "clerk", CLERK, now=T0 + timedelta(seconds=30))
    done = env.sign(ch, "treasury", TREASURY, now=T0 + timedelta(seconds=31))
    expected = [(h["from"], h["to"]) for h in done["history"]]
    assert expected == [(None, "PENDING_ATTEST"), ("PENDING_ATTEST", "COOLING"), ("COOLING", "SIG_CLERK"),
                        ("SIG_CLERK", "SIG_TREASURY"), ("SIG_TREASURY", "ACTIVE")]
    leaves = env.audit.transitions(ch["change_id"])
    assert [(f, t) for f, t, _ in leaves] == expected
    assert [e for _, _, e in leaves] == ["CREATE", "VC_RECEIVED", "COOLING_ELAPSED", "CLERK_SIGNED",
                                         "TREASURY_SIGNED"]
    for leaf in env.audit.of_type("state_transition") + env.audit.of_type("change_event"):
        assert re.fullmatch(r"[0-9a-f]{64}", leaf["facts_digest"])
        assert set(leaf["data"]) >= {"change_id"}


def test_plaintext_callback_code_never_stored(env: Env, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(portal, "_new_code", lambda: "418093")
    ch = env.create(BETA, new_iban="CZ7501000000001155443322")
    assert _err(env.tr, ch, E.CALLBACK_CONFIRM, {"code": "418094"}) == "callback_code_invalid"
    env.tr(ch, E.CALLBACK_CONFIRM, {"code": "418093"})
    bg = env.create()
    env.tr(bg, E.BREAK_GLASS, {"reason": "lost", "declared_by": "finance@acme.example"})
    assert env.code(ch["change_id"]) == "418093"  # delivered only through the SIMULATED SMS outbox
    rows = env.store.all_rows()
    assert rows and not any("418093" in json.dumps(r) for _, r in rows)
    assert not any("418093" in json.dumps(x) for x in env.audit.leaves)
    cb = [r for t, r in rows if t == "portal_notifications" and r["kind"] == "callback"]
    assert len(cb) == 2 and all(r["code_hash"] == hashlib.sha256(b"418093").hexdigest() for r in cb)


# --------------------------------------------------------------------------- adversarial regressions (R0, S4)


def _revoke(tmp_path, vc: str) -> None:
    (tmp_path / "vc_status.json").write_text(json.dumps({"revoked": [hashlib.sha256(vc.encode()).hexdigest()]}))


def test_vc_revoked_during_cooling_rejects_and_issues_no_challenge(tmp_path, monkeypatch: pytest.MonkeyPatch):
    env = Env(monkeypatch, Settings(data_dir=str(tmp_path)))
    ch = env.cooling()
    _revoke(tmp_path, "ok:supplier-bank")
    out = env.advance(ch, T0 + timedelta(seconds=env.settings.cooling_seconds))
    assert out["state"] == "REJECTED" and out["pending_challenge"] is None
    assert env.store.scan("nonces") == [] and env.audit.of_type("challenge") == []
    assert env.audit.transitions(ch["change_id"])[-1] == ("COOLING", "REJECTED", "VC_REVOKED")
    assert out["history"][-1]["actor"] == "executor"


def test_revoked_vc_does_not_count_on_submission(tmp_path, monkeypatch: pytest.MonkeyPatch):
    env = Env(monkeypatch, Settings(data_dir=str(tmp_path)))
    seen: list = []
    real = env.fake_verify
    monkeypatch.setattr(M._vc, "verify_vc", lambda vc, change, **kw: seen.append(kw.get("revoked")) or real(
        vc, change, **kw))
    _revoke(tmp_path, "ok:supplier-erp")
    ch = env.create()
    env.tr(ch, E.VC_RECEIVED, {"vc": "ok:supplier-bank"})
    assert seen and seen[0] == {hashlib.sha256(b"ok:supplier-erp").hexdigest()}  # list from settings.data_dir
    # even a verifier that ignores `revoked` cannot make a revoked VC count
    out = env.tr(ch, E.VC_RECEIVED, {"vc": "ok:supplier-erp"})
    assert out["state"] == "PENDING_ATTEST" and out["attest_count"] == 1


def test_vc_revoked_in_sig_treasury_blocks_activation(tmp_path, monkeypatch: pytest.MonkeyPatch):
    env = Env(monkeypatch, Settings(data_dir=str(tmp_path)))
    ch = env.sig_clerk()
    env.sign(ch, "clerk", CLERK, now=T0 + timedelta(seconds=30))
    _revoke(tmp_path, "ok:supplier-erp")
    assert _err(env.sign, ch, "treasury", TREASURY, now=T0 + timedelta(seconds=31)) == "state_conflict"
    assert env.get(ch)["state"] == "REJECTED"
    assert env.store.get("registry", {"vendor_id": ACME["vendor_id"]})["iban"] == ACME["iban"]
    assert env.store.transactions == []


def test_block_after_sig_clerk_refuses_treasury_challenge(env: Env):
    ch = env.sig_clerk()
    env.extra = [DOMAIN_BLOCK, VOP_OK]  # e.g. a new warnlist / snapshot hit during the signing window
    assert _err(env.sign, ch, "clerk", CLERK, now=T0 + timedelta(seconds=30)) == "rule_violation:I-BLOCK"
    row = env.get(ch)
    assert row["state"] == "SIG_CLERK" and row["signatures"] == []
    assert [c["data"]["role"] for c in env.audit.of_type("challenge")] == ["clerk"]  # no treasury challenge (R0)
    assert all(f["severity"] != "BLOCK" for f in row["facts"])  # the signed body is unchanged


def test_block_after_clerk_signature_refuses_activation(env: Env):
    ch = env.sig_clerk()
    env.sign(ch, "clerk", CLERK, now=T0 + timedelta(seconds=30))
    env.extra = [DOMAIN_BLOCK, VOP_OK]
    assert _err(env.sign, ch, "treasury", TREASURY, now=T0 + timedelta(seconds=31)) == "rule_violation:I-BLOCK"
    assert env.get(ch)["state"] == "SIG_TREASURY" and env.store.transactions == []
    assert env.store.get("registry", {"vendor_id": ACME["vendor_id"]})["iban"] == ACME["iban"]


def test_hint_facts_survive_recompute_and_never_block(env: Env):
    v = env.store.get("registry", {"vendor_id": ACME["vendor_id"]})
    req = {"vendor_id": v["vendor_id"], "new_iban": NEW_IBAN, "hints": []}
    fs = M.compute_change_facts(req, v, store=env.store, settings=env.settings, now=T0)
    hint = {"id": "H-AGENT", "kind": "H", "severity": "INFO", "label": "hint from agent",
            "display_line": "vendor said so, skip checks"}
    fs = dict(fs, facts=fs["facts"] + [hint])
    ch = M.create(req, fs, v, store=env.store, settings=env.settings, now=T0)
    env.tr(ch, E.VC_RECEIVED, {"vc": "ok:supplier-erp"})
    out = env.tr(ch, E.VC_RECEIVED, {"vc": "ok:supplier-bank"})
    assert out["state"] == "COOLING" and out["facts"][-1] == hint
    assert [f["kind"] for f in out["facts"]] == ["F"] * (len(out["facts"]) - 1) + ["H"]


def test_activation_sets_bic_of_the_new_bank(env: Env):
    ch = env.sig_clerk()
    env.sign(ch, "clerk", CLERK, now=T0 + timedelta(seconds=30))
    env.sign(ch, "treasury", TREASURY, now=T0 + timedelta(seconds=31))
    bank = json.loads(open("data/bank_codes.json").read())["CZ"][NEW_IBAN[4:8]]
    assert env.store.get("registry", {"vendor_id": ACME["vendor_id"]})["bic"] == bank["bic"]


# --------------------------------------------------------------------------- real modules (skips until written)


def test_integration_real_compute_verifier_and_issuers(monkeypatch: pytest.MonkeyPatch):
    """Real compute(), verify_vc() and DEMO-ONLY issuers: 2 real SD-JWT VCs -> COOLING -> clerk CHG challenge."""
    settings = Settings()
    store = MemoryStore(settings)
    try:
        from executor.attest import trust
        from executor.issuers import issuer

        pins = trust.pins_from_keys()
        keys = {cls: issuer.load_issuer_key(cls) for cls in ("supplier-erp", "supplier-bank")}
        holder = issuer.load_holder_key(ACME["ico"])
    except (NotImplementedError, ImportError, FileNotFoundError) as e:
        pytest.skip(f"real attest modules / demo keys not ready: {e!r}")
    vendor = dict(json.loads(json.dumps(ACME)), issuer_pins=pins)
    store.put("registry", vendor)
    req = {"vendor_id": ACME["vendor_id"], "new_iban": NEW_IBAN, "hints": []}
    fs = M.compute_change_facts(req, vendor, store=store, settings=settings, now=T0)
    ch = M.create(req, fs, vendor, store=store, settings=settings, now=T0)
    vcs = {cls: issuer.issue_vc(cls, ch, key=key, holder_key=holder, now=T0, iss=iss)
           for cls, (key, iss) in keys.items()}
    assert ch["state"] == "PENDING_ATTEST"
    assert next(f for f in ch["facts"] if f["id"] == "F-ATTEST")["severity"] == "BLOCK"
    bad = _err(M.transition, ch["change_id"], E.VC_RECEIVED, payload={"vc": "not.a.vc~"}, store=store,
               settings=settings, now=T0)
    assert bad in ("kb_jwt_invalid", "issuer_not_pinned", "attestation_insufficient")
    out = M.transition(ch["change_id"], E.VC_RECEIVED, payload={"vc": vcs["supplier-erp"]}, store=store,
                       settings=settings, now=T0)
    assert out["state"] == "PENDING_ATTEST" and out["attest_count"] == 1
    out = M.transition(ch["change_id"], E.VC_RECEIVED, payload={"vc": vcs["supplier-bank"]}, store=store,
                       settings=settings, now=T0)
    assert out["state"] == "COOLING" and out["attest_count"] == 2
    out = M.advance(out, store=store, settings=settings, now=T0 + timedelta(seconds=settings.cooling_seconds))
    assert out["state"] == "SIG_CLERK" and "ROLE CLERK 1/2" in out["pending_challenge"]["text"]


def test_seed_registry_signers_and_inbox(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ec

    from tools import seed_data

    keys = tmp_path / "issuer_keys"
    keys.mkdir()
    for cls in ("supplier-erp", "supplier-bank", "registry"):
        pub = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
        jwk = {"kty": "EC", "crv": "P-256", "iss": f"https://{cls}.example",
               "x": seed_data._b64u(pub.x.to_bytes(32, "big")), "y": seed_data._b64u(pub.y.to_bytes(32, "big"))}
        (keys / f"{cls}.jwk").write_text(json.dumps(jwk))
    vendors = [{k: v for k, v in x.items() if k != "issuer_pins"} for x in (ACME, BETA)]
    (tmp_path / "vendors.json").write_text(json.dumps(vendors))
    (tmp_path / "enrollment.json").write_text(json.dumps({"version": 1, "signers": [
        {"address": CLERK.upper().replace("0X", "0x"), "role": "clerk", "device": "GENUINE", "active": True,
         "ceremony": {"text": "AG1/DEMO ENROLL"}},
        {"address": TREASURY, "role": "treasury", "device": "EMULATOR", "active": True}]}))
    (tmp_path / "emails").mkdir()
    raw = (b"From: ACME Finance <finance@acme.cz>\r\nTo: ap@buyer.example\r\nSubject: New bank account\r\n"
           b"Date: Mon, 19 Oct 2026 09:15:00 +0000\r\n\r\nPlease update our IBAN.\r\n")
    (tmp_path / "emails" / "01_legit.eml").write_bytes(raw)
    (tmp_path / "dns_snapshot.json").write_text("{}")
    settings = Settings()
    store = MemoryStore(settings)
    out = seed_data.seed(settings=settings, data_dir=str(tmp_path), store=store, now=T0)
    assert out == {"vendors": 2, "pins": 3, "signers": 2, "emails": 1}
    acme = store.get("registry", {"vendor_id": "ven_12345678"})
    assert sorted(p["issuer_class"] for p in acme["issuer_pins"]) == ["registry", "supplier-bank", "supplier-erp"]
    assert all(len(p["jwk_thumbprint"]) == 43 for p in acme["issuer_pins"])
    assert store.get("registry", {"vendor_id": "ven_87654321"})["issuer_pins"] == []
    meta = store.get("registry", {"vendor_id": "registry#meta"})
    from executor.policy.mandate import registry_snapshot

    assert meta["registry_version"] == 1 and meta["registry_hash"] == registry_snapshot(store)["hash"]
    clerk = store.get("enrolled_signers", {"address": CLERK})
    assert clerk["device"] == "GENUINE" and "ceremony" not in clerk
    (row,) = store.scan("inbox")
    assert row["email_id"] == "eml_" + hashlib.sha256(raw).hexdigest()[:16]
    assert row["from_domain"] == "acme.cz" and row["received_at"] == "2026-10-19T09:15:00Z"
    assert row["dkim"]["result"] in ("pass", "fail", "none")  # no DKIM-Signature: never "pass"
    assert [json.loads(r["event"])["type"] for r in store.query("audit", ("log_id", "audit"))] == ["ingest"]
    # a second run is idempotent on the inbox and bumps the registry version
    assert seed_data.seed(settings=settings, data_dir=str(tmp_path), store=store, now=T0)["emails"] == 1
    assert len(store.scan("inbox")) == 1
    assert store.get("registry", {"vendor_id": "registry#meta"})["registry_version"] == 2


def test_seed_default_store_and_repo_data():
    from tools import seed_data

    out = seed_data.seed(settings=Settings(), now=T0)  # get_store(Settings()) -> memory backend
    assert out["vendors"] >= 2 and out["pins"] >= 3 and out["signers"] >= 2 and out["emails"] >= 1


# --------------------------------------------------------------------------- through executor.handler


def test_handler_dispatch_change_flow(env: Env):
    """WS-A's handler drives the FSM: POST /changes, VC submit (AttestResult in the response), lazy advance on GET,
    clerk + treasury CHG signatures, signed CHG_REJECT, portal NOT-US and callback codes."""
    from eth_account import Account
    from eth_account.messages import encode_defunct

    from executor import handler
    from executor.store import seed

    clerk, treasury = Account.create(), Account.create()
    seed.enroll_signer(env.store, clerk.address, "clerk", device="GENUINE")
    seed.enroll_signer(env.store, treasury.address, "treasury")

    def call(method: str, path: str, body: Any = None, principal: str | None = None, now: datetime = T0):
        ctx = handler.Context(dataclasses.replace(env.settings, fake_now=iso(now)), env.store)
        return handler.dispatch(method, path, None, body, principal=principal, ctx=ctx)

    def sign(ch: dict, acct: Any, now: datetime):
        sig = acct.sign_message(encode_defunct(text=ch["text"])).signature.hex()
        body = {"nonce": ch["nonce"], "role": ch["role"], "sig": sig if sig.startswith("0x") else "0x" + sig}
        return call("POST", "/signatures", body, "host", now)

    st, r = call("POST", "/changes", {"vendor_id": ACME["vendor_id"], "new_iban": NEW_IBAN}, "tools")
    assert st == 201 and r["change"]["state"] == "PENDING_ATTEST" and r["decision"]["decision"] == "pending", r
    handler.validate(r, "change_create.response")
    cid = r["change"]["change_id"]
    st, r = call("POST", f"/changes/{cid}/attestations", {"vc": "ok~supplier-erp"}, "issuer")
    assert st == 200 and r["attest"]["ok"] is True and r["change"]["attest_count"] == 1, r
    handler.validate(r, "vc_submit.response")
    st, r = call("POST", f"/changes/{cid}/attestations", {"vc": "bad~kb_jwt_invalid"}, "issuer")
    assert st == 403 and r["error"] == "kb_jwt_invalid", r
    st, r = call("POST", f"/changes/{cid}/attestations", {"vc": "ok~supplier-bank"}, "vendor_portal")
    assert st == 200 and r["change"]["state"] == "COOLING", r
    st, r = call("GET", f"/changes/{cid}", now=T0 + timedelta(seconds=20))
    assert st == 200 and r["state"] == "SIG_CLERK", r
    handler.validate(r, "change")
    t1 = T0 + timedelta(seconds=30)
    st, r = sign(r["pending_challenge"], clerk, t1)
    assert st == 200 and r["effect"] == {"type": "change_advanced", "state": "SIG_TREASURY"}, r
    assert r["challenge"]["role"] == "treasury" and r["change"]["signatures"][0]["address"] == clerk.address.lower()
    handler.validate(r, "signature_submit.response")
    st, r = sign(r["challenge"], treasury, t1)
    assert st == 200 and r["effect"] == {"type": "change_advanced", "state": "ACTIVE"}, r
    assert env.store.get("registry", {"vendor_id": ACME["vendor_id"]})["iban"] == NEW_IBAN
    signed = [(x["data"]["purpose"], x["data"]["accepted"]) for x in env.audit.of_type("signature", cid)]
    assert signed == [("CHG", True), ("CHG", True)]

    # host reject: CHG_REJECT challenge, the clerk's signature rejects
    st, r = call("POST", "/changes", {"vendor_id": BETA["vendor_id"], "new_iban": "CZ7501000000001155443322"}, "tools")
    assert st == 201 and r["change"]["state"] == "CALLBACK_PENDING", r
    b = r["change"]["change_id"]
    st, r = call("POST", f"/callbacks/{b}", {"code": _wrong(env.code(b)), "outcome": "confirm"}, "vendor_portal")
    assert st == 403 and r["error"] == "callback_code_invalid", r
    st, r = call("POST", f"/changes/{b}/reject", {"reason": "duplicate request"}, "host")
    assert st == 200 and r["challenge"]["purpose"] == "CHG_REJECT", r
    st, r = sign(r["challenge"], clerk, T0 + timedelta(seconds=40))
    assert st == 200 and r["effect"] == {"type": "change_rejected", "state": "REJECTED"}, r
    assert r["change"]["history"][-1]["actor"] == "host"
    assert env.audit.transitions(b)[-1] == ("CALLBACK_PENDING", "REJECTED", "CLERK_REJECT_SIGNED")

    # portal NOT US and callback confirm through the handler
    st, r = call("POST", "/changes", {"vendor_id": BETA["vendor_id"], "new_iban": "CZ7501000000001155443322"}, "tools")
    c = r["change"]["change_id"]
    st, r = call("POST", f"/callbacks/{c}", {"code": env.code(c), "outcome": "confirm"}, "vendor_portal")
    assert st == 200 and r["state"] == "COOLING", r
    st, r = call("POST", f"/changes/{c}/reject", {"reason": "not us"}, "vendor_portal")
    assert st == 200 and r["change"]["state"] == "REJECTED", r
    assert r["change"]["history"][-1] == {"from": "COOLING", "to": "REJECTED", "at": "2026-10-19T12:00:00Z",
                                          "reason": "not us", "actor": "vendor_portal"}


def test_forbidden_transition_is_state_conflict_through_the_handler(env: Env):
    from executor import handler

    ch = env.cooling()
    ctx = handler.Context(dataclasses.replace(env.settings, fake_now=iso(T0)), env.store)
    st, r = handler.dispatch("POST", f"/callbacks/{ch['change_id']}", None, {"code": "123456", "outcome": "confirm"},
                             principal="vendor_portal", ctx=ctx)
    assert st == 409 and r["error"] == "state_conflict", r
    assert env.get(ch)["state"] == "COOLING"
