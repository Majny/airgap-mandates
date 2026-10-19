"""tools/seed_data: signers seeded from data/enrollment.json are enrolled in the audit log (CONTRACTS §6, §7.2). Owner: WS-D.

Regression: seed_signers wrote enrolled_signers rows without an `enroll` leaf, so verify_audit refused every bundle with
"accepted signature from 0x.. not enrolled before it" (first AWS run with the physical clerk).
"""
from __future__ import annotations

import dataclasses
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct

from executor import handler, render
from executor.config import Settings, iso
from executor.store import seed as wseed
from executor.store.memory import MemoryStore
from tools import seed_data, verify_audit

T0 = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)


def _enroll_row(acct, role: str, nonce: str, *, active: bool = True) -> dict:
    text = render.render_enroll(role=role, nonce=nonce)
    sig = Account.sign_message(encode_defunct(text=text), acct.key).signature.hex()
    return {"address": acct.address.lower(), "role": role, "label": f"{role} (TEST key)", "device": "EMULATOR",
            "device_model": "T3B1", "firmware_version": "2.12.5", "cert_chain_sha256": None, "fw_hash": None,
            "derivation_path": "m/44'/60'/0'/0/0", "enroll_sig": sig if sig.startswith("0x") else "0x" + sig,
            "active": active, "enrolled_at": iso(T0),
            "ceremony": {"nonce": nonce, "text": text, "transport": "test"}}


def _world(tmp_path: Path, rows: list[dict]):
    data = tmp_path / "data"
    shutil.copytree(wseed.dev_data_dir(), data)
    (data / "enrollment.json").write_text(json.dumps({"version": 1, "signers": rows}))
    settings = Settings(backend="memory", fake_now=iso(T0), data_dir=str(data))
    store = MemoryStore(settings)
    seed_data.seed(settings=settings, store=store, now=T0)
    return settings, store


def _enroll_leaves(store) -> list[dict]:
    evs = [json.loads(r["event"]) for r in store.scan("audit") if isinstance(r.get("event"), str)]
    return sorted((e for e in evs if e["type"] == "enroll"), key=lambda e: e["seq"])


def test_seeded_signers_have_enroll_leaf_and_enroll_seq_and_reseed_is_idempotent(tmp_path):
    clerk, treasury, spare = Account.create(), Account.create(), Account.create()
    rows = [_enroll_row(clerk, "clerk", "0C55A1E7"), _enroll_row(treasury, "treasury", "91BC02E1"),
            _enroll_row(spare, "clerk", "2F42E9E9", active=False)]
    settings, store = _world(tmp_path, rows)
    leaves = _enroll_leaves(store)
    assert [e["subject_id"] for e in leaves] == [r["address"] for r in rows]  # inactive row is logged too
    for r, e in zip(rows, leaves):
        got = store.get("enrolled_signers", {"address": r["address"]})
        assert got["enroll_seq"] == e["seq"] and got["active"] is r["active"]
        assert "ceremony" not in got and e["data"]["enroll_sig"] == r["enroll_sig"]
    seed_data.seed(settings=settings, store=store, now=T0)
    assert _enroll_leaves(store) == leaves  # no second enroll leaf on re-seed


def test_verify_audit_accepts_signatures_by_seeded_signers(tmp_path):
    clerk, treasury = Account.create(), Account.create()
    settings, store = _world(tmp_path, [_enroll_row(clerk, "clerk", "0C55A1E7"),
                                        _enroll_row(treasury, "treasury", "91BC02E1")])

    def call(method, path, body=None, principal=None):
        ctx = handler.Context(dataclasses.replace(settings, fake_now=iso(T0)), store)
        return handler.dispatch(method, path, None, body, principal=principal, ctx=ctx)

    def sign(ch, acct):
        sig = Account.sign_message(encode_defunct(text=ch["text"]), acct.key).signature.hex()
        return call("POST", "/signatures", {"nonce": ch["nonce"], "role": ch["role"],
                                             "sig": sig if sig.startswith("0x") else "0x" + sig}, "host")

    st_, r = call("POST", "/mandates", {"max_per_payment_minor": 8_000_000, "max_total_minor": 25_000_000,
                                        "max_count": 20, "payee_scope": "existing_only",
                                        "valid_until": iso(T0 + timedelta(days=1)), "currency": "CZK"}, "host")
    assert st_ == 201, r
    st_, r = sign(r["challenge"], clerk)
    assert st_ == 200, r
    st_, r = sign(r["challenge"], treasury)
    assert st_ == 200 and r["mandate"]["status"] == "ACTIVE", r
    st_, bundle = call("GET", "/audit/export", principal="auditor")
    assert st_ == 200, bundle
    rep = verify_audit.verify(bundle, allow_uncovered_tail=True)
    assert rep.ok, rep.problems
