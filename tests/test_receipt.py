"""Receipts (executor/audit/receipt.py, CONTRACTS.md v2 §7.4): round trip, tampering, CLI. Owner: WS-B."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from executor.audit import checkpoint as cp
from executor.audit import log, receipt
from tests.ws_b_store import FakeStore, build_log, demo_events, make_settings
from tools import verify_audit as va

TX = f"tx_{1:016x}"
FIXTURE = Path(__file__).resolve().parents[1] / "contracts" / "fixtures" / "receipts_get" / "ok.json"


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    settings = make_settings(tmp_path_factory.mktemp("rc"), checkpoint_every_n_leaves=5)
    store = FakeStore()
    build_log(store, settings, ledger=True)
    return store, settings


@pytest.fixture
def r(env):
    store, settings = env
    return receipt.receipt(TX, store=store, settings=settings)


def test_round_trip(r, env):
    store, settings = env
    assert receipt.verify_receipt(r), receipt.receipt_problems(r)
    assert r["entry"]["type"] == "execution" and r["entry"]["data"]["tx_id"] == TX
    assert r["tx"] == store.get("ledger", {"tx_id": TX})
    assert r["tree_size"] > r["seq"]
    assert cp.witness_name(settings) in r["checkpoint_note"]
    assert set(r["key_ids"]) == set(r["vkeys"]) == {"log", "w1"}
    json.dumps(r)  # JSON-serialisable as is (QR payload)


def test_without_ledger_row_scans_leaves(env):
    store, settings = env
    s2 = FakeStore()
    s2.tables = copy.deepcopy(store.tables)
    s2.tables["ledger"] = {}
    r2 = receipt.receipt(TX, store=s2, settings=settings)
    assert receipt.verify_receipt(r2)
    assert r2["tx"]["tx_id"] == TX and r2["tx"]["seq"] == r2["seq"]


def test_unknown_or_uncovered(tmp_path, env):
    store, settings = env
    with pytest.raises(LookupError):
        receipt.receipt("tx_0000000000000000", store=store, settings=settings)
    s = make_settings(tmp_path, checkpoint_every_n_leaves=1000, checkpoint_max_seconds=3600)
    st = FakeStore()
    seq = None
    for ev in demo_events(1):
        seq = log.append(ev, store=st, settings=s)
        if ev["type"] == "execution":
            break
    assert seq is not None
    with pytest.raises(LookupError, match="not covered"):
        receipt.receipt(TX, store=st, settings=s)


def test_tampered_entry(r):
    r["entry"]["data"]["amount_minor"] += 1
    assert not receipt.verify_receipt(r)
    assert any("leaf hash mismatch" in p for p in receipt.receipt_problems(r))


def test_tampered_entry_with_recomputed_leaf_hash(r):
    r["entry"]["data"]["iban"] = "CZ5508000000001234567899"
    r["leaf_hash"] = log.leaf_hash(r["entry"])
    assert any("inclusion proof" in p for p in receipt.receipt_problems(r))


def test_tampered_proof(r):
    h = r["inclusion_proof"][0]
    r["inclusion_proof"][0] = ("0" if h[0] != "0" else "1") + h[1:]
    assert any("inclusion proof" in p for p in receipt.receipt_problems(r))


def test_tampered_note(r):
    lines = r["checkpoint_note"].split("\n")
    lines[1] = str(int(lines[1]) + 1)
    r["checkpoint_note"] = "\n".join(lines)
    assert not receipt.verify_receipt(r)


def test_w1_cosignature_missing(r, env):
    _, settings = env
    w1 = cp.witness_name(settings)
    r["checkpoint_note"] = "".join(ln for ln in r["checkpoint_note"].splitlines(keepends=True) if f" {w1} " not in ln)
    assert any("quorum" in p for p in receipt.receipt_problems(r))


def test_key_ids_inconsistent(r):
    r["key_ids"]["w1"] = "00000000"
    assert any("key_ids.w1" in p for p in receipt.receipt_problems(r))


def test_swapped_vkey_types(r):
    r["vkeys"]["log"], r["vkeys"]["w1"] = r["vkeys"]["w1"], r["vkeys"]["log"]
    r["key_ids"]["log"], r["key_ids"]["w1"] = r["key_ids"]["w1"], r["key_ids"]["log"]
    assert not receipt.verify_receipt(r)


def test_contracts_fixture_key_ids():
    """The fixture's key ids and vkeys agree. Its inclusion proof and signatures are synthetic, so it is NOT
    required to verify end to end."""
    fx = json.loads(FIXTURE.read_text(encoding="utf-8"))["response"]
    for role, vk in fx["vkeys"].items():
        assert cp.parse_vkey(vk)["key_id"].hex() == fx["key_ids"][role]
    assert fx["entry"]["seq"] == fx["seq"] and fx["entry"]["data"]["tx_id"] == fx["tx"]["tx_id"]
    assert not any(p.startswith("key_ids") or p.startswith("vkeys") for p in receipt.receipt_problems(fx))


def test_cli_receipt(r, env, tmp_path, capsys):
    store, settings = env
    rp = tmp_path / "r.json"
    rp.write_text(json.dumps(r), encoding="utf-8")
    assert va.main(["--receipt", str(rp)]) == 0
    assert "RESULT: OK" in capsys.readouterr().out
    bp = tmp_path / "b.json"
    bp.write_text(json.dumps(log.export("audit", store=store, settings=settings)), encoding="utf-8")
    assert va.main([str(bp), "--no-replay", "--receipt", str(rp)]) == 0
    capsys.readouterr()
    r["entry"]["data"]["amount_minor"] += 1
    rp.write_text(json.dumps(r), encoding="utf-8")
    assert va.main(["--receipt", str(rp)]) == 1
    assert f"receipt: seq {r['seq']}: leaf hash mismatch" in capsys.readouterr().out


# ---- review fixes: tx authenticated against the entry, pinned keys, ledger seq sanity, CLI robustness


@pytest.mark.parametrize("field,value", [("amount_minor", 1), ("iban", "CZ5508000000001234567899"),
                                         ("vendor_id", "ven_99999999"), ("currency", "EUR"),
                                         ("authorization", {"kind": "stepup"}), ("proposal_id", "prp_9")])
def test_tampered_tx_fields(r, field, value):
    r["tx"][field] = value
    assert not receipt.verify_receipt(r)
    assert any("does not match the logged execution" in p and field in p for p in receipt.receipt_problems(r))


def test_tx_absent_only_entry_vouched(r, tmp_path, capsys):
    r["tx"] = None
    assert receipt.verify_receipt(r)
    rp = tmp_path / "r.json"
    rp.write_text(json.dumps(r), encoding="utf-8")
    assert va.main(["--receipt", str(rp)]) == 0
    assert "only the execution leaf (entry.data) is vouched for" in capsys.readouterr().out


def test_pinned_receipt_keys(r, tmp_path):
    pins = {"log": r["vkeys"]["log"], "w1": r["vkeys"]["w1"]}
    assert receipt.verify_receipt(r, trusted_vkeys=pins)
    # a self-consistent receipt from a log the attacker signed with their own keys verifies only unpinned
    settings = make_settings(tmp_path, checkpoint_every_n_leaves=5)
    store = FakeStore()
    build_log(store, settings, ledger=True)
    forged = receipt.receipt(TX, store=store, settings=settings)
    assert receipt.verify_receipt(forged)
    problems = receipt.receipt_problems(forged, trusted_vkeys=pins)
    assert any(p.startswith("vkeys.log: receipt key") and "is not the pinned key" in p for p in problems)
    assert any("checkpoint note" in p for p in problems)


def test_cli_receipt_keys(r, env, tmp_path, capsys):
    rp = tmp_path / "r.json"
    rp.write_text(json.dumps(r), encoding="utf-8")
    assert va.main(["--receipt", str(rp)]) == 0
    out = capsys.readouterr().out
    assert "self-asserted keys" in out and r["key_ids"]["log"] in out and r["key_ids"]["w1"] in out
    kp = tmp_path / "k.json"
    kp.write_text(json.dumps({"log": r["vkeys"]["log"], "w1": r["vkeys"]["w1"]}), encoding="utf-8")
    assert va.main(["--receipt", str(rp), "--trust-keys", str(kp)]) == 0
    out = capsys.readouterr().out
    assert "pinned via --trust-keys" in out and "self-asserted" not in out
    kp.write_text(json.dumps({"log": cp.vkeys(make_settings(tmp_path))["log"], "w1": r["vkeys"]["w1"]}),
                  encoding="utf-8")
    assert va.main(["--receipt", str(rp), "--trust-keys", str(kp)]) == 1
    assert "is not the pinned key" in capsys.readouterr().out


@pytest.mark.parametrize("payload", ["[1, 2]", '"x"', "3", '{"entry": "x", "seq": 1}'])
def test_cli_receipt_not_an_object(tmp_path, capsys, payload):
    rp = tmp_path / "r.json"
    rp.write_text(payload, encoding="utf-8")
    assert va.main(["--receipt", str(rp)]) == 1
    out = capsys.readouterr().out
    assert "RESULT: FAIL" in out and "malformed receipt" in out and "Traceback" not in out


def test_ledger_row_seq_pointing_elsewhere_falls_back_to_scan(env):
    store, settings = env
    s2 = FakeStore()
    s2.tables = copy.deepcopy(store.tables)
    row = s2.get("ledger", {"tx_id": TX})
    true_seq = row["seq"]
    s2.put("ledger", {**row, "seq": 0})  # seq 0 is an enroll leaf
    r2 = receipt.receipt(TX, store=s2, settings=settings)
    assert r2["seq"] == true_seq and r2["entry"]["type"] == "execution" and r2["entry"]["data"]["tx_id"] == TX
    # the inconsistent ledger row is carried as is and flagged, never silently trusted
    assert any("does not match the logged execution (seq)" in p for p in receipt.receipt_problems(r2))
    s2.put("ledger", {"tx_id": "tx_ffffffffffffffff", "seq": true_seq})  # row for a tx with no execution leaf
    with pytest.raises(LookupError):
        receipt.receipt("tx_ffffffffffffffff", store=s2, settings=settings)
