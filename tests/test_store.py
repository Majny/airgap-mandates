"""Store backends (memory + moto DynamoDB) and the §3.2 execution transaction. Owner: WS-A."""
from __future__ import annotations

import pytest

from executor.config import Settings
from executor.store import (MISSING, AnyOf, IncrementBounded, Put, TxConflict, UpdateIf, ensure_head, get_store,
                            next_seq, shims, tx_execute)


@pytest.fixture(params=["memory", "moto"])
def store(request, monkeypatch):
    if request.param == "memory":
        yield get_store(Settings(backend="memory"))
        return
    from moto import mock_aws

    from executor.store import dynamo

    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing", "AWS_SESSION_TOKEN": "testing",
                 "AWS_DEFAULT_REGION": "eu-central-1"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    with mock_aws():
        settings = Settings(backend="moto")
        dynamo.create_tables(settings)
        yield get_store(settings)


# ------------------------------------------------------------------ basic ops

def test_get_put_roundtrip(store):
    assert store.get("ledger", {"tx_id": "tx_1"}) is None
    item = {"tx_id": "tx_1", "amount_minor": 1234, "rail": {"status": "PENDING", "xml_c14n_sha256": None},
            "authorization": {"kind": "mandate"}, "tags": [1, 2]}
    store.put("ledger", item)
    assert store.get("ledger", {"tx_id": "tx_1"}) == item
    got = store.get("ledger", {"tx_id": "tx_1"})
    assert isinstance(got["amount_minor"], int) and isinstance(got["tags"][0], int)
    got["amount_minor"] = 0  # copies out
    assert store.get("ledger", {"tx_id": "tx_1"})["amount_minor"] == 1234


def test_main_entity_keys_and_strip(store):
    store.put("proposals", {"proposal_id": "p1", "status": "PENDING_SIG"})
    store.put("attestations", {"change_id": "c1", "sk": "vc#1", "verified": True})
    assert store.get("proposals", {"proposal_id": "p1"}) == {"proposal_id": "p1", "status": "PENDING_SIG"}
    assert store.get("attestations", {"change_id": "c1", "sk": "vc#1"}) == {"change_id": "c1", "sk": "vc#1",
                                                                            "verified": True}
    assert store.get("changes", {"change_id": "p1"}) is None
    assert store.scan("proposals") == [{"proposal_id": "p1", "status": "PENDING_SIG"}]


def test_put_if_absent(store):
    assert store.put_if_absent("registry", {"vendor_id": "v1", "name": "A"}, "vendor_id")
    assert not store.put_if_absent("registry", {"vendor_id": "v1", "name": "B"}, "vendor_id")
    assert store.get("registry", {"vendor_id": "v1"})["name"] == "A"
    assert store.put_if_absent("nonces", {"nonce": "N1", "used": False}, "nonce")
    assert not store.put_if_absent("nonces", {"nonce": "N1", "used": True}, "nonce")


def test_update_if_conditions(store):
    key = {"nonce": "N1"}
    # create-on-missing when conditions pass
    assert store.update_if("nonces", key, {"used": False}, {"used": MISSING})
    assert store.get("nonces", key) == {"nonce": "N1", "used": False}
    assert not store.update_if("nonces", key, {"used": True}, {"used": MISSING})
    assert store.update_if("nonces", key, {"used": True, "used_by": "x"}, {"used": False})
    assert not store.update_if("nonces", key, {"used": True}, {"used": False})
    # equality on a missing item fails and writes nothing
    assert not store.update_if("nonces", {"nonce": "N2"}, {"used": True}, {"used": False})
    assert store.get("nonces", {"nonce": "N2"}) is None
    # AnyOf
    assert store.update_if("proposals", {"proposal_id": "p"}, {"status": "PENDING_SIG"},
                           {"status": AnyOf(MISSING, "PENDING_SIG")})
    assert store.update_if("proposals", {"proposal_id": "p"}, {"status": "EXECUTED"},
                           {"status": AnyOf(MISSING, "PENDING_SIG")})
    assert not store.update_if("proposals", {"proposal_id": "p"}, {"status": "DENIED"},
                               {"status": AnyOf(MISSING, "PENDING_SIG")})
    assert store.get("proposals", {"proposal_id": "p"}) == {"proposal_id": "p", "status": "EXECUTED"}
    # map equality
    store.put("ledger", {"tx_id": "t", "rail": {"status": "PENDING", "xml_c14n_sha256": None}})
    assert store.update_if("ledger", {"tx_id": "t"}, {"rail": {"status": "ACTC", "xml_c14n_sha256": "h"}},
                           {"rail": {"status": "PENDING", "xml_c14n_sha256": None}})
    assert not store.update_if("ledger", {"tx_id": "t"}, {"rail": {"status": "ACTC", "xml_c14n_sha256": "z"}},
                               {"rail": {"status": "PENDING", "xml_c14n_sha256": None}})


def test_increment(store):
    assert store.increment("counters", {"name": "proposal_no"}, "value") == 1
    assert store.increment("counters", {"name": "proposal_no"}, "value") == 2
    assert store.increment("counters", {"name": "proposal_no"}, "value", by=5) == 7
    assert store.get("counters", {"name": "proposal_no"}) == {"name": "proposal_no", "value": 7}


def test_query_base_range_reverse_limit(store):
    for s in range(5):
        store.put("audit", {"log_id": "audit", "seq": s, "x": s})
    store.put("audit", {"log_id": "attest", "seq": 0})
    assert [r["seq"] for r in store.query("audit", ("log_id", "audit"))] == [0, 1, 2, 3, 4]
    assert [r["seq"] for r in store.query("audit", ("log_id", "audit"), sk_range=(1, 3))] == [1, 2, 3]
    assert [r["seq"] for r in store.query("audit", ("log_id", "audit"), reverse=True, limit=2)] == [4, 3]
    for i in range(3):
        store.put("checkpoints", {"log_id": "audit", "sk": f"{i * 10:012d}", "note": str(i)})
    rows = store.query("checkpoints", ("log_id", "audit"), reverse=True, limit=1)
    assert rows == [{"log_id": "audit", "sk": f"{20:012d}", "note": "2"}]
    assert len(store.query("checkpoints", ("log_id", "audit"), sk_range=(f"{0:012d}", f"{10:012d}"))) == 2


def test_query_index(store):
    store.put("ledger", {"tx_id": "a", "vendor_id": "v1", "executed_at": "2026-01-02"})
    store.put("ledger", {"tx_id": "b", "vendor_id": "v1", "executed_at": "2026-01-01"})
    store.put("ledger", {"tx_id": "c", "vendor_id": "v2", "executed_at": "2026-01-03"})
    store.put("ledger", {"tx_id": "d", "executed_at": "2026-01-03"})  # not indexed
    assert [r["tx_id"] for r in store.query("ledger", ("vendor_id", "v1"), index="by_vendor")] == ["b", "a"]
    assert [r["tx_id"] for r in store.query("ledger", ("vendor_id", "v1"), index="by_vendor", reverse=True,
                                            limit=1)] == ["a"]
    store.put("mandates", {"mandate_id": "m1", "status": "ACTIVE", "mandate_no": 2})
    store.put("mandates", {"mandate_id": "m2", "status": "ACTIVE", "mandate_no": 1})
    store.put("mandates", {"mandate_id": "m3", "status": "REVOKED", "mandate_no": 3})
    assert [r["mandate_id"] for r in store.query("mandates", ("status", "ACTIVE"), index="by_status")] == ["m2", "m1"]


def test_query_main_gsi1_entity_filter(store):
    store.put("proposals", {"proposal_id": "p1", "gsi1pk": "vendor#v1", "gsi1sk": "2026-01-02"})
    store.put("proposals", {"proposal_id": "p2", "gsi1pk": "vendor#v1", "gsi1sk": "2026-01-01"})
    store.put("changes", {"change_id": "c1", "gsi1pk": "vendor#v1", "gsi1sk": "2026-01-01T00"})
    rows = store.query("proposals", ("gsi1pk", "vendor#v1"), index="gsi1")
    assert [r["proposal_id"] for r in rows] == ["p2", "p1"]
    assert all("pk" not in r and "sk" not in r for r in rows)
    assert [r["change_id"] for r in store.query("changes", ("gsi1pk", "vendor#v1"), index="gsi1")] == ["c1"]
    assert [r["proposal_id"] for r in store.query("proposals", ("gsi1pk", "vendor#v1"), index="gsi1",
                                                  limit=1, reverse=True)] == ["p1"]
    assert [r["proposal_id"] for r in store.query("proposals", ("proposal_id", "p1"))] == ["p1"]


def test_scan(store):
    store.put("registry", {"vendor_id": "v1"})
    store.put("registry", {"vendor_id": "v2"})
    assert sorted(r["vendor_id"] for r in store.scan("registry")) == ["v1", "v2"]
    assert store.scan("witness_state") == []


def test_transact_all_or_nothing(store):
    store.put("mandates", {"mandate_id": "m", "status": "ACTIVE", "spent_minor": 0, "count": 0})
    ok = store.transact([Put("ledger", {"tx_id": "t1"}, if_absent_key="tx_id"),
                         IncrementBounded("mandates", {"mandate_id": "m"}, {"spent_minor": 50, "count": 1},
                                          {"spent_minor": 100, "count": 5}, {"status": "ACTIVE"}),
                         UpdateIf("proposals", {"proposal_id": "p"}, {"status": "EXECUTED"}, {"status": MISSING})])
    assert ok
    assert store.get("mandates", {"mandate_id": "m"})["spent_minor"] == 50
    # second: bound exceeded -> nothing written
    assert not store.transact([Put("ledger", {"tx_id": "t2"}, if_absent_key="tx_id"),
                               IncrementBounded("mandates", {"mandate_id": "m"}, {"spent_minor": 51, "count": 1},
                                                {"spent_minor": 100, "count": 5}, {"status": "ACTIVE"})])
    assert store.get("ledger", {"tx_id": "t2"}) is None
    assert store.get("mandates", {"mandate_id": "m"}) == {"mandate_id": "m", "status": "ACTIVE", "spent_minor": 50,
                                                          "count": 1}
    # duplicate Put key -> nothing written
    assert not store.transact([Put("registry", {"vendor_id": "zz"}),
                               Put("ledger", {"tx_id": "t1", "x": 1}, if_absent_key="tx_id")])
    assert store.get("registry", {"vendor_id": "zz"}) is None
    # impossible bound (by alone exceeds max)
    assert not store.transact([IncrementBounded("mandates", {"mandate_id": "m"}, {"count": 9}, {"count": 5})])


def test_transact_token_idempotency(store, request):
    if request.node.callspec.params["store"] == "moto":
        pytest.skip("moto does not emulate ClientRequestToken idempotency (real DynamoDB does)")
    ops = [Put("ledger", {"tx_id": "t1"}, if_absent_key="tx_id")]
    assert store.transact(ops, client_request_token="tok1")
    assert store.transact(ops, client_request_token="tok1")  # same token + same ops: success, not re-applied
    assert store.scan("ledger") == [{"tx_id": "t1"}]
    other = [Put("ledger", {"tx_id": "t2"}, if_absent_key="tx_id")]
    assert not store.transact(other, client_request_token="tok1")
    assert store.get("ledger", {"tx_id": "t2"}) is None


# ------------------------------------------------------------------ tx_execute (§3.2)

S = Settings(backend="memory", fake_now="2026-10-19T10:00:00Z")


def _seed(store, *, status="ACTIVE", spent=0, count=0, max_total=100_000, max_count=3):
    ensure_head(store)
    store.put("mandates", {"mandate_id": "mdt_1", "status": status, "spent_minor": spent, "count": count,
                           "max_total_minor": max_total, "max_count": max_count, "mandate_no": 1})


def _args(tx_id="tx_1", amount=10_000, proposal_id="prp_1", mandate=True, max_total=100_000, max_count=3):
    auth = {"kind": "mandate", "mandate_id": "mdt_1"} if mandate else {"kind": "stepup", "nonce": "N1"}
    row = {"tx_id": tx_id, "proposal_id": proposal_id, "vendor_id": "v1", "iban": "CZ00", "amount_minor": amount,
           "currency": "CZK", "authorization": auth, "executed_at": "2026-10-19T10:00:00Z",
           "rail": {"status": "PENDING", "xml_c14n_sha256": None}}
    ev = shims.make_event("execution", {"tx_id": tx_id, "proposal_id": proposal_id}, subject_id=proposal_id,
                          actor="executor", settings=S)
    debit = {"mandate_id": "mdt_1", "amount_minor": amount, "max_total_minor": max_total,
             "max_count": max_count} if mandate else None
    return {"leaf_event": ev, "ledger_row": row, "proposal_id": proposal_id, "mandate_debit": debit}


def _snapshot(store):
    return {t: sorted(map(repr, store.scan(t))) for t in ("audit", "ledger", "mandates", "proposals")}


def test_tx_execute_mandate_happy(store):
    _seed(store)
    seq = tx_execute(store, expected_seq=0, **_args())
    assert seq == 0 and next_seq(store) == 1
    assert store.get("ledger", {"tx_id": "tx_1"})["seq"] == 0
    assert store.get("audit", {"log_id": "audit", "seq": 0})["leaf_hash"]
    m = store.get("mandates", {"mandate_id": "mdt_1"})
    assert (m["spent_minor"], m["count"]) == (10_000, 1)
    p = store.get("proposals", {"proposal_id": "prp_1"})
    assert p["status"] == "EXECUTED" and p["tx_id"] == "tx_1"


def test_tx_execute_stepup_happy_with_proposal_set(store):
    _seed(store)
    store.put("proposals", {"proposal_id": "prp_1", "status": "PENDING_SIG"})
    tx_execute(store, expected_seq=0, proposal_set={"proposal_no": 7}, **_args(mandate=False))
    p = store.get("proposals", {"proposal_id": "prp_1"})
    assert (p["status"], p["proposal_no"]) == ("EXECUTED", 7)
    assert store.get("mandates", {"mandate_id": "mdt_1"})["count"] == 0


def test_tx_execute_leaf_tx_id_mismatch(store):
    a = _args()
    a["ledger_row"] = {**a["ledger_row"], "tx_id": "tx_other"}
    with pytest.raises(ValueError):
        tx_execute(store, expected_seq=0, **a)


@pytest.mark.parametrize("case", ["head_seq", "overspend", "count", "not_active", "dup_tx", "proposal_executed"])
def test_tx_execute_conflicts_write_nothing(store, case):
    _seed(store, status="SUSPENDED" if case == "not_active" else "ACTIVE",
          spent=95_000 if case == "overspend" else 0, count=3 if case == "count" else 0)
    expected = 0
    if case == "head_seq":
        expected = 5
    if case == "dup_tx":
        store.put("ledger", {"tx_id": "tx_1", "proposal_id": "old"})
    if case == "proposal_executed":
        store.put("proposals", {"proposal_id": "prp_1", "status": "EXECUTED"})
    before = _snapshot(store)
    with pytest.raises(TxConflict):
        tx_execute(store, expected_seq=expected, **_args())
    assert _snapshot(store) == before
