"""Security invariant tests (CONTRACTS.md v2 §8.2). Owners: WS-A (S6), WS-B (S6 lag, S12)."""
import itertools
import json

import pytest

CRASH_POINTS = (None, "before_transact", "inside_transact", "after_commit")


class _Crash(Exception):
    """Simulated process death."""


def _is_execution(ops):
    from executor.store import Put

    return any(isinstance(op, Put) and op.table == "ledger" for op in ops)


def _run_execution(store, settings, n, crash, monkeypatch):
    """One ledger.execute + rail submit with the process 'dying' at `crash`. Returns True if it committed."""
    from executor.bank import ledger
    from executor.rail import submit as rail
    from executor.store import shims

    orig_transact, orig_apply = store.transact, store._apply
    armed = {"apply": False}

    def transact(ops, client_request_token=None):
        if _is_execution(ops):
            if crash == "before_transact":
                raise _Crash
            armed["apply"] = crash == "inside_transact"
        return orig_transact(ops, client_request_token)

    def apply(op):
        if armed["apply"]:
            raise _Crash  # conditions checked, nothing applied yet
        return orig_apply(op)

    def after_commit(**kw):
        if crash == "after_commit":
            raise _Crash

    monkeypatch.setattr(store, "transact", transact)
    monkeypatch.setattr(store, "_apply", apply)
    monkeypatch.setattr(shims, "after_commit", after_commit)
    pid = f"prp_{n}"
    proposal = {"proposal_id": pid, "vendor_id": "v1", "iban": "CZ6508000000192000145399",
                "invoice": {"vendor_id": "v1", "amount_minor": 1000 + n, "currency": "CZK"}}
    auth = {"kind": "mandate", "mandate_id": "mdt_1"}
    try:
        tx = ledger.execute(proposal, auth, store=store, settings=settings,
                            mandate=store.get("mandates", {"mandate_id": "mdt_1"}))
        rail.submit(tx, store=store, settings=settings)
    except _Crash:
        pass
    finally:
        monkeypatch.setattr(store, "transact", orig_transact)
        monkeypatch.setattr(store, "_apply", orig_apply)
        monkeypatch.undo()  # restore shims.after_commit too ("restart")
    return store.get("ledger", {"tx_id": ledger.tx_id_for("mdt_1", pid)}) is not None


def _assert_invariants(store):
    leaves = {i["seq"]: json.loads(i["event"]) for i in store.query("audit", ("log_id", "audit")) if "event" in i}
    rows = store.scan("ledger")
    for row in rows:
        leaf = leaves.get(row["seq"])
        assert leaf is not None and leaf["type"] == "execution" and leaf["data"]["tx_id"] == row["tx_id"]
    executed_leaves = {e["data"]["tx_id"] for e in leaves.values() if e["type"] == "execution"}
    assert executed_leaves == {r["tx_id"] for r in rows}
    m = store.get("mandates", {"mandate_id": "mdt_1"})
    assert m["spent_minor"] == sum(r["amount_minor"] for r in rows)
    assert m["count"] == len(rows)
    for p in store.scan("proposals"):
        assert p["status"] != "EXECUTED" or store.get("ledger", {"tx_id": p["tx_id"]}) is not None


def test_s6_crash_between(monkeypatch):
    from executor.config import Settings
    from executor.rail import submit as rail
    from executor.store import get_store

    settings = Settings(backend="memory", fake_now="2026-10-19T10:00:00Z")
    for crashes in itertools.product(CRASH_POINTS, repeat=3):
        store = get_store(settings)
        store.put("mandates", {"mandate_id": "mdt_1", "status": "ACTIVE", "spent_minor": 0, "count": 0,
                               "max_total_minor": 10**9, "max_count": 100, "mandate_no": 1})
        unsubmitted = []
        for n, crash in enumerate(crashes):
            committed = _run_execution(store, settings, n, crash, monkeypatch)
            assert committed == (crash in (None, "after_commit")), (crashes, n)
            if crash == "after_commit":
                from executor.bank.ledger import tx_id_for

                unsubmitted.append(tx_id_for("mdt_1", f"prp_{n}"))
            _assert_invariants(store)
        assert rail.recover_unsubmitted(store=store, settings=settings) == unsubmitted, crashes
        assert rail.recover_unsubmitted(store=store, settings=settings) == []
        assert all(r["rail"]["status"] == "ACTC" for r in store.scan("ledger"))
        _assert_invariants(store)


def test_s6_checkpoint_lag():
    pytest.skip("TODO WS-B: every execution covered by a witnessed checkpoint within 60 s")


def test_s12_replay():
    pytest.skip("TODO WS-B: verify_audit --replay reproduces every decision at its policy_hash")
