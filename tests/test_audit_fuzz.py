"""Security invariant tests (CONTRACTS.md v2 §8.2). Owners: WS-A (S6), WS-B (S6 lag, S12, mutation property)."""
from __future__ import annotations

import copy
import itertools
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from executor.audit import checkpoint as cp
from executor.audit import log
from tests.ws_b_store import FakeStore, build_log, demo_events, make_settings
from tools import verify_audit as va

T0 = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _dt(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))

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


def test_s6_checkpoint_lag(tmp_path):
    """Leaves arrive every 7 s (simulated clock), the scheduler ticks every 30 s, no size trigger: every execution
    leaf is covered by a W1-cosigned checkpoint created within 60 s of the leaf's ts."""
    base = make_settings(tmp_path, checkpoint_every_n_leaves=10_000, checkpoint_max_seconds=30)
    store = FakeStore()
    events = [{**ev, "ts": None} for ev in demo_events(4)]
    for t in range(0, 7 * len(events) + 61):
        s = replace(base, fake_now=_iso(T0 + timedelta(seconds=t)))
        if t % 7 == 0 and t // 7 < len(events):
            log.append(events[t // 7], store=store, settings=s)
        if t % 30 == 0:
            log.tick(store=store, settings=s)

    vk = cp.vkeys(base)
    w1 = cp.witness_name(base)
    cosigned = []
    for row in sorted(store.query("checkpoints", log.checkpoint_pk("audit")), key=lambda r: r["created_at"]):
        if w1 in cp.verify_note(row["note"], [vk["log"], vk["w1"]])["verified"]:
            cosigned.append((int(row["size"]), _dt(row["created_at"])))
    executions = [(int(r["seq"]), _dt(r["ts"])) for r in log.leaves("audit", store=store)
                  if '"type":"execution"' in r["event"]]
    assert len(executions) == 4
    for seq, ts in executions:
        cover = next((c for size, c in cosigned if size > seq and c >= ts), None)
        assert cover is not None, f"seq {seq}: no cosigned checkpoint covers it"
        assert cover - ts <= timedelta(seconds=60), f"seq {seq}: covered after {cover - ts}"


def test_s12_replay():
    """verify_audit --replay re-runs decide() for every decision leaf of a real executor run (allow, deny, challenge,
    step-up recheck) at its policy_hash; a tampered decision is caught and named by seq."""
    from tests.wsa_helpers import Harness

    h = Harness()
    h.mandate()
    h.propose(1_000_000)
    h.propose(1_000_000)  # duplicate -> deny
    _, r = h.propose(12_500_050, vendor="ven_87654321", no="Z-1")
    h.submit(r["decision"]["challenge"], h.clerk)  # step-up recheck leaf
    log.tick(store=h.store, settings=h.settings)
    bundle = log.export("audit", store=h.store, settings=h.settings)
    rep = va.verify(bundle, replay=True)
    decisions = [le for le in bundle["leaves"] if le["event"]["type"] == "decision"]
    assert len(decisions) == 4 and rep.checked.get("replayed") == 4
    assert not [p for p in rep.problems if "replay" in p or "decide" in p], rep.problems

    bad = copy.deepcopy(bundle)
    le = next(x for x in bad["leaves"] if x["event"]["type"] == "decision" and x["event"]["data"]["decision"] == "allow")
    le["event"]["data"]["decision"] = "deny"
    rep = va.verify(bad, replay=True)
    assert any(p.startswith(f"seq {le['seq']}: replay gives allow") for p in rep.problems), rep.problems


# property: any single mutation of a checkpoint-covered leaf is detected and named
@pytest.fixture(scope="module")
def keydir(tmp_path_factory):
    return tmp_path_factory.mktemp("fuzzkeys")


def _random_events(draw, n):
    tools = draw(st.lists(st.sampled_from(["list_vendors", "get_invoice", "propose_payment", "read_email"]),
                          min_size=n, max_size=n))
    return [log.make_event("tool_call", {"session_id": "s1", "step": i, "tool": t, "args_sha256": "ab" * 32,
                                         "result": "ok", "rule_ids": [], "untrusted_read": i % 3 == 0},
                           subject_id=None, actor="agent") for i, t in enumerate(tools)]


@settings(max_examples=100, deadline=None)
@given(data=st.data())
def test_property_single_mutation_detected(keydir, data):
    n = data.draw(st.integers(3, 30), label="leaves")
    s = make_settings(keydir, checkpoint_every_n_leaves=data.draw(st.integers(1, 7), label="every"))
    store = FakeStore()
    build_log(store, s, _random_events(data.draw, n))
    bundle = log.export("audit", store=store, settings=s)
    rep = va.verify(bundle, replay=False)
    assert rep.ok, rep.problems
    covered = rep.checked["covered_leaves"]  # mutating the uncovered tail is only caught by the next checkpoint

    b = copy.deepcopy(bundle)
    lv = b["leaves"]
    kind = data.draw(st.sampled_from(["delete", "swap", "swap_events", "edit", "edit_rehash"]), label="kind")
    i = data.draw(st.integers(0, covered - 1), label="i")
    if kind == "delete":
        del lv[i]
        needle = f"seq {i}: missing"
    elif kind in ("swap", "swap_events"):
        j = data.draw(st.integers(0, covered - 1).filter(lambda x: x != i), label="j")
        if kind == "swap":
            lv[i], lv[j] = lv[j], lv[i]
        else:
            lv[i]["event"], lv[j]["event"] = lv[j]["event"], lv[i]["event"]
        needle = f"seq {min(i, j)}:"
    else:
        ev = lv[i]["event"]
        ev["actor"] = "host" if ev["actor"] != "host" else "agent"
        if kind == "edit_rehash":
            lv[i]["leaf_hash"] = log.leaf_hash(ev)
            needle = "root mismatch"
        else:
            needle = f"seq {i}: leaf hash mismatch"
    rep = va.verify(b, replay=False)
    assert not rep.ok
    assert needle in "\n".join(rep.problems), (kind, rep.problems)


def _enroll_leaves(h):
    """Harness enrols via seed.enroll_signer (table only, no ceremony); log the enroll leaves the real ceremony
    (tools/enroll.py) writes, so the verifier can check signer enrolment."""
    for acct, role, device, i in ((h.clerk, "clerk", "GENUINE", 0), (h.treasury, "treasury", "EMULATOR", 1)):
        log.append(log.make_event("enroll", {"address": acct.address.lower(), "role": role, "label": role,
                                             "device": device, "device_model": "T3T1", "firmware_version": "2.12.5",
                                             "cert_chain_sha256": "ab" * 32, "fw_hash": "ab" * 32,
                                             "derivation_path": f"m/44'/60'/0'/0/{i}", "enroll_sig": "0x"},
                                  subject_id=None, actor="tools"), store=h.store, settings=h.settings)


def test_real_executor_run_verifies():
    """A real executor run (2/2 mandate, allow, duplicate deny, challenge + PAY step-up, tick, export) verifies with
    replay and the review's semantic checks (step-up signature, mandate signers, uncovered tail)."""
    from tests.wsa_helpers import Harness

    h = Harness()
    _enroll_leaves(h)
    h.mandate()
    assert h.propose(1_000_000)[0] in (200, 201)
    h.propose(1_000_000)  # duplicate -> deny
    _, r = h.propose(12_500_050, vendor="ven_87654321", no="Z-1")
    assert r["decision"]["decision"] == "challenge"
    st_, sr = h.submit(r["decision"]["challenge"], h.clerk)
    assert st_ == 200 and sr["effect"]["type"] == "payment_executed"
    log.tick(store=h.store, settings=h.settings)
    bundle = log.export("audit", store=h.store, settings=h.settings)
    rep = va.verify(bundle, replay=True)
    assert rep.ok, rep.problems
    c = rep.checked
    assert c["replayed"] == 4 and c["executions"] == 2 and c["mandates_active_quorum"] == 1
    assert c["uncovered_leaves"] == 0 and c["signers_enrolled"] == 3

    # drop the PAY step-up signature: the challenged execution is no longer backed by a signature
    bad = copy.deepcopy(bundle)
    sig = next(le for le in bad["leaves"] if le["event"]["type"] == "signature"
               and le["event"]["data"]["purpose"] == "PAY")
    sig["event"]["data"]["accepted"] = False
    sig["leaf_hash"] = log.leaf_hash(sig["event"])
    rep = va.verify(bad, replay=True)
    assert any("after a challenge decision" in p and "without an accepted PAY signature" in p for p in rep.problems)
