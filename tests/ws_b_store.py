"""WS-B test helpers on WS-A's MemoryStore (CONTRACTS.md v2 §3.3; dev/CI backend)."""
from __future__ import annotations

from dataclasses import replace
from typing import Any

from executor.config import Settings
from executor.store.memory import MemoryStore


class FakeStore(MemoryStore):
    """MemoryStore with default settings; `tables` exposes the raw tables for tests that clone a store."""

    def __init__(self, settings: Any = None) -> None:
        super().__init__(settings or Settings())

    @property
    def tables(self) -> dict[str, Any]:
        return self._tables

    @tables.setter
    def tables(self, value: dict[str, Any]) -> None:
        self._tables = value


def make_settings(tmp_path, **kw) -> Settings:
    return replace(Settings(), local_key_dir=str(tmp_path / "keys"), **kw)


H = "ab" * 32  # placeholder digest (inputs/facts/hints) for test leaves
CLERK, TREASURY = "0x" + "c1" * 20, "0x" + "7e" * 20


def _ev(t, data, subject_id=None, actor="executor", ts=None):
    from executor.audit import log
    from executor.models import DECISION_RELEVANT_EVENTS
    from executor.policy.rules import policy_hash

    digests = ({"policy_hash": policy_hash(), "inputs_digest": H, "facts_digest": H, "hints_digest": H}
               if t in {e.value for e in DECISION_RELEVANT_EVENTS} else {})
    return log.make_event(t, data, subject_id=subject_id, actor=actor, ts=ts, **digests)


def _sig(nonce, purpose, role, addr, subject_id):
    t = "cd" * 32
    return [_ev("challenge", {"nonce": nonce, "nonce_secret_sha256": H, "purpose": purpose, "role": role,
                              "subject_id": subject_id, "deployment": "DEMO", "profile": "safe5-mono-18x7",
                              "text_sha256": t, "subject_hash": H, "exp": "2026-10-19T12:10:00Z"}, subject_id),
            _ev("signature", {"nonce": nonce, "purpose": purpose, "role": role, "signer_address": addr,
                              "text_sha256": t, "sig": "0x" + "11" * 65, "accepted": True, "error": None},
                subject_id, actor="host")]


def demo_events(n_payments: int = 2) -> list[dict]:
    """A plausible event mix for a fictitious company (enrolment, 2/2 mandate, payments, payee change)."""
    enroll = {"label": "test", "device_model": "Safe 5", "firmware_version": "2.8.0", "cert_chain_sha256": H,
              "fw_hash": H, "enroll_sig": "0x" + "22" * 65, "active": True}
    evs = [_ev("enroll", {"address": CLERK, "role": "clerk", "device": "GENUINE", "derivation_path": "m/44'/60'/0'/0/0",
                          **enroll}, actor="tools"),
           _ev("enroll", {"address": TREASURY, "role": "treasury", "device": "EMULATOR",
                          "derivation_path": "m/44'/60'/0'/0/1", **enroll}, actor="tools")]
    for i, (role, addr) in enumerate((("clerk", CLERK), ("treasury", TREASURY)), 1):
        evs += _sig(f"A000000{i}", "MANDATE", role, addr, "mnd_1")
        evs.append(_ev("mandate_signed", {"mandate_id": "mnd_1", "mandate_no": 1, "signer_address": addr,
                                          "role": role, "nonce": f"A000000{i}", "sig_index": i, "sig_total": 2,
                                          "status": "ACTIVE" if i == 2 else "PENDING_SIG", "fields": {}}, "mnd_1"))
    for p in range(1, n_payments + 1):
        pid, tx = f"prp_{p}", f"tx_{p:016x}"
        pay = {"vendor_id": "ven_00000001", "iban": "CZ6508000000192000145399", "amount_minor": 100000 * p,
               "currency": "CZK"}
        evs += [_ev("proposal", {"proposal_id": pid, "invoice": {"invoice_no": f"FV-{p}", **pay}, "hints": []},
                    pid, actor="tools"),
                _ev("facts", {"subject_id": pid, "facts": [], "snapshots": {}}, pid),
                _ev("decision", {"subject_id": pid, "decision": "allow", "rule_ids": [], "mandate_id": "mnd_1"}, pid),
                _ev("execution", {"tx_id": tx, "proposal_id": pid, **pay,
                                  "authorization": {"kind": "mandate", "mandate_id": "mnd_1"}}, tx),
                _ev("rail_submitted", {"tx_id": tx, "format": "pain.001.001.09", "msg_id": f"MSG{p}",
                                       "xml_c14n_sha256": H, "status": "ACTC"}, tx, actor="rail")]
    cid = "chg_1"

    def st(frm, to, event, ts=None):
        return _ev("state_transition", {"change_id": cid, "from": frm, "to": to, "event": event, "reason": ""}, cid,
                   ts=ts)

    evs += [st(None, "PENDING_ATTEST", "CREATE"),
            _ev("change_event", {"change_id": cid, "event": "cooling_scheduled",
                                 "detail": {"not_before": "2026-10-19T12:00:20.000Z"}}, cid),
            st("PENDING_ATTEST", "COOLING", "VC_RECEIVED", ts="2026-10-19T12:00:00.000Z"),
            st("COOLING", "SIG_CLERK", "COOLING_ELAPSED", ts="2026-10-19T12:00:21.000Z"),
            *_sig("C0000001", "CHG", "clerk", CLERK, cid),
            st("SIG_CLERK", "SIG_TREASURY", "CLERK_SIGNED"),
            *_sig("C0000002", "CHG", "treasury", TREASURY, cid),
            st("SIG_TREASURY", "ACTIVE", "TREASURY_SIGNED"),
            _ev("tool_call", {"session_id": "s1", "step": 1, "tool": "list_vendors", "args_sha256": H,
                              "result": "ok", "rule_ids": [], "untrusted_read": False}, actor="agent")]
    return evs


def build_log(store, settings, events=None, *, ledger: bool = False) -> None:
    """Append events (checkpoints + inproc W1 as configured), then tick so every leaf is covered."""
    from executor.audit import log

    for ev in demo_events() if events is None else events:
        seq = log.append(ev, store=store, settings=settings)
        if ledger and ev["type"] == "execution":
            d = ev["data"]
            store.put("ledger", {**{k: d[k] for k in ("tx_id", "proposal_id", "vendor_id", "iban", "amount_minor",
                                                      "currency", "authorization")},
                                 "seq": seq, "executed_at": "2026-10-19T12:00:00Z", "rail": {"status": "ACTC"}})
    log.tick(store=store, settings=settings)
