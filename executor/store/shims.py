"""Fallbacks for cross-workstream functions that have not landed yet (WS-B audit, WS-C sig, WS-D facts).

Every wrapper calls the owner's function first and only falls back when it raises NotImplementedError, so the
owner's implementation takes over automatically on merge. The fallbacks follow CONTRACTS v2 byte for byte where
the contract fixes the bytes (leaf v2, audit row, EIP-191); the facts fallback is a labelled stub
(evidence.source = "ws-a-fallback") that only produces the WS-A-owned facts plus a VoP placeholder.

Owner: WS-A.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from executor.canonical import canonical_json, sha256_hex
from executor.store import TxConflict, ensure_head, leaf_ops, next_seq


def digest(obj: Any) -> str:
    return sha256_hex(canonical_json(obj))


# ---------------------------------------------------------------- audit (WS-B)

def _now_iso(settings: Any) -> str:
    from executor.config import now

    dt = now(settings)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def make_event(event_type: str, data: dict[str, Any], *, subject_id: str | None, actor: str, settings: Any,
               log_id: str = "audit", policy_hash: str | None = None, inputs_digest: str | None = None,
               facts_digest: str | None = None, hints_digest: str | None = None, ts: str | None = None
               ) -> dict[str, Any]:
    """Leaf v2 without seq (CONTRACTS §7.2)."""
    ts = ts or _now_iso(settings)
    try:
        from executor.audit import log

        return log.make_event(event_type, data, subject_id=subject_id, actor=actor, log_id=log_id,
                              policy_hash=policy_hash, inputs_digest=inputs_digest, facts_digest=facts_digest,
                              hints_digest=hints_digest, ts=ts)
    except NotImplementedError:
        pass
    return {"v": 2, "log_id": log_id, "ts": ts, "type": event_type, "actor": actor, "subject_id": subject_id,
            "data": data, "policy_hash": policy_hash, "inputs_digest": inputs_digest, "facts_digest": facts_digest,
            "hints_digest": hints_digest}


def append(event: dict[str, Any], *, store: Any, settings: Any) -> int:
    """Append one non-execution leaf (head-conditioned Put in its own transaction, §3.2); returns seq."""
    try:
        from executor.audit import log

        return log.append(event, store=store, settings=settings)
    except NotImplementedError:
        pass
    log_id = event.get("log_id", "audit")
    ensure_head(store, log_id)
    for _ in range(20):
        seq = next_seq(store, log_id)
        if store.transact(leaf_ops(event, seq)):
            from executor import oplog

            oplog.leaf({**event, "seq": seq}, seq)
            return seq
    raise TxConflict("audit head contention")


def after_commit(*, store: Any, settings: Any) -> None:
    """Hook after a leaf written by tx_execute (bypassing audit.append): let WS-B checkpoint if due."""
    try:
        from executor.audit import checkpoint

        fn = getattr(checkpoint, "maybe_checkpoint", None)
        if fn is not None:
            fn("audit", store=store, settings=settings)
    except NotImplementedError:
        pass


# ---------------------------------------------------------------- signatures (WS-C)

def verify_eip191(text: str, sig: str) -> str:
    try:
        from executor import sig as sigmod

        return sigmod.verify_eip191(text, sig)
    except NotImplementedError:
        pass
    from eth_account import Account
    from eth_account.messages import encode_defunct

    if not isinstance(sig, str) or not sig.startswith("0x") or len(sig) != 132:
        raise ValueError("malformed signature")
    try:
        return Account.recover_message(encode_defunct(text=text), signature=sig).lower()
    except Exception as e:  # noqa: BLE001 - any recovery failure is a bad signature
        raise ValueError(f"recovery failed: {e}") from e


# ---------------------------------------------------------------- facts (WS-D)

def compute_facts(subject: dict[str, Any], state: dict[str, Any], now: datetime) -> dict[str, Any]:
    """executor.facts.compute.compute(); fallback = WS-A ledger/mandate facts + VoP stub + H facts."""
    try:
        from executor.facts import compute

        return compute.compute(subject, state, now)
    except NotImplementedError:
        pass
    from executor.policy.facts_wsa import wsa_facts
    from executor.render import FACT_ORDER

    facts: list[dict[str, Any]] = []
    if subject.get("kind") == "proposal":
        facts += wsa_facts(subject, state, now)
        if state.get("payee"):
            facts.append({"id": "F-VOP", "kind": "F", "severity": "INFO", "label": "Verification of Payee (stub)",
                          "display_line": "VOP MTCH", "evidence": {"code": "MTCH", "source": "ws-a-fallback"}})
    order = {fid: i for i, fid in enumerate(FACT_ORDER)}
    facts.sort(key=lambda f: (order.get(f["id"], len(order)), "" if f["id"] in order else f["id"],
                              f["display_line"]))
    sev = [f["severity"] for f in facts]
    max_sev = "BLOCK" if "BLOCK" in sev else "WARN" if "WARN" in sev else "INFO"
    hints = [{"id": "H-AGENT" if h.get("source") == "agent" else "H-UI", "kind": "H", "severity": "INFO",
              "label": "Agent stated reason" if h.get("source") == "agent" else "Host hint",
              "display_line": str(h.get("text", ""))[:200]} for h in subject.get("hints", [])]
    return {"subject_id": subject.get("subject_id", ""), "computed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "facts": facts + hints, "facts_digest": digest(facts), "snapshots": {}, "max_severity": max_sev}
