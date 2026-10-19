"""Pure decision function, Cedar via cedarpy (replayed offline by tools/verify_audit.py). CONTRACTS.md v2 §2.2, §8.1.

No I/O, no LLM, no clock. Owner: WS-A.
decide() first projects its arguments onto decide_inputs() (the exact JSON-able leaf inputs) and evaluates only the
projection, so decide(**decide_inputs(s, f, st), policy=p) == decide(s, f, st, p) (S12).
"""
from __future__ import annotations

import re
from typing import Any

import cedarpy

from executor.canonical import canonical_json, sha256_hex
from executor.models import DecisionObj, FactSet
from executor.policy import invariants as inv
from executor.policy.rules import policy_ids

_SET_NAMES = {"1": "hard_deny", "2": "mandate_allow", "3": "change"}
_SET_RE = re.compile(r"^// Policy set (\d) of 3", re.M)
_MANDATE_KEYS = ("mandate_id", "status", "policy_hash", "max_per_payment_minor", "max_total_minor", "max_count",
                 "spent_minor", "count", "valid_from", "valid_until", "require_vop", "max_anom",
                 "payee_registry_version")
# Forbids that only compare against the (all-zero) Mandate::"none" caps; noise when there is no mandate at all.
_NONE_MANDATE_NOISE = frozenset({"I-EXP", "I-PER", "I-BUDGET", "I-COUNT", "I-VOP", "I-ANOM", "I-SPLIT"})


# ---------------------------------------------------------------- policy material

def policy_sets(policy: dict[str, Any]) -> dict[str, str]:
    """Split policy['cedar_policies_text'] back into {'hard_deny', 'mandate_allow', 'change'} on the leading
    `// Policy set N of 3` comment of each file (works for any logged material, not just the current files)."""
    text = policy["cedar_policies_text"]
    starts = [(m.start(), m.group(1)) for m in _SET_RE.finditer(text)]
    out = {}
    for i, (pos, n) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(text)
        out[_SET_NAMES[n]] = text[pos:end]
    if set(out) != set(_SET_NAMES.values()):
        raise ValueError("cedar_policies_text does not contain the three policy sets")
    return out


def policy_hash_of(policy: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(policy))


def _authorize(text: str, request: dict[str, Any], entities: list[dict[str, Any]],
               schema: dict[str, Any]) -> tuple[bool, list[str]]:
    """(allowed, sorted determining forbid @ids). P-* permits are never returned."""
    r = cedarpy.is_authorized(request, text, entities, schema=schema)
    if r.diagnostics.errors:
        raise ValueError(f"cedar evaluation error: {list(r.diagnostics.errors)}")
    ids = policy_ids(text)
    hit = {ids[int(p.removeprefix("policy"))] for p in r.diagnostics.reasons}
    return r.decision == cedarpy.Decision.Allow, sorted(i for i in hit if not i.startswith("P-"))


# ---------------------------------------------------------------- inputs (leaf)

def _proj_invoice(i: dict[str, Any]) -> dict[str, Any]:
    return {"vendor_id": i.get("vendor_id"), "invoice_no": i.get("invoice_no", ""),
            "issue_date": i.get("issue_date"), "amount_minor": int(i.get("amount_minor", 0))}


def decide_inputs(subject: dict[str, Any], facts: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """Exact JSON-able inputs of decide() (ints/strings/bools/None only). Idempotent; IBANs are not included."""
    m = state.get("mandate")
    p = state.get("payee")
    payee = None if p is None else {
        "active_iban": bool(p.get("iban") or p.get("active_iban")),
        "status": p.get("status", "ACTIVE"),
        "in_network": bool(p.get("in_network")),
    }
    reg_hit = state.get("reg_hit")
    return {
        "subject": {"proposal_id": subject.get("proposal_id"), "invoice": _proj_invoice(subject["invoice"])},
        "facts": {"facts": list(facts["facts"]), "facts_digest": facts["facts_digest"]},
        "state": {
            "mandate": None if m is None else {k: m.get(k) for k in _MANDATE_KEYS},
            "payee": payee,
            "proposals": [{"proposal_id": x.get("proposal_id"), "status": x.get("status"),
                           "invoice": _proj_invoice({"vendor_id": x.get("vendor_id"), **(x.get("invoice") or {})})}
                          for x in state.get("proposals") or [] if x.get("status") in inv.DUP_STATUSES],
            "history": [{"vendor_id": r.get("vendor_id"), "amount_minor": int(r["amount_minor"]),
                         "executed_at": r["executed_at"]} for r in state.get("history") or []],
            "now": state["now"] if isinstance(state["now"], str) else inv.to_datetime(state["now"]).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
            "reg_hit": bool(reg_hit) if reg_hit is not None else p is not None,
        },
    }


def inputs_digest(subject: dict[str, Any], facts: dict[str, Any], state: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(decide_inputs(subject, facts, state)))


# ---------------------------------------------------------------- decide

def _mandate_entity(m: dict[str, Any] | None, phash: str) -> dict[str, Any]:
    if m is None:
        attrs = dict(status="NONE", policy_current=False, max_per_payment_minor=0, max_total_minor=0, max_count=0,
                     spent_minor=0, count=0, valid_from=0, valid_until=0, require_vop=[], max_anom=0,
                     payee_registry_version=0)
        mid = "none"
    else:
        attrs = dict(status=str(m.get("status")), policy_current=m.get("policy_hash") == phash,
                     max_per_payment_minor=int(m.get("max_per_payment_minor") or 0),
                     max_total_minor=int(m.get("max_total_minor") or 0), max_count=int(m.get("max_count") or 0),
                     spent_minor=int(m.get("spent_minor") or 0), count=int(m.get("count") or 0),
                     valid_from=inv.epoch(m.get("valid_from")), valid_until=inv.epoch(m.get("valid_until")),
                     require_vop=sorted(m.get("require_vop") or []),
                     max_anom=int(m["max_anom"]) if m.get("max_anom") is not None
                     else inv.PARAMS["I-ANOM"]["default_max_anom"],
                     payee_registry_version=int(m.get("payee_registry_version") or 0))
        mid = str(m["mandate_id"])
    return {"uid": {"type": "Mandate", "id": mid}, "attrs": attrs, "parents": []}


def _fact_ids(facts: Any, severities: tuple[str, ...]) -> set[str]:
    return {f["id"] for f in inv.f_facts(facts) if f["severity"] in severities}


def decide(subject: dict[str, Any], facts: FactSet, state: dict[str, Any], policy: dict[str, Any]) -> DecisionObj:
    """Tri-state decision for a payment proposal.

    subject: {"proposal_id", "invoice": {vendor_id, invoice_no, issue_date, amount_minor, ...}}.
    facts:   FactSet from executor.facts.compute.compute() (H facts are ignored entirely).
    state:   {"mandate": Mandate | None, "payee": registry row | None, "proposals": [prior proposals of the vendor],
              "history": [ledger rows of the vendor], "now": iso str, optional "reg_hit": bool}.
    policy:  executor.policy.rules.policy_material() (or the logged material for policy_hash on replay).
    Returns the Decision object without 'challenge' (the caller attaches it iff decision == "challenge").
    rule_ids = sorted(determining forbid @ids | F ids of BLOCK/WARN facts); allow => [].
    """
    x = decide_inputs(subject, facts, state)
    subject, facts, state = x["subject"], x["facts"], x["state"]
    phash = policy_hash_of(policy)
    sets = policy_sets(policy)
    schema = policy["cedar_schema"]
    m, p = state["mandate"], state["payee"]
    vendor = subject["invoice"]["vendor_id"]
    mandate = _mandate_entity(m, phash)
    payee = {"uid": {"type": "Payee", "id": str(vendor)},
             "attrs": {"known": p is not None, "active": p is not None and p["active_iban"] and p["status"] == "ACTIVE",
                       "in_network": bool(p and p["in_network"])}, "parents": []}
    request = {"principal": f'Mandate::"{mandate["uid"]["id"]}"', "action": 'Action::"pay"',
               "resource": f'Payee::"{vendor}"', "context": inv.cedar_context(subject, facts, state)}
    entities = [mandate, payee]
    flagged = _fact_ids(facts, ("BLOCK", "WARN"))

    allowed, forbids = _authorize(sets["hard_deny"], request, entities, schema)
    if not allowed:
        outcome, rule_ids = "deny", sorted(set(forbids) | flagged)
    else:
        allowed, forbids = _authorize(sets["mandate_allow"], request, entities, schema)
        if allowed:
            outcome, rule_ids = "allow", []
        else:
            if m is None:
                forbids = [i for i in forbids if i not in _NONE_MANDATE_NOISE]
            outcome, rule_ids = "challenge", sorted(set(forbids) | flagged) or ["I-MANDATE"]
    return {"decision": outcome, "rule_ids": rule_ids, "facts": facts["facts"], "facts_digest": facts["facts_digest"],
            "mandate_id": None if m is None else m["mandate_id"], "policy_hash": phash}


def may_issue_chg_challenge(change: dict[str, Any], facts: FactSet, *, now: Any,
                            policy: dict[str, Any]) -> tuple[bool, list[str]]:
    """Policy set `change` (I-ATTEST, I-CALLBACK, I-COOLOFF, I-BLOCK): (allowed, rule_ids). R0.

    rule_ids = sorted(determining forbid @ids | F ids of BLOCK facts). Any BLOCK fact => (False, ...).
    """
    blocks = _fact_ids(facts, ("BLOCK",))
    principal = {"uid": {"type": "Change", "id": str(change["change_id"])},
                 "attrs": {"state": str(change.get("state", "")), "in_network": bool(change.get("in_network")),
                           "break_glass": bool(change.get("break_glass")),
                           "not_before": inv.epoch(change.get("not_before"))}, "parents": []}
    resource = {"uid": {"type": "Payee", "id": str(change["vendor_id"])},
                "attrs": {"known": True, "active": True, "in_network": bool(change.get("in_network"))}, "parents": []}
    request = {"principal": f'Change::"{change["change_id"]}"', "action": 'Action::"issue_chg_challenge"',
               "resource": f'Payee::"{change["vendor_id"]}"',
               "context": {"attest_count": int(change.get("attest_count") or 0),
                           "callback_confirmed": (change.get("callback") or {}).get("status") == "confirmed",
                           "block_hit": bool(blocks), "now": inv.epoch(now)}}
    allowed, forbids = _authorize(policy_sets(policy)["change"], request, [principal, resource], policy["cedar_schema"])
    return allowed and not blocks, sorted(set(forbids) | blocks)
