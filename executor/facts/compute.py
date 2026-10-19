"""Facts engine: FactSet for a proposal or a payee change, pure over content-hashed snapshots. CONTRACTS.md v2 §2.1.

Owner: WS-D.

Every snapshot-derived fact carries `prov` = SHA-256 of the snapshot it was computed from, and FactSet.snapshots
lists name -> SHA-256 of every snapshot used, so verify_audit.py can replay a decision offline. No live calls here
(F-VAT live mode is opt-in via AIRGAP_ADIS_MODE and never on stage).
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from executor import render
from executor.config import iso
from executor.facts import _util
from executor.models import FACT_ORDER, Fact, FactSet

_SEV_RANK = {"INFO": 0, "WARN": 1, "BLOCK": 2}
_HINT_MAX = 200


def _fact_key(f: Fact) -> tuple[int, str, str]:
    fid = f["id"]
    idx = FACT_ORDER.index(fid) if fid in FACT_ORDER else len(FACT_ORDER)
    return (idx, fid if idx == len(FACT_ORDER) else "", f["display_line"])


def order_facts(facts: list[Fact]) -> list[Fact]:
    """F facts sorted by (FACT_ORDER index, unknown ids after by id, display_line), then H facts in input order."""
    f_facts = sorted((f for f in facts if f["kind"] == "F"), key=_fact_key)
    return f_facts + [f for f in facts if f["kind"] == "H"]


def facts_digest(facts: list[Fact]) -> str:
    """sha256(canonical_json([f for f in facts if f['kind'] == 'F'])) in canonical order."""
    return _util.digest([f for f in order_facts(facts) if f["kind"] == "F"])


def max_severity(facts: list[Fact]) -> str:
    sevs = [f["severity"] for f in facts if f["kind"] == "F"]
    return max(sevs, key=_SEV_RANK.__getitem__) if sevs else "INFO"


def _sanitize_hint(text: str) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]", " ", str(text))
    return " ".join(text.split())[:_HINT_MAX]


def hint_facts(hints: list[dict[str, Any]]) -> list[Fact]:
    """H-AGENT / H-UI facts, severity INFO; UI and log only, never on the device (S3: never in Cedar context)."""
    out: list[Fact] = []
    for h in hints or []:
        fid = "H-AGENT" if h.get("source") == "agent" else "H-UI"
        text = _sanitize_hint(h.get("text", ""))
        out.append({"id": fid, "kind": "H", "severity": "INFO", "label": f"hint from {h.get('source', 'ui')}",
                    "display_line": text})
    return out


def _translit_fact(name: str) -> Fact | None:
    try:
        shown = render.display_name(name)
    except render.RenderError:
        return None  # the renderer will fail closed on this name; nothing to report here
    if shown == " ".join(str(name).split()).upper():
        return None
    return _util.make_fact("F-NAME-TRANSLIT", "INFO", f"Name transliterated for the device: {name} -> {shown}",
                           "NAME TRANSLIT", evidence={"name": name, "shown": shown})


def _email_facts(email: dict[str, Any], payee: dict[str, Any], state: dict[str, Any], now: datetime,
                 snapshots: dict[str, str]) -> list[Fact]:
    from executor.facts import dkim, domain, domain_age

    out: list[Fact] = []
    from_domain = (email.get("from_domain") or "").lower()
    mr = _util.snapshot_path(state, "mostlyright")
    mr_path = mr if mr.exists() else None
    f = domain.domain_fact(from_domain, payee.get("domain", ""), mr_path=mr_path)
    out.append(f)
    if f.get("prov"):
        snapshots["mostlyright"] = f["prov"]
    dns_raw, dns_sha = _util.read_snapshot(_util.snapshot_path(state, "dns"))
    snapshots["dns"] = dns_sha
    out.append(dkim.dkim_fact(email.get("dkim") or {"result": "none"}, prov=dns_sha))
    out.append(domain_age.domain_age_fact(from_domain, _first_seen(from_domain, payee, state), now))
    return out


def _first_seen(from_domain: str, payee: dict[str, Any], state: dict[str, Any]) -> str | None:
    """First time we saw the sender domain: our inbox, or the registry when it is exactly the vendor's registered
    domain (known to us since enrolment). Lookalikes never equal the registered domain, so they stay new."""
    seen = [state["domain_first_seen"]] if state.get("domain_first_seen") else []
    registered = (payee.get("domain") or "").lower()
    if registered and from_domain == registered and payee.get("registered_since"):
        since = str(payee["registered_since"])
        seen.append(since if "T" in since else f"{since}T00:00:00Z")
    return min(seen) if seen else None


def compute(subject: dict[str, Any], state: dict[str, Any], now: datetime) -> FactSet:
    """subject: {"kind": "proposal"|"change", "subject_id", ...request fields}; for a change `new_iban` (+ `email_id`),
    for a proposal `invoice` (+ `hints`).
    state: {"payee": registry row (required), "email": inbox row or None (incl. the ingest `dkim` verdict),
    "domain_first_seen": iso str|None (inbox by_domain), "change": change row (for F-ATTEST / F-CALLBACK),
    "attest_results": [AttestResult], "tool_log": [tool_call rows], "mandate", "extra_facts": [Fact] (WS-A:
    F-MANDATE / F-DUP / F-SPLIT / F-Z), "snapshots": {name: path} overrides, "data_dir",
    "email_raw": raw .eml bytes|None (inbox.email_state; for a proposal F-AMOUNT-DOC is always computed and a
    missing source email blocks it and F-DKIM)}.
    Returns FactSet (F facts sorted by FACT_ORDER, then H facts; facts_digest over F facts only; prov on every
    snapshot-derived fact)."""
    from executor.facts import anom, attest_fact, callback, firstseen, iban_bank, psp, sanction, vat, vop, warnlist

    kind = subject.get("kind")
    if kind not in ("proposal", "change"):
        raise ValueError(f"subject.kind must be proposal|change, got {kind!r}")
    payee = state.get("payee") or {}
    if not payee:
        raise ValueError("state.payee (registry row) is required")
    name = payee["name"]
    ico = payee["ico"]
    iban = subject["new_iban"] if kind == "change" else payee["iban"]
    snapshots: dict[str, str] = {}
    facts: list[Fact] = []

    def add(f: Fact | None, snap: str | None = None) -> None:
        if f is None:
            return
        facts.append(f)
        if snap and f.get("prov"):
            snapshots[snap] = f["prov"]

    if kind == "change":
        change = state.get("change") or {}
        in_network = bool(payee.get("in_network"))
        break_glass = bool(change.get("break_glass"))
        add(attest_fact.attest_fact({"in_network": in_network, "break_glass": break_glass},
                                    state.get("attest_results") or []))
        if not in_network or break_glass:
            add(callback.callback_fact(change))

    if state.get("email"):
        facts.extend(_email_facts(state["email"], payee, state, now, snapshots))
    elif subject.get("email_id"):
        # The request cites an email the inbox does not hold: there is no verified sender at all (fail closed;
        # without this a made-up email_id would silently drop F-DOMAIN / F-DKIM).
        cited = str(subject["email_id"])[:64]
        add(_util.make_fact("F-DKIM", "BLOCK", f"Cited email {cited} is not in the inbox", "DKIM FAIL",
                            evidence={"result": "none", "d": None, "s": None, "aligned": False}))
    elif kind == "proposal":
        # A proposal must come from a source email (invoice.email_id is optional in the schema, and the tools
        # principal may be driven by a compromised agent): no email means no verified sender (fail closed).
        add(_util.make_fact("F-DKIM", "BLOCK", "No source email for the invoice: sender cannot be verified",
                            "DKIM FAIL", evidence={"result": "none", "d": None, "s": None, "aligned": False}))

    mr_path = _util.snapshot_path(state, "mostlyright")
    add(warnlist.warnlist_fact(name, [payee.get("domain", "")], mr_path=mr_path), "mostlyright")
    add(sanction.sanction_fact(name, ico, mr_path=mr_path), "mostlyright")
    add(vop.vop_fact(iban, name, vop_path=_util.snapshot_path(state, "vop")), "vop")
    if kind == "change":
        # Account binding: a proposal pays the registry's ACTIVE IBAN, which already passed the change flow (2/2).
        add(psp.psp_fact(iban, mr_path=mr_path, bank_codes_path=_util.snapshot_path(state, "bank_codes")),
            "mostlyright")
    add(vat.vat_fact(ico, iban, adis_path=_util.snapshot_path(state, "adis")), "adis")
    add(iban_bank.bank_fact(iban, payee.get("country", "CZ"),
                            bank_codes_path=_util.snapshot_path(state, "bank_codes")), "bank_codes")
    add(firstseen.firstseen_fact(iban, payee.get("iban_history") or [], now), "registry")
    add(anom.anom_fact(subject, state.get("tool_log") or [], payee=payee, mandate=state.get("mandate"), now=now),
        "toollog")
    add(_translit_fact(name))
    if kind == "proposal":
        from executor.facts.amount_doc import amount_doc_fact

        # Always computed: no source email / raw message -> BLOCK 'AMOUNT DOC N/A' (CONTRACTS §2.1, fail closed).
        add(amount_doc_fact(subject.get("invoice") or {}, state.get("email_raw"), vendor_ico=ico))

        from executor.policy.facts_wsa import wsa_facts  # F-MANDATE, F-DUP, F-SPLIT, F-Z (WS-A)

        facts.extend(wsa_facts(subject, state, now))
    facts.extend(state.get("extra_facts") or [])

    ordered = order_facts(facts + hint_facts(subject.get("hints") or []))
    return {
        "subject_id": subject.get("subject_id", ""),
        "computed_at": iso(now),
        "facts": ordered,
        "facts_digest": facts_digest(ordered),
        "snapshots": dict(sorted(snapshots.items())),
        "max_severity": max_severity(ordered),
    }
