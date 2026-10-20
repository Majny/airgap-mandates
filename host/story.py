"""Plain-language story of the audit log for the projector (the Story tab in host/ui.py). Owner: orchestrator.

Pure functions over the auditor export bundle plus GET /vendors, /changes and /proposals: one card per thing a
non-technical audience should notice (paid automatically, needed the Trezor, attack stopped), newest first.
Untrusted host (TB3) like the rest of the UI: this is a reading aid, the offline verifier is the proof.
"""
from __future__ import annotations

import re
from typing import Any

# tone -> (icon, colour); the colours match SEV_COLOUR in host/ui.py
TONES = {"ok": ("✅", "#067647"), "human": ("✋", "#1d4ed8"), "attack": ("🛑", "#b42318"), "info": ("•", "#475467")}

TOOL_ATTACKS = {
    "mandate.write": "tried to raise its own spending limit",
    "T-MAIL-ALLOWLIST": "tried to email our data to an outside address",
    "T-MAIL-IBAN": "tried to leak a bank account number by email",
}
SIG_ATTACKS = {
    "nonce_reused": ("Replay attack stopped", "an old Trezor signature was sent again; every signature works once"),
    "expired": ("Replay attack stopped", "a captured approval was sent after its challenge expired; approvals are "
                                         "valid for minutes and only once"),
    "unknown_signer": ("Forged approval stopped", "signed by a key that is not an enrolled hardware device"),
    "caller_not_allowed": ("Agent tried to approve its own payment", "the agent has no right to submit approvals"),
    "render_mismatch": ("Tampered approval stopped", "this PC sent the Trezor a different payment than the bank "
                        "issued; the device showed it and the executor only accepts its own text"),
}


def czk(minor: int | None) -> str:
    return f"{(minor or 0) / 100:,.2f} CZK".replace(",", " ")


def _card(seq: int, tone: str, title: str, body: str = "", device: str | None = None) -> dict[str, Any]:
    return {"seq": seq, "tone": tone, "title": title, "body": body, "device": device}


def plain_fact(f: dict[str, Any]) -> str:
    """One fact in words an operator reads: the executor's label minus internal tags like (embedded_reference)."""
    if f.get("id") == "F-ATTEST":
        m = re.search(r"(\d)/(\d)", str(f.get("display_line", "")))
        return f"{m.group(1)} of {m.group(2)} independent confirmations" if m else "independent confirmations"
    return re.sub(r"\s*\(\w*_\w*\)", "", str(f.get("label") or f.get("display_line") or f.get("id", "")))


def plain_reason(reason: str) -> str:
    """FSM history reasons are executor-internal; translate the ones an operator sees."""
    if reason.startswith("BLOCK at create"):
        return "rejected on arrival: hard block"
    return {"not us": "the supplier's registered contact answered \u201cnot us\u201d"}.get(reason, reason)


def _reasons(facts: list[dict[str, Any]], severities: tuple[str, ...] = ("BLOCK",)) -> str:
    return "; ".join(plain_fact(f) for f in facts if f.get("kind", "F") == "F" and f.get("severity") in severities)


def _lookalike_of(domain: str, reg_domains: dict[str, str]) -> str | None:
    """The registered supplier domain that `domain` imitates, or None. A lookalike is an unregistered sender domain
    that carries a registered supplier's core label (acme-cz.com imitates acme.cz)."""
    d = (domain or "").lower()
    if not d or d in reg_domains:
        return None
    flat = d.replace("-", "").replace(".", "")
    for rd in reg_domains:
        core = rd.split(".")[0]
        if len(core) >= 3 and core in flat:
            return rd
    return None


def _agent_claims(hints: list[dict[str, Any]]) -> str:
    said = [h.get("text") or h.get("display_line") for h in hints if h.get("text") or h.get("display_line")]
    return f" The agent claimed “{said[0]}”: ignored, the agent's words are never evidence." if said else ""


def build(bundle: dict[str, Any] | None, vendors: list[dict[str, Any]], changes: list[dict[str, Any]],
          proposals: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """-> (kpis, cards newest first)."""
    leaves = sorted((bundle or {}).get("leaves", []), key=lambda leaf: leaf.get("seq", 0))
    names = {v["vendor_id"]: v.get("name") or v["vendor_id"] for v in vendors}
    reg_domains = {str(v["domain"]).lower(): v.get("name") or v["vendor_id"] for v in vendors if v.get("domain")}
    known_ibans = {v.get("iban") for v in vendors} | {h.get("iban") for v in vendors
                                                      for h in v.get("iban_history") or []}
    by_change = {c["change_id"]: c for c in changes}
    pending = {p["proposal_id"]: p for p in proposals if p.get("status") == "CHALLENGED"}
    labels: dict[str, str] = {}
    software: set[str] = set()
    domains: dict[str, str] = {}
    invoices: dict[str, dict[str, Any]] = {}
    hints: dict[str, list[dict[str, Any]]] = {}
    decided: set[str] = set()
    cards: list[dict[str, Any]] = []
    k = {"paid_minor": 0, "paid_n": 0, "auto_n": 0, "attacker_minor": 0, "attacks": 0, "device_n": 0}

    def vendor(vid: str | None) -> str:
        return names.get(vid or "", vid or "?")

    for leaf in leaves:
        ev, seq = leaf.get("event") or {}, leaf.get("seq", 0)
        typ, sid, d = ev.get("type"), str(ev.get("subject_id") or ""), ev.get("data") or {}
        if typ == "enroll":
            labels[str(d.get("address", "")).lower()] = d.get("device") or "UNKNOWN"
            if "software key" in str(d.get("label", "")):
                software.add(str(d.get("address", "")).lower())
        elif typ == "ingest":
            dom = d.get("from_domain") or "?"
            domains[d.get("email_id", "")] = dom
            imitated = _lookalike_of(dom, reg_domains)
            if imitated:
                k["attacks"] += 1
                cards.append(_card(seq, "attack", f"Email from a lookalike domain: {dom}",
                                   f"{dom} imitates the registered supplier domain {imitated} "
                                   f"({reg_domains[imitated]}). It is treated as untrusted: any payment or account "
                                   "change it asks for is rejected on arrival, and the Trezor stays dark."))
        elif typ == "proposal":
            invoices[sid] = d.get("invoice") or {}
            hints[sid] = d.get("hints") or []
        elif typ == "decision" and sid in invoices and sid not in decided:
            decided.add(sid)
            inv = invoices[sid]
            what = f"{vendor(inv.get('vendor_id'))} · {czk(inv.get('amount_minor'))}"
            facts = ((d.get("inputs") or {}).get("facts") or {}).get("facts") or []
            if d.get("decision") == "allow":
                k["auto_n"] += 1
                cards.append(_card(seq, "ok", f"Paid automatically: {what}",
                                   "Inside the signed mandate, so no human was needed."))
            elif d.get("decision") == "challenge":
                why = _reasons(facts, ("BLOCK", "WARN")) or "outside the mandate"
                p = pending.get(sid)
                cards.append(_card(seq, "human", f"Needs a human: {what}",
                                   f"{why}. Sent to the clerk's Trezor: the device shows the exact amount and "
                                   "account, and the clerk holds to confirm." + _agent_claims(hints[sid]),
                                   (p or {}).get("decision", {}).get("challenge", {}).get("text") if p else None))
            else:
                k["attacks"] += 1
                sender = domains.get(inv.get("email_id", ""), "")
                cards.append(_card(seq, "attack", f"Payment blocked: {what}",
                                   (f"Invoice email from {sender}. " if sender else "")
                                   + f"{_reasons(facts) or 'policy'}. Nothing to approve: the Trezor stays dark."
                                   + _agent_claims(hints[sid])))
        elif typ == "execution":
            amount, iban = d.get("amount_minor") or 0, d.get("iban")
            if iban in known_ibans:
                k["paid_minor"] += amount
                k["paid_n"] += 1
            else:
                k["attacker_minor"] += amount
            if (d.get("authorization") or {}).get("kind") == "stepup":
                cards.append(_card(seq, "ok", f"Paid after the clerk confirmed: {vendor(d.get('vendor_id'))} · "
                                               f"{czk(amount)}", f"To the account in the vendor master ({iban})."))
        elif typ == "signature":
            addr = str(d.get("signer_address") or "").lower()
            dev = labels.get(addr, "not enrolled")
            who = "Clerk" if d.get("role") == "clerk" else "Treasury"
            what = {"MANDATE": "the mandate", "PAY": "the payment", "CHG": "the account change",
                    "CHG_REJECT": "rejecting the change"}.get(d.get("purpose"), d.get("purpose"))
            if d.get("accepted"):
                k["device_n"] += 1
                dev_txt = "with a software key (test)" if addr in software else "on the real Trezor" if dev == "GENUINE" else (
                    "on the emulator (simulated person)" if dev == "EMULATOR" else f"({dev})")
                cards.append(_card(seq, "info", f"{who} confirmed {what} {dev_txt}"))
            else:
                k["attacks"] += 1
                title, why = SIG_ATTACKS.get(d.get("error"), ("Approval refused", str(d.get("error"))))
                cards.append(_card(seq, "attack", title, why + "."))
        elif typ == "tool_call" and d.get("result") == "forbidden":
            k["attacks"] += 1
            rules = d.get("rule_ids") or []
            what = TOOL_ATTACKS.get(d.get("tool")) or next((TOOL_ATTACKS[r] for r in rules if r in TOOL_ATTACKS),
                                                           f"tried {d.get('tool')}")
            cards.append(_card(seq, "attack", f"Hijacked agent {what}", f"Refused ({', '.join(rules)})."))
        elif typ == "state_transition" and str(sid).startswith("chg_"):
            c = by_change.get(sid, {})
            who = c.get("vendor_name") or vendor(c.get("vendor_id"))
            sender = domains.get(c.get("email_id", ""), "?")
            ask = f"Email from {sender} asks to send {who}'s payments to a new account {c.get('new_iban', '?')}."
            ev_name, to = d.get("event"), d.get("to")
            if ev_name == "CREATE" and to == "REJECTED":
                k["attacks"] += 1
                cards.append(_card(seq, "attack", f"Account-change attack stopped: {who}",
                                   f"{ask} {_reasons(c.get('facts') or [])}. Nothing to approve: the Trezor stays "
                                   "dark." + _agent_claims([f for f in c.get("facts") or [] if f.get("kind") == "H"])))
            elif ev_name == "CREATE":
                cards.append(_card(seq, "info", f"Account-change request: {who}",
                                   f"{ask} It needs 2 of 3 independent confirmations (supplier ERP, supplier's "
                                   "bank, registry) before anyone can even sign. Until then there is no button."
                                   + _agent_claims([f for f in c.get("facts") or [] if f.get("kind") == "H"])))
            elif ev_name == "TRIPWIRE_NOT_US":
                k["attacks"] += 1
                cards.append(_card(seq, "attack", f"Mailbox takeover stopped: {who}",
                                   f"The email came from the real {sender} (hacked mailbox) and had 0 of 3 "
                                   f"confirmations. {who}'s registered contact answered “not us”: rejected."))
            elif ev_name == "VC_RECEIVED" and to == "COOLING":
                cards.append(_card(seq, "info", f"2 of 3 independent confirmations: {who}",
                                   "Supplier ERP and supplier's bank vouched for the new account. Cooling-off starts."))
            elif to == "SIG_CLERK":
                cards.append(_card(seq, "human", f"Account change needs two people: {who}",
                                   "Cooling-off over. Clerk and treasury must each confirm on their own device.",
                                   (c.get("pending_challenge") or {}).get("text") if c.get("state") == "SIG_CLERK"
                                   else None))
            elif to == "ACTIVE":
                cards.append(_card(seq, "ok", f"New account active: {who}",
                                   "Legitimate change: 2 of 3 confirmations, cooling-off, clerk + treasury."))
            elif to in ("REJECTED", "EXPIRED"):
                cards.append(_card(seq, "info", f"Account change {to.lower()}: {who}", plain_reason(d.get("reason") or "")))
        elif typ == "mandate_signed" and not any(cd.get("mandate") == sid for cd in cards):
            f = d.get("fields") or {}
            card = _card(seq, "info", "Mandate signed on hardware",
                         f"The agent may pay existing suppliers up to {czk(f.get('max_per_payment_minor'))} each, "
                         f"{czk(f.get('max_total_minor'))} in total, at most {f.get('max_count')} payments. "
                         "Anything else needs a human on the Trezor.")
            card["mandate"] = sid
            cards.append(card)
    return k, list(reversed(cards))
