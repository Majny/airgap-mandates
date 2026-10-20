"""Plain-language story of the audit log for the projector (the Overview tab in host/ui.py), the Security tab's
incident cards and the Audit tab's event log. Owner: orchestrator.

Pure functions over the auditor export bundle plus GET /vendors, /changes and /proposals (auditors: the bundle only):
  build()     one card per thing a non-technical audience should notice (paid automatically, needed the Trezor,
              attack stopped), newest first;
  security()  one incident card per attack (executor.audit.explain.incidents): what kind of attack, who / where from,
              what they tried, how it was stopped, money moved, audit seq;
  event_log() every audit leaf explained, newest first, filterable by level.
Untrusted host (TB3) like the rest of the UI: this is a reading aid, the offline verifier is the proof.
"""
from __future__ import annotations

import html
from typing import Any

from executor.audit import explain as X

# One vocabulary for the ops log, this console and host/alerts.py: the wording tables live in the executor's explainer.
from executor.audit.explain import (SIG_ATTACKS, TOOL_ATTACKS, czk, lookalike_of, plain_fact,  # noqa: F401
                                    plain_reason, reasons)

# tone -> (icon, colour); the colours match SEV_COLOUR in host/ui.py
TONES = {"ok": ("✅", "#067647"), "human": ("✋", "#1d4ed8"), "attack": ("🛑", "#b42318"), "info": ("•", "#475467"),
         "hold": ("⏸", "#b54708")}


def _card(seq: int, tone: str, title: str, body: str = "", device: str | None = None) -> dict[str, Any]:
    return {"seq": seq, "tone": tone, "title": title, "body": body, "device": device}


_reasons = reasons
_lookalike_of = lookalike_of


def _agent_claims(hints: list[dict[str, Any]]) -> str:
    said = [h.get("text") or h.get("display_line") for h in hints if h.get("text") or h.get("display_line")]
    return f" The agent claimed “{said[0]}”: ignored, the agent's words are never evidence." if said else ""


def build(bundle: dict[str, Any] | None, vendors: list[dict[str, Any]], changes: list[dict[str, Any]],
          proposals: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """-> (kpis, cards newest first)."""
    leaves = X._rows(_dict_or_empty(bundle).get("leaves") or [])
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
    known = X.known_from(vendors, changes, proposals)  # the explainer's verdict decides attack vs. refusal

    def vendor(vid: str | None) -> str:
        return names.get(vid or "", vid or "?")

    for leaf in leaves:
        ev, seq = X._dict(leaf.get("event")), X._seq(leaf) or 0
        typ, sid, d = ev.get("type"), str(ev.get("subject_id") or ""), X._dict(ev.get("data"))
        x = X.explain(ev, seq, known=known, full_iban=True)
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
                                   f"change it asks for is rejected on arrival: {X.NO_SIGN}."))
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
                                   + f"{_reasons(facts, hostile_first=True) or 'policy'}. Nothing to approve: "
                                   f"{X.NO_SIGN}." + _agent_claims(hints[sid])))
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
            elif x is not None and x.level == X.ATTACK:
                k["attacks"] += 1
                title, why = SIG_ATTACKS.get(x.rule_ids[0] if x.kind != "replayed approval" else "nonce_reused",
                                             ("Approval refused", str(d.get("error"))))
                lab = known.label(sid)
                if lab and d.get("purpose") == "PAY":  # name the payment the attacker went for
                    title += f": {lab[0]}"
                cards.append(_card(seq, "attack", html.escape(title), html.escape(why[:1].upper() + why[1:]) + "."))
            elif x is not None:
                cards.append(_card(seq, "info", html.escape(x.title), html.escape(x.why) + "."))
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
            new = X.iban(c["new_iban"], True) if c.get("new_iban") else "?"
            ask = f"Email from {sender} asks to send {who}'s payments to a new account {new}."
            ev_name, to = d.get("event"), d.get("to")
            risk = X.change_risk(c, full_iban=True) if ev_name == "CREATE" and to != "REJECTED" else None
            if ev_name == "CREATE" and to == "REJECTED" and (x is None or x.level == X.ATTACK):
                k["attacks"] += 1
                cards.append(_card(seq, "attack", f"Account-change attack stopped: {who}",
                                   f"{ask} {_reasons(c.get('facts') or [], hostile_first=True)}. Nothing to approve: "
                                   f"{X.NO_SIGN}." + _agent_claims([f for f in c.get("facts") or []
                                                                     if f.get("kind") == "H"])))
            elif ev_name == "CREATE" and to == "REJECTED":
                cards.append(_card(seq, "info", f"Account change refused on arrival: {who}",
                                   f"{ask} {html.escape(x.why if x else '')}."))
            elif risk is not None:  # held, with the warning signs of a hacked supplier mailbox
                cards.append(_card(seq, "hold", html.escape(f"Suspicious account change on hold: {who} → {new}"),
                                   html.escape(f"{ask} Warning signs: {risk.why}.") + " See the <b>Security</b> tab."))
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


# ---------------------------------------------------------------- Security tab (incident cards) and event log

LOG_FILTERS = {  # Audit tab "Event log" filter -> levels shown ("Attacks only": ERROR only for a breach)
    "Attacks only": (X.ATTACK, X.ERROR),
    "Everything except routine noise": tuple(lv for lv in X.LEVELS if lv != X.NOISE),
    "Everything": X.LEVELS,
}
LEVEL_LOOK = {  # level -> (icon, label, colour); colours match SEV_COLOUR / TONES
    X.ATTACK: ("🛑", "ATTACK", "#b42318"), X.ERROR: ("💥", "ERROR", "#7a0916"), X.BLOCKED: ("⛔", "BLOCKED", "#b54708"),
    X.HUMAN: ("✋", "HUMAN", "#1d4ed8"), X.PAID: ("💸", "PAID", "#067647"), X.OK: ("✅", "OK", "#067647"),
    X.INFO: ("•", "INFO", "#475467"), X.NOISE: ("·", "NOISE", "#98a2b3"),
}
_CHANGE_KINDS = ("mailbox takeover", "mailbox takeover?", "payee name mismatch", "fake attestation",
                 "callback code guessing", "warn-listed payee", "sanctioned payee", "spoofed email")


_NOT_BY_EMAIL = ("tampered approval (PC malware)", "forged approval", "replayed approval", "hijacked agent",
                 "data exfiltration", "stolen agent credentials")


def _dict_or_empty(b: Any) -> dict[str, Any]:
    return b if isinstance(b, dict) else {}


def linked(sec: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """subject (prp_/chg_ id) -> the incident card it belongs to: the Payments / Approvals rows get a red tag."""
    out: dict[str, dict[str, Any]] = {}
    for c in (sec or {}).get("incidents") or []:
        if c.get("subject"):
            out.setdefault(str(c["subject"]), c)
    return out


def when(ts: Any) -> str:
    """'2026-10-20T09:05:02.777Z' -> '2026-10-20 09:05 UTC'."""
    t = str(ts or "")
    return f"{t[:10]} {t[11:16]} UTC" if len(t) >= 16 else t


def _context(leaves: list[dict[str, Any]]) -> tuple[dict[str, dict[str, Any]], dict[str, list[tuple[int, Any]]]]:
    """From the leaves alone (auditors have nothing else): proposal_id -> {invoice, hints}, subject -> [(seq, ts)]."""
    props: dict[str, dict[str, Any]] = {}
    seqs: dict[str, list[tuple[int, Any]]] = {}
    for le in leaves:
        ev = X._dict(le.get("event"))
        sid = str(ev.get("subject_id") or "")
        if sid and isinstance(le.get("seq"), int):
            seqs.setdefault(sid, []).append((le["seq"], ev.get("ts")))
        if ev.get("type") == "proposal":
            d = X._dict(ev.get("data"))
            props[sid] = {"invoice": X._dict(d.get("invoice")), "hints": [h for h in d.get("hints") or []
                                                                         if isinstance(h, dict)]}
    return props, seqs


def _who(inc: X.Incident, known: X.Known) -> list[str]:
    """Who / where from, in words: sender domain (lookalike or the supplier's own), signing key, agent session.
    HTML-safe lines (values escaped, <b> added here)."""
    e = html.escape
    out: list[str] = []
    dom, kind = inc.who.get("sender_domain"), inc.kind
    if kind in _NOT_BY_EMAIL:  # the invoice email behind a forged / replayed / tampered approval is not the attacker
        dom = None
    if dom:
        imitated = X.lookalike_of(dom, known.domains)
        if imitated:
            out.append(f"Email from <b>{e(dom)}</b>: a lookalike of the real supplier domain {e(imitated)} "
                       f"({e(str(known.domains[imitated]))}). It is not the supplier.")
        elif dom in known.domains and kind == "mailbox takeover":
            out.append(f"Email from <b>{e(dom)}</b>, the supplier's real domain: their mailbox was hacked (the "
                       "supplier confirmed it did not send the request).")
        elif dom in known.domains and kind in _CHANGE_KINDS:
            out.append(f"Email from <b>{e(dom)}</b>, the supplier's own domain: the mailbox was probably hacked, or "
                       "the email forged.")
        elif kind == "prompt injection":
            out.append(f"Text hidden inside an invoice emailed from <b>{e(dom)}</b>.")
        else:
            out.append(f"Email from <b>{e(dom)}</b>.")
    elif kind == "prompt injection":
        out.append("Text hidden inside an invoice the AI agent read.")
    signer = e(str(inc.who.get("signer") or ""))
    if kind == "forged approval":
        out.append(f"Signing key <b>{signer or '?'}</b>: not one of our registered Trezor devices.")
    elif kind == "replayed approval":
        out.append(f"A copy of an approval made earlier on the Trezor {signer}, sent again by someone else.")
    elif kind == "tampered approval (PC malware)":
        out.append("Malware on the clerk's PC (the computer the bank console runs on). The Trezor itself was not "
                   "fooled.")
    sessions = sorted({e(str(s.extra.get("session"))) for s in inc.steps if s.extra.get("session")})
    tools = sorted({e(str(s.extra.get("tool"))) for s in inc.steps if s.extra.get("tool")})
    if sessions or tools:
        out.append("Our AI agent" + (f" (session {', '.join(sessions)})" if sessions else "")
                   + (f", using the tool <b>{', '.join(tools)}</b>" if tools else "")
                   + ". Someone is steering it.")
    if kind == "fake attestation":
        out.append("Someone posing as the supplier's ERP / bank confirmation service.")
    if kind in ("stolen agent credentials", "credential misuse"):
        out.append("Someone holding the AI agent's credentials.")
    return out or ["Not recorded in the audit log."]


def _tried(inc: X.Incident, known: X.Known, props: dict[str, dict[str, Any]],
           full_iban: bool) -> tuple[str, list[tuple[str, str]], int | None]:
    """-> (what they tried, [(label, value)] details, amount at stake)."""
    subj, kind = str(inc.subject or ""), inc.kind
    facts: list[tuple[str, str]] = []
    if subj.startswith("prp_"):
        p = known.proposals.get(subj) or props.get(subj) or {}
        inv = p.get("invoice") or {}
        vendor, amount = known.vendor(inv.get("vendor_id") or p.get("vendor_id")), inv.get("amount_minor")
        if vendor and vendor != "?":
            facts.append(("Supplier", vendor))
        if amount is not None:
            facts.append(("Amount", X.czk(amount)))
        if inv.get("invoice_no"):
            facts.append(("Invoice", X.clean(inv.get("invoice_no"), 40)))
        hint = " ".join(str(h.get("text") or h.get("display_line") or "") for h in p.get("hints") or [])
        hint_iban = X.find_iban(hint)
        if hint_iban:
            facts.append(("Account they wanted", X.iban(hint_iban, full_iban)))
        what = f"{vendor} · {X.czk(amount)}" if amount is not None else vendor
        tried = {
            "lookalike domain (BEC)": f"Get a fake invoice paid in the name of {vendor} ({X.czk(amount)}).",
            "prompt injection": f"Talk our AI agent into paying {X.czk(amount)} for {vendor} to a different account"
                                + (f" ({X.iban(hint_iban, full_iban)})" if hint_iban else "") + ".",
            "forged approval": f"Approve the payment {what} without a registered Trezor.",
            "replayed approval": f"Approve the payment {what} with an approval that was already used.",
            "tampered approval (PC malware)": f"Swap the bank account in the clerk's approval of {what}, so the "
                                              "money goes to the attacker instead of the supplier.",
        }.get(kind, f"Get the payment {what} through.")
        return tried, facts, amount
    if subj.startswith("chg_"):
        c = known.changes.get(subj) or {}
        vendor = c.get("vendor_name") or known.vendor(c.get("vendor_id")) if c else "the supplier"
        new = c.get("new_iban") or inc.who.get("new_iban")
        if vendor:
            facts.append(("Supplier", vendor))
        if new:
            facts.append(("Account they wanted", X.iban(new, full_iban)))
        if c.get("old_iban"):
            facts.append(("Registered account (unchanged)", X.iban(c["old_iban"], full_iban)))
        to = f" ({X.iban(new, full_iban)})" if new else ""
        if kind == "fake attestation":
            return f"Fake {vendor}'s confirmation, so that {vendor}'s payments go to a new account{to}.", facts, None
        return (f"Redirect all future payments to {vendor} into a new bank account{to}, controlled by the attacker.",
                facts, None)
    if subj.startswith("mnd_"):
        return (f"Re-use an approval of the spending mandate {subj} that was already used." if kind ==
                "replayed approval" else f"Get the spending mandate {subj} approved without a person."), facts, None
    if kind in ("data exfiltration", "hijacked agent", "tampered tool manifest", "replayed tool call"):
        acts = [s.title.removeprefix("Hijacked agent ").removeprefix("tried to ") for s in inc.steps]
        uniq = list(dict.fromkeys(acts))
        return f"Make our AI agent {' and '.join(uniq)}.".replace("..", "."), facts, None
    return inc.title + ".", facts, inc.money_minor


def _policy(leaves: list[dict[str, Any]], seqs: list[int], bundle: dict[str, Any]) -> str | None:
    """The policy hash the incident's decisions were made under (its leaves), else the export's only policy."""
    want = set(seqs)
    for le in leaves:
        if X._seq(le) in want and X._dict(le.get("event")).get("policy_hash"):
            return str(le["event"]["policy_hash"])
    pol = list(_dict_or_empty(bundle.get("policies")).keys())
    return pol[0] if len(pol) == 1 else None


def _proof_kind(leaves: list[dict[str, Any]], seqs: list[int]) -> str:
    """What tools.verify_audit re-checks offline for these entries: "decision" (decide() replayed at the logged policy
    hash), "signature" (signature leaves re-verified) or "log" (hash chain and witness checkpoints only)."""
    want = set(seqs)
    types = {X._dict(le.get("event")).get("type") for le in leaves if X._seq(le) in want}
    return "decision" if "decision" in types else "signature" if "signature" in types else "log"


def _next_step(inc: X.Incident, supplier: str) -> str:
    """What the operator should do about a payment an attack touched that still waits for approval. The system cannot
    know the payment is genuine: verify out of band, and the Trezor screen is the only truth."""
    phone = (f"confirm the invoice with {supplier} by phone, on the contact registered in the vendor master (never a "
             "number from the email)")
    trezor = "approve only after reading the amount and account on the Trezor screen: it is the only truth"
    if inc.kind in X.LINKED_KINDS:
        return f"This payment came in with the attack and still waits in Payments. Reject it, or {phone} first."
    if inc.kind == "tampered approval (PC malware)":
        return ("Treat this PC as compromised: take it off the network and call IT security. Do not approve from it. "
                f"The payment still waits; before anyone approves it from a clean PC, {phone}, and {trezor}.")
    if inc.kind in ("forged approval", "replayed approval"):
        return ("Someone tried to approve this payment without our Trezor; it still waits in Payments. That does not "
                f"tell you whether the invoice is real: {phone}, and {trezor}.")
    return f"The payment still waits in Payments. Before anyone approves it, {phone}, and {trezor}."


_REFUSAL_WHO = {"agent": "Someone holding the AI agent's credentials (role agent), calling the bank's API directly.",
                "tools": "Someone holding the AI agent's tool credentials (role tools), calling the bank's API "
                         "directly."}


def _refusal_card(d: dict[str, Any], seed_seq: int | None) -> dict[str, Any]:
    """A request-level attack (executor.oplog ring: no audit leaf) as an incident card."""
    kind = str(d.get("kind") or "refused request")
    principal = str(d.get("principal") or "?")
    who = [html.escape(_REFUSAL_WHO.get(principal, f"A caller with the {principal} role."))]
    tried = f"{d.get('method', '')} {d.get('path', '')}: {d.get('title') or ''}".strip()
    after = d.get("after_seq")
    return {"level": X.ATTACK, "kind": kind, "threat": d.get("threat") or X.THREAT_BY_KIND.get(kind, X.PE),
            "layer": d.get("layer") or "", "evidence": d.get("evidence") or "",
            "headline": f"Attack stopped: {kind}", "title": str(d.get("title") or ""),
            "what": X.KIND_PLAIN.get(kind, ""), "when": when(d.get("log_ts") or d.get("ts")), "who": who, "tried": tried,
            "facts": [("Request", f"{d.get('method', '')} {d.get('path', '')} → HTTP {d.get('status')}")],
            "stopped": [(None, str(d.get("why") or ""))], "at_stake_minor": d.get("money_minor"), "moved_minor": 0,
            "held": kind.endswith("?"), "breach": False, "waiting": False, "next": "", "seqs": [],
            "subject": d.get("subject"), "policy": None, "request_level": True,
            "order": (after if isinstance(after, int) else -1) + 0.5,
            "backdrop": bool(d.get("scene")) and seed_seq is not None}


def security(bundle: dict[str, Any] | None, vendors: list[dict[str, Any]] = (), changes: list[dict[str, Any]] = (),
             proposals: list[dict[str, Any]] = (), *, full_iban: bool = True,
             seed_seq: int | None = None, refusals: list[dict[str, Any]] = ()) -> dict[str, Any]:
    """Incident cards for the Security tab (and the global banner), newest first:
    {"n", "attacker_minor", "latest", "kinds": {kind: count}, "backdrop_n", "incidents": [card...]}. seed_seq: the
    first audit seq of live traffic on a seeded demo stack (tools.local_stack / memory:); a card whose entries all
    lie before it is the replayed demo backdrop (`backdrop`: the ops log's [demo replay]) and is left out of n, kinds
    and latest, so the banner and "Attacks stopped" count only what happened live. A card holds level, kind,
    headline, title, what (kind in plain words), when, who [html-safe lines], tried, facts [(label, value)],
    stopped [(seq, why)], at_stake_minor, moved_minor, seqs, subject, breach, waiting (the payment is still waiting
    for approval), next (what the operator should do now, or ""), threat / layer / evidence (Track 3 vocabulary),
    policy (hash), proof (_proof_kind: what verify_audit re-checks offline), order. Strings are plain text except `who`, which may carry <b>; the renderer escapes everything
    else. Only BREACH_KIND is a breach: a bank rejection is not. refusals: request-level attacks that wrote no audit
    leaf (executor.oplog.recent / fetch_recent), each one card ("request_level"; backdrop when logged while seeding).
    Also "groups": live counts per threat group (X.THREAT_GROUPS + X.FRAUD_GROUP)."""
    leaves = X._rows(_dict_or_empty(bundle).get("leaves") or [])
    vendors, changes, proposals = list(vendors or []), list(changes or []), list(proposals or [])
    known = X.known_from(vendors, changes, proposals)
    for le in leaves:  # fill senders / cites / devices the way the explainer does
        X.explain(X._dict(le.get("event")), X._seq(le), known=known, full_iban=full_iban)
    props, seqs = _context(leaves)
    cards: list[dict[str, Any]] = []
    for inc in X.incidents(leaves, vendors, changes, proposals, full_iban=full_iban):
        if not inc.who.get("sender_domain") and known.sender_of(inc.subject):
            inc.who["sender_domain"] = known.sender_of(inc.subject)  # e.g. the email an injected invoice came in
        tried, facts, stake = _tried(inc, known, props, full_iban)
        steps = sorted(inc.steps, key=lambda st: st.seq if st.seq is not None else 10**9)
        stopped = list(dict.fromkeys((st.seq, st.why) for st in steps if st.why))
        # the leaves that record the attack; a held change has none yet, so point at its own entries
        own = sorted({st.seq for st in steps if st.seq is not None})
        subj_rows = seqs.get(str(inc.subject), [])
        related = own or sorted(q for q, _ in subj_rows)
        ts = next((st.ts for st in reversed(steps) if st.ts), None) or next((t for _, t in reversed(subj_rows) if t),
                                                                          None)
        breach = any(X.is_breach(st) for st in inc.steps)
        held = inc.kind.endswith("?")
        kind = inc.kind.rstrip("?")
        subj = str(inc.subject or "")
        waiting = (not breach and subj.startswith("prp_")
                   and (known.proposals.get(subj) or {}).get("status") in ("PENDING_SIG", "CHALLENGED"))
        supplier = next((v for k_, v in facts if k_ == "Supplier"), "the supplier")
        nxt = _next_step(inc, supplier) if waiting else ""
        headline = (f"MONEY LEFT THE BANK: {kind}" if breach else
                    f"Suspected attack, on hold: {kind}" if held else
                    f"Attack blocked, payment still waiting: {kind}" if nxt and inc.kind in X.LINKED_KINDS
                    else f"Attack stopped: {kind}")
        cards.append({
            "level": inc.level, "kind": inc.kind, "headline": headline, "title": inc.title,
            "what": X.KIND_PLAIN.get(inc.kind, ""), "when": when(ts),
            "who": _who(inc, known), "tried": tried, "facts": facts, "stopped": stopped,
            "at_stake_minor": stake if stake is not None else inc.money_minor,
            "moved_minor": (inc.money_minor or 0) if breach else 0, "held": held, "breach": breach,
            "waiting": waiting, "next": nxt, "seqs": related, "subject": inc.subject,
            "threat": inc.threat, "layer": inc.layer, "evidence": inc.evidence,
            "policy": _policy(leaves, related, _dict_or_empty(bundle)), "request_level": False,
            "proof": _proof_kind(leaves, related),
            "order": float(max(related, default=-1)),
            "backdrop": seed_seq is not None and bool(related) and max(related) < seed_seq})
    told = {c["subject"] for c in cards if c.get("subject")}
    for d in refusals or []:
        if isinstance(d, dict) and not (d.get("subject") and d.get("subject") in told):  # a held change: GET /changes
            cards.append(_refusal_card(d, seed_seq))
    # newest first by the audit entries each card points at (a held change has no attack leaf, only its own entries);
    # a request-level refusal sits right after the last leaf written before it
    cards.sort(key=lambda c: c["order"], reverse=True)
    live = [c for c in cards if not c["backdrop"]]
    kinds: dict[str, int] = {}
    groups = {g: 0 for g in (*X.THREAT_GROUPS.values(), X.FRAUD_GROUP)}
    for c in live:
        kinds[c["kind"]] = kinds.get(c["kind"], 0) + 1
        groups[X.threat_group(c.get("threat"))] += 1
    return {"n": len(live), "attacker_minor": sum(c["moved_minor"] for c in live),
            "latest": live[0] if live else None, "kinds": kinds, "groups": groups,
            "backdrop_n": len(cards) - len(live), "incidents": cards}


def event_log(bundle: dict[str, Any] | None, vendors: list[dict[str, Any]] = (), changes: list[dict[str, Any]] = (),
              proposals: list[dict[str, Any]] = (), *, show: str = "Everything except routine noise",
              full_iban: bool = True) -> list[X.Explained]:
    """Every audit leaf explained with console context, newest first, filtered by LOG_FILTERS[show]."""
    levels = LOG_FILTERS.get(show, LOG_FILTERS["Everything"])
    rows = X.explain_all(_dict_or_empty(bundle).get("leaves") or [], vendors, changes, proposals, full_iban=full_iban)
    attacks_only = show == "Attacks only"
    return [e for e in reversed(rows) if e.level in levels and not (attacks_only and e.level == X.ERROR
                                                                    and not X.is_breach(e))]
