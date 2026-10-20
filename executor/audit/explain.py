"""Plain-English explanations of audit leaves and refused requests: one vocabulary for the ops log (executor.oplog),
the bank console (host/story.py, host/ui.py) and the alert watcher (host/alerts.py). Owner: orchestrator.

Pure: no I/O, no store reads, never raises (an event it cannot read comes back as an INFO "unreadable" line). Only
named fields are read, so signatures, nonce secrets, callback codes, VC bodies and e-mail bodies never reach the text.
Attacker-controlled strings (agent hints, error messages) are stripped of control characters and truncated.

    explain(event, seq=None, *, known=None, full_iban=False) -> Explained | None   one audit leaf (v2 event dict)
    refusal(method, path, principal, status, error_code, message) -> Explained      a 4xx/5xx that wrote no leaf
    response(method, path, principal, status, body) -> Explained | None             a 2xx whose body says more
    change_risk(change) -> Explained | None        a pending payee change with red flags (possible mailbox takeover)
    known_from(vendors, changes, proposals) -> Known                   optional context the console has (GET /vendors..)
    incidents(leaves, vendors=(), changes=(), proposals=()) -> list[Incident]   ATTACKs and breaches per subject
    learn(event, known) / learn_body(body, known)    names and amounts from data already in hand (no store reads)

KIND_PLAIN maps each attack kind to one sentence a non-technical reader understands (Security tab, alerts).

Levels: ATTACK (someone tried something hostile and was stopped), BLOCKED (refused, not necessarily hostile), HUMAN
(waiting for a person / Trezor), PAID, OK, INFO, NOISE (checkpoint/anchor/ok tool calls: debug only), ERROR (the
system failed, or money reached an account outside the vendor master). `kind` is a short category label. Only kind
BREACH_KIND ("money to an unregistered account") means money left the bank; any other ERROR (a bank rejection, an
internal error) is an operational failure and never an incident, a breach card or a breach alert.

IBANs are masked (`CZ65 …5399`) unless full_iban=True (the console shows full IBANs; the ops log never does).
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Iterable

LEVELS = ("ATTACK", "BLOCKED", "HUMAN", "PAID", "OK", "INFO", "NOISE", "ERROR")
ATTACK, BLOCKED, HUMAN, PAID, OK, INFO, NOISE, ERROR = LEVELS
BREACH_KIND = "money to an unregistered account"  # the only ERROR that means money reached an attacker
NO_SIGN = "no approval was offered, so nobody could sign it"

# ---------------------------------------------------------------- shared vocabulary (also host/story.py)

TOOL_ATTACKS = {
    "mandate.write": "tried to raise its own spending limit",
    "T-MAIL-ALLOWLIST": "tried to email our data to an outside address",
    "T-MAIL-IBAN": "tried to leak a bank account number by email",
}
SIG_ATTACKS = {
    "nonce_reused": ("Replay attack stopped", "an old Trezor signature was sent again; every signature works once"),
    "expired": ("Late approval refused", "the approval arrived after its challenge expired; approvals are valid for "
                                        "minutes and only once (a slow clerk, or a captured approval sent again)"),
    "unknown_signer": ("Forged approval stopped", "no enrolled Trezor signed this payment: either a key that is not "
                       "ours, or a real Trezor that malware on the PC showed a different payment, or an approval "
                       "moved over from another payment"),
    "bad_signature": ("Forged approval stopped", "the signature is not valid for this payment"),
    "caller_not_allowed": ("Agent tried to approve its own payment", "the agent has no right to submit approvals"),
    "render_mismatch": ("Tampered approval stopped", "this PC sent the Trezor a different payment than the bank "
                        "issued; the device showed it and the executor only accepts its own text"),
}
# titles of refused signatures in the log, the Security tab and the attacker console: no "stopped" (the headline adds
# "→ stopped by <layer>"); SIG_ATTACKS keeps the Overview card titles
SIG_TITLES = {"nonce_reused": "Replay of an old Trezor approval", "unknown_signer": "Forged approval",
              "bad_signature": "Forged approval", "render_mismatch": "Tampered approval"}
# signature error -> (level, kind); anything not listed is BLOCKED "approval refused"
SIG_KINDS: dict[str, tuple[str, str]] = {
    "nonce_reused": (ATTACK, "replayed approval"),
    "expired": (BLOCKED, "expired approval"),
    "unknown_signer": (ATTACK, "forged approval"),
    "bad_signature": (ATTACK, "forged approval"),
    "render_mismatch": (ATTACK, "tampered approval (PC malware)"),
    "caller_not_allowed": (ATTACK, "stolen agent credentials"),
}
# plain words for rule ids that show up in why-lines
RULE_WORDS = {
    "I-PAYEE": "payee not in the vendor master", "I-DUP": "duplicate invoice", "I-AMOUNT": "amount not in the invoice",
    "I-BLOCK": "a hard-block fact", "I-MANDATE": "no mandate covers it", "I-EXP": "mandate expired",
    "I-PER": "over the per-payment cap", "I-BUDGET": "over the mandate budget", "I-COUNT": "too many payments",
    "I-REGISTRY": "payee changed after the mandate was signed", "I-VOP": "Verification of Payee not a match",
    "I-ANOM": "agent behaviour anomalous", "I-SPLIT": "looks like a split payment", "I-WARN": "a warning fact",
    "I-ATTEST": "not enough independent confirmations", "I-CALLBACK": "callback not confirmed",
    "I-COOLOFF": "cooling-off not over", "I-NONCE": "approval already used",
    "T-DECOY": "decoy tool (no legitimate agent calls it)", "T-MAIL-ALLOWLIST": "recipient not allowlisted",
    "T-MAIL-IBAN": "an IBAN in an outgoing mail", "T-MANIFEST": "tool manifest does not match",
    "T-STEP-REUSE": "tool step replayed", "T-BAD-REQUEST": "malformed tool request", "T-TAINT": "acted on untrusted text",
    "E-ALLOWLIST": "recipient not allowlisted", "E-DLP-IBAN": "bank account numbers in the message",
    "E-DLP-ICO": "company ids in the message", "E-DLP-NAME": "supplier names in the message",
    "E-DLP-CARD": "card numbers in the message", "E-DLP-COUNT": "bulk data in the message",
    "E-ENCODED": "encoded payload", "E-URLDATA": "data smuggled in a URL", "E-GUARDRAILS": "Bedrock Guardrails",
    "E-SIZE": "too large / attachment", "E-RATE": "too many messages",
}
# BLOCK facts that mean someone is lying to us (vs. bookkeeping blocks such as a duplicate)
HOSTILE_FACTS = ("F-DOMAIN", "F-DKIM", "F-WARNLIST", "F-SANCTION", "F-ANOM", "F-VOP")
# hostile facts that are BLOCK whenever they are not INFO (rules.FACT_SEVERITY): F-VOP (CMTC / NOAP) and F-ANOM can be
# a mere WARN, so a decision's rule_ids alone never make them an attack
BLOCK_ONLY_FACTS = ("F-DOMAIN", "F-DKIM", "F-WARNLIST", "F-SANCTION")
FACT_KINDS = {"F-DOMAIN": "lookalike domain (BEC)", "F-DKIM": "spoofed email", "F-WARNLIST": "warn-listed payee",
              "F-SANCTION": "sanctioned payee", "F-ANOM": "hijacked agent", "F-VOP": "payee name mismatch",
              "F-NAME-TRANSLIT": "payee name mismatch", "F-DUP": "duplicate invoice",
              "F-AMOUNT-DOC": "amount not in invoice", "F-SPLIT": "split payment", "F-MANDATE": "outside the mandate"}
# kind -> what this kind of attack is, in one sentence for a non-technical reader (console Security tab, alerts)
KIND_PLAIN = {
    "lookalike domain (BEC)": "Business email fraud: someone wrote from an address made to look like a real "
                              "supplier's, hoping we pay them or move the supplier's payments to their account.",
    "spoofed email": "An email forged to look as if it came from a real supplier.",
    "mailbox takeover": "The supplier's real mailbox was hacked and used to ask us to send their payments to a new "
                        "bank account.",
    "mailbox takeover?": "A request to send a supplier's payments to a new bank account, with the warning signs of a "
                         "hacked supplier mailbox. It is held until the supplier confirms through independent "
                         "channels; nobody can approve it before that.",
    "payee name mismatch": "Someone asked us to pay a bank account whose holder is not the supplier (Verification of "
                           "Payee does not match).",
    "warn-listed payee": "The payee is on a regulator's warning list.",
    "sanctioned payee": "The payee is on the EU sanctions list.",
    "prompt injection": "An invoice carried hidden instructions for our AI agent, trying to talk it into paying "
                        "someone else.",
    "hijacked agent": "Our AI agent was manipulated into trying something it must never do.",
    "data exfiltration": "Someone tried to get our data (bank accounts, supplier details) sent out of the bank.",
    "tampered tool manifest": "The AI agent's tools were tampered with.",
    "replayed tool call": "An old AI agent request was sent again.",
    "stolen agent credentials": "Someone used the AI agent's credentials to do what only a person on a Trezor may do.",
    "credential misuse": "A system role tried to do something it is not allowed to do.",
    "IBAN injection": "Someone tried to sneak a bank account number into a payment request.",
    "replayed approval": "Someone captured a valid Trezor approval and sent it again, hoping it counts twice.",
    "forged approval": "Someone sent an approval that none of our registered Trezor devices made for this payment: "
                       "a foreign key, or a real Trezor tricked by malware on the PC into signing something else.",
    "tampered approval (PC malware)": "Malware on the clerk's PC changed the payment it asked the Trezor to sign.",
    "fake attestation": "Someone forged a supplier's confirmation of a new bank account.",
    "callback code guessing": "Someone tried to guess the code we send to the supplier's registered contact.",
    "log fork / witness refusal": "The audit log may have been rewritten: an independent witness refused to confirm "
                                  "it.",
    "money to an unregistered account": "Money was paid to an account that is not in the vendor master.",
    "drill": "A simulated attack (security drill).",
}
# attack kinds whose payment itself came from the attacker: a later "needs a human" line for it carries a warning
LINKED_KINDS = ("prompt injection", "lookalike domain (BEC)", "spoofed email", "payee name mismatch",
                "warn-listed payee", "sanctioned payee")
# ---- Track 3 vocabulary: the threat class of every ATTACK, and the defence layer that stopped it (with evidence)
PI, DE, PE = "PROMPT INJECTION", "DATA EXFILTRATION", "PRIVILEGE ESCALATION"  # the brief's three
BEC, ATO, RF, HT, LT = ("PAYMENT FRAUD (BEC)", "ACCOUNT TAKEOVER", "REPLAY / FORGERY", "HOST TAMPERING",
                        "LOG TAMPERING")
THREATS = (PI, DE, PE, BEC, ATO, RF, HT, LT)
THREAT_BY_KIND = {
    "prompt injection": PI, "hijacked agent": PI, "data exfiltration": DE,
    "stolen agent credentials": PE, "credential misuse": PE, "IBAN injection": PE,
    "lookalike domain (BEC)": BEC, "spoofed email": BEC, "payee name mismatch": BEC, "warn-listed payee": BEC,
    "sanctioned payee": BEC, "money to an unregistered account": BEC,
    "mailbox takeover": ATO, "mailbox takeover?": ATO, "callback code guessing": ATO,
    "replayed approval": RF, "forged approval": RF, "fake attestation": RF, "replayed tool call": RF,
    "tampered approval (PC malware)": HT, "tampered tool manifest": HT, "log fork / witness refusal": LT,
}
# summary row of the Security tab: the brief's three, everything else is fraud / tampering
THREAT_GROUPS = {PI: "prompt injection", DE: "data exfiltration", PE: "privilege escalation"}
FRAUD_GROUP = "fraud & tampering"
L_INPUT, L_PERM, L_ANOM, L_FACTS, L_HW, L_EGRESS, L_TLOG = (
    "input sanitisation", "permission scoping", "anomaly detection on agent actions", "executor facts + policy",
    "hardware signature", "egress gateway", "transparency log")
LAYERS = (L_INPUT, L_PERM, L_ANOM, L_FACTS, L_HW, L_EGRESS, L_TLOG)
DETERMINISTIC = "deterministic: no LLM in the decision path"
REPLAY_CMD = "python -m tools.verify_audit <export.json>"  # re-runs decide() at the logged policy hash (S12)


def threat_title(threat: str | None) -> str:
    """'PAYMENT FRAUD (BEC)' -> 'Payment fraud (BEC)' (alert titles: '🛑 Payment fraud (BEC) stopped: …')."""
    t = str(threat or "").capitalize()
    return t.replace("(bec)", "(BEC)")


def threat_group(threat: str | None) -> str:
    return THREAT_GROUPS.get(str(threat or ""), FRAUD_GROUP)


PURPOSES = {"MANDATE": "the mandate", "PAY": "a payment", "CHG": "a bank-account change",
            "CHG_REJECT": "rejecting a bank-account change", "VENDOR_ATTEST": "a supplier attestation"}

# Verification of Payee answer codes (EPC) and attestation errors in plain words
VOP_WORDS = {"NMTC": "account holder name does not match the supplier", "CMTC": "holder name only a close match",
             "MTCH": "name matches", "NOAP": "check not possible"}
VC_WORDS = {"vc_invalid": "its digital signature is not valid", "kb_jwt_invalid": "the holder proof is not valid",
            "issuer_not_pinned": "it was not issued by a confirmation service we know",
            "aud_mismatch": "it was issued for a different request", "expired": "it has expired",
            "nonce_mismatch": "it was issued for a different request"}
_INJECTION = re.compile(r"ignore (all |any )?(previous|prior|above) instructions|disregard .{0,20}instructions|"
                        r"system prompt|you are now|new instructions", re.I)
# an IBAN candidate in any case, run together or grouped by single separators (space, NBSP, hyphen, dot) in groups of
# any size; _iban_at() trims it to the IBAN (trailing words dropped) and checks length and digits
_IBAN_SEP = "[ \\-.\u00a0\u202f]"
_IBAN_RX = re.compile(rf"(?i)\b[a-z]{{2}}\d{{2}}(?:{_IBAN_SEP}?[a-z0-9])+")
_IBAN_SEG = re.compile(r"[A-Za-z0-9]+")
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f  ‪-‮⁦-⁩]")


def czk(minor: int | None) -> str:
    return f"{(minor or 0) / 100:,.2f} CZK".replace(",", " ")


def mask_iban(iban: Any) -> str:
    """'CZ6508000000192000145399' -> 'CZ65 …5399' (country + check digits and the last 4)."""
    s = re.sub(r"\s", "", str(iban or ""))
    return f"{s[:4]} …{s[-4:]}" if len(s) >= 12 else (s or "?")


def iban(value: Any, full: bool = False) -> str:
    if full:
        s = re.sub(r"\s", "", str(value or ""))
        return " ".join(s[i:i + 4] for i in range(0, len(s), 4)) or "?"
    return mask_iban(value)


def _iban_at(text: str) -> tuple[str, int] | None:
    """(compact upper-case IBAN, length of `text` it spans) for an _IBAN_RX candidate, or None. A group without a digit
    ends the IBAN unless it has 4 characters (GB29 NWBK ...); trailing letter-only groups are words, not the IBAN;
    15-34 characters with at least 8 digits."""
    segs = []
    for m in _IBAN_SEG.finditer(text):
        g = m.group(0)
        if segs and not any(c.isdigit() for c in g) and len(g) != 4:
            break
        segs.append((g, m.end()))
    while len(segs) > 1 and not any(c.isdigit() for c in segs[-1][0]):
        segs.pop()
    while len(segs) > 1 and sum(len(g) for g, _ in segs) > 34:
        segs.pop()
    compact = "".join(g for g, _ in segs).upper()
    if 15 <= len(compact) <= 34 and compact[2:4].isdigit() and sum(c.isdigit() for c in compact) >= 8:
        return compact, segs[-1][1]
    return None


def _sub_ibans(text: str, fn: Any) -> str:
    """Replace every IBAN in free text (any case, any grouping) with fn(compact IBAN)."""
    out, i = [], 0
    for m in _IBAN_RX.finditer(text):
        r = _iban_at(m.group(0))
        if r is None:
            continue
        out += [text[i:m.start()], fn(r[0])]
        i = m.start() + r[1]
    return "".join(out) + text[i:]


def find_iban(text: Any) -> str | None:
    """The first IBAN in free text, compact and upper-case, or None."""
    for m in _IBAN_RX.finditer(str(text or "")):
        r = _iban_at(m.group(0))
        if r is not None:
            return r[0]
    return None


def mask_ibans(text: str) -> str:
    """Mask every IBAN in free text (upper or lower case, run together or grouped by space / hyphen / dot)."""
    return _sub_ibans(str(text), mask_iban)


def safe(text: Any) -> str:
    """One value for an ops-log line: no control / bidi characters (no forged lines), IBANs masked. Keeps the length
    and long hex (a signer address in subject= is not a secret)."""
    return mask_ibans(_CTRL.sub(" ", str(text if text is not None else "")))


# secret-looking runs: signatures / keys (long hex), JWT / SD-JWT (eyJ..., '~' separated disclosures)
_HEX_RX = re.compile(r"\b0x[0-9a-fA-F]{40,}\b|\b[0-9a-fA-F]{48,}\b")
_MASKED_RX = re.compile(r"\b[A-Z]{2}\d{2} …[A-Z0-9]{1,4}")
_FULL_RX = re.compile(r"\b[A-Z]{2}\d{2}(?: [A-Z0-9]{1,4}){2,8}")  # a full IBAN as clean(full_iban=True) spaces it
_JWT_RX = re.compile(r"eyJ[\w.~=+/-]*|\b[\w-]{8,}~[\w.~=+/-]*")


def _no_secrets(s: str) -> str:
    return _JWT_RX.sub("[token redacted]", _HEX_RX.sub("[hex redacted]", s))


def clean(text: Any, n: int = 140, *, full_iban: bool = False) -> str:
    """Untrusted text for one log line: no control/bidi characters, collapsed spaces, IBANs masked (or, full_iban,
    spaced in groups of 4), long hex / JWT-looking runs redacted, truncated on a word boundary and never inside an
    IBAN."""
    s = _no_secrets(" ".join(_CTRL.sub(" ", str(text if text is not None else "")).split()))
    s = _sub_ibans(s, lambda c: iban(c, full_iban))
    if len(s) <= n:
        return s
    cut = n - 1
    for rx in (_FULL_RX, _MASKED_RX):
        for m in rx.finditer(s):
            if m.start() < cut < m.end():
                cut = m.start()
    sp = s.rfind(" ", 0, cut + 1)
    cut = sp if sp > n // 2 else cut
    return s[:cut].rstrip(" ,;:") + "…"


def clip(text: Any, n: int = 160) -> str:
    """clean() for an evidence line: cut at a clause boundary ('; ', ', ', ' (') when one lies in the second half."""
    s = clean(text, 10_000)
    if len(s) <= n:
        return s
    cut = max(s.rfind(sep, 0, n - 1) for sep in ("; ", ", ", " ("))
    return s[:cut].rstrip(" ,;:") + "…" if cut > n // 2 else clean(s, n)


def redact(text: Any, n: int = 160) -> str:
    """A server or validation message for the ops log: clean() plus no quoted values and no 6-digit codes (a
    jsonschema message repeats the offending value: a callback code, a signature, a VC)."""
    s = re.sub(r"'[^']{7,}'?|\"[^\"]{7,}\"?", "'…'", str(text if text is not None else ""))
    return clean(re.sub(r"(?<![\w.])\d{6}(?![\w.])", "[code redacted]", s), n)


def schema_words(msg: Any) -> str:
    """'code: 739215 is not of type 'string'' -> 'code: wrong type'. Keeps the field path and the kind of error,
    never the value (it may be a callback code, a signature or a VC)."""
    s = str(msg or "")
    path, _, rest = s.partition(": ") if ": " in s else ("body", "", s)
    named = re.findall(r"'([\w.-]{1,40})'", rest)
    for rx, words in ((r"is not of type", "wrong type"), (r"does not match", "bad format"),
                      (r"is a required property", "missing field"), (r"Additional properties", "unknown field"),
                      (r"is too long|is too short|non-empty|expected at most|expected at least", "wrong length"),
                      (r"is not one of|is not a valid enum|was expected", "not an allowed value"),
                      (r"under any of the given schemas|is valid under each|should not be valid", "does not match "
                       "any allowed request shape"), (r"less than|greater than|multiple of", "out of range")):
        if re.search(rx, rest):
            if words in ("missing field", "unknown field") and named:
                words += " " + ", ".join(f"'{x}'" for x in named[:4])
            return clean(f"{path[:60]}: {words}", 160)
    return redact(s)


def short_addr(a: Any) -> str:
    s = str(a or "")
    return f"{s[:6]}…{s[-4:]}" if len(s) > 12 else (s or "?")


def plain_fact(f: dict[str, Any]) -> str:
    """One fact in words an operator reads: the executor's label minus internal tags like (embedded_reference)."""
    if not isinstance(f, dict):
        return ""
    if f.get("id") == "F-ATTEST":
        m = re.search(r"(\d)/(\d)", str(f.get("display_line", "")))
        return f"{m.group(1)} of {m.group(2)} independent confirmations" if m else "independent confirmations"
    s = re.sub(r"\s*\(\w*_\w*\)", "", str(f.get("label") or f.get("display_line") or f.get("id", "")))
    s = re.sub(r"\b(NMTC|CMTC|MTCH|NOAP)\b", lambda m: VOP_WORDS[m.group(1)], s)
    return s.replace("(absent != safe)", "(not on the lists; that alone proves nothing)")


def plain_reason(reason: str) -> str:
    """FSM history reasons are executor-internal; translate the ones an operator sees."""
    if reason.startswith("BLOCK at create"):
        return "rejected on arrival: hard block"
    return {"not us": "the supplier's registered contact answered “not us”"}.get(reason, reason)


def _is_fact(f: Any, severities: tuple[str, ...]) -> bool:
    return isinstance(f, dict) and f.get("kind", "F") == "F" and f.get("severity") in severities


def reasons(facts: list[dict[str, Any]], severities: tuple[str, ...] = ("BLOCK",), *, hostile_first: bool = False) -> str:
    """'; '-joined plain facts of these severities. hostile_first: only the facts that mean someone is lying to us
    (HOSTILE_FACTS) when there are any, so an attack line leads with the lookalike domain, not with bookkeeping."""
    fs = [f for f in facts or [] if _is_fact(f, severities)]
    if hostile_first and any(f.get("id") in HOSTILE_FACTS for f in fs):
        fs = sorted((f for f in fs if f.get("id") in HOSTILE_FACTS), key=lambda f: HOSTILE_FACTS.index(f["id"]))
    return "; ".join(plain_fact(f) for f in fs)


def lookalike_of(domain: str, reg_domains: Iterable[str]) -> str | None:
    """The registered supplier domain that `domain` imitates, or None. A lookalike is an unregistered sender domain
    that carries a registered supplier's core label (acme-cz.com imitates acme.cz)."""
    d = (domain or "").lower()
    regs = [str(r).lower() for r in reg_domains]
    if not d or d in regs:
        return None
    flat = d.replace("-", "").replace(".", "")
    for rd in regs:
        core = rd.split(".")[0]
        if len(core) >= 3 and core in flat:
            return rd
    return None


def rules_txt(rule_ids: Iterable[str]) -> str:
    ids = [str(r) for r in rule_ids or [] if r]
    return f" [{', '.join(ids)}]" if ids else ""


# ---------------------------------------------------------------- data types

@dataclass(frozen=True)
class Explained:
    level: str
    kind: str
    title: str
    why: str = ""
    subject: str | None = None
    money_minor: int | None = None
    seq: int | None = None
    rule_ids: tuple[str, ...] = ()
    type: str = "request"  # audit event type, or "request" / "response" for request-level lines
    actor: str | None = None
    ts: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)  # who/what details (sender domain, target, tool, signer)
    threat: str = ""  # ATTACK (and breach) only: one of THREATS
    layer: str = ""  # ATTACK / BLOCKED: the defence layer that stopped it (LAYERS)
    evidence: str = ""  # ATTACK / BLOCKED: the fact or rule id and its value ("F-DOMAIN: acme-cz.com imitates acme.cz")

    @property
    def text(self) -> str:
        """'title — why' (one line)."""
        return f"{self.title} — {self.why}" if self.why else self.title

    @property
    def held(self) -> bool:
        return self.kind.endswith("?")

    @property
    def headline(self) -> str:
        """The ops-log title: 'PROMPT INJECTION · <title> → stopped by <layer>: <evidence> · 0 CZK moved'. Plain title
        for anything that is neither an attack nor a refusal."""
        if self.level not in (ATTACK, BLOCKED) and not is_breach(self):
            return self.title
        out = f"{self.threat} · {self.title}" if self.threat else self.title
        if self.layer:
            out += f" → {'held by' if self.held else 'stopped by'} {self.layer}" + (f": {self.evidence}"
                                                                                    if self.evidence else "")
        if is_breach(self):
            out += f" · {czk(self.money_minor)} MOVED"
        elif self.level == ATTACK:
            out += f" · {czk(self.money_minor)} at stake, 0 CZK moved" if self.money_minor else " · 0 CZK moved"
        return out

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["rule_ids"] = list(self.rule_ids)
        d["text"] = self.text
        d["headline"] = self.headline
        return d


@dataclass
class Known:
    """Context the console already holds (GET /vendors, /changes, /proposals); the ops log runs without it."""

    names: dict[str, str] = field(default_factory=dict)  # vendor_id -> name
    domains: dict[str, str] = field(default_factory=dict)  # registered domain -> vendor name
    ibans: set[str] = field(default_factory=set)  # every registry IBAN, current and historic
    changes: dict[str, dict[str, Any]] = field(default_factory=dict)  # change_id -> change row
    proposals: dict[str, dict[str, Any]] = field(default_factory=dict)  # proposal_id -> proposal row
    senders: dict[str, str] = field(default_factory=dict)  # email_id -> from_domain (filled while reading leaves)
    devices: dict[str, str] = field(default_factory=dict)  # signer address -> GENUINE / EMULATOR (from enroll leaves)
    cites: dict[str, str] = field(default_factory=dict)  # proposal_id -> email_id (from proposal leaves)
    accepted: dict[str, int | None] = field(default_factory=dict)  # nonce of an accepted signature -> its seq (replays)
    tool_args: dict[str, dict[str, str]] = field(default_factory=dict)  # "session#step" -> {"to", "iban"} (masked)
    labels: dict[str, tuple[str, int | None]] = field(default_factory=dict)  # subject -> ("ACME s.r.o. · 1.00 CZK", amt)
    attacked: dict[str, tuple[str, int | None]] = field(default_factory=dict)  # subject -> (attack kind, seq)

    def size(self) -> int:
        return sum(len(x) for x in (self.names, self.domains, self.changes, self.proposals, self.senders,
                                    self.devices, self.cites, self.accepted, self.labels, self.attacked,
                                    self.tool_args))

    def label(self, subject: Any) -> tuple[str, int | None] | None:
        """('Delta Stavby s.r.o. · 91 200.00 CZK', amount) of a payment, or ('ACME s.r.o.', None) of a change."""
        s = str(subject or "")
        if s in self.labels:
            return self.labels[s]
        p, c = self.proposals.get(s), self.changes.get(s)
        if p:
            inv = p.get("invoice") or {}
            amt = inv.get("amount_minor")
            return f"{self.vendor(inv.get('vendor_id') or p.get('vendor_id'))} · {czk(amt)}", amt
        if c and (c.get("vendor_name") or c.get("vendor_id")):
            return str(c.get("vendor_name") or self.vendor(c.get("vendor_id"))), None
        return None

    def sender_of(self, subject: Any) -> str | None:
        """Sender domain of the email a proposal / change cites."""
        em = self.cites.get(str(subject)) or (self.changes.get(str(subject)) or {}).get("email_id") or \
            ((self.proposals.get(str(subject)) or {}).get("invoice") or {}).get("email_id")
        return self.senders.get(em) if em else None

    def vendor(self, vid: Any) -> str:
        return self.names.get(str(vid or ""), str(vid or "?"))


def known_from(vendors: Iterable[dict[str, Any]] = (), changes: Iterable[dict[str, Any]] = (),
               proposals: Iterable[dict[str, Any]] = ()) -> Known:
    vendors = list(vendors or [])
    return Known(
        names={v["vendor_id"]: v.get("name") or v["vendor_id"] for v in vendors if v.get("vendor_id")},
        domains={str(v["domain"]).lower(): v.get("name") or v.get("vendor_id") for v in vendors if v.get("domain")},
        ibans={v.get("iban") for v in vendors if v.get("iban")}
        | {h.get("iban") for v in vendors for h in v.get("iban_history") or [] if h.get("iban")},
        changes={c["change_id"]: c for c in changes or [] if c.get("change_id")},
        proposals={p["proposal_id"]: p for p in proposals or [] if p.get("proposal_id")})


def _name_in(facts: Any) -> str | None:
    """The supplier name the executor put into the facts (F-SANCTION / F-WARNLIST evidence)."""
    for f in facts or []:
        if isinstance(f, dict) and f.get("id") in ("F-SANCTION", "F-WARNLIST") and isinstance(f.get("evidence"), dict):
            if f["evidence"].get("name"):
                return str(f["evidence"]["name"])
    return None


def learn(event: Any, known: Known | None) -> None:
    """Fill `known` with supplier names and payment labels from one audit leaf (decision facts, challenge params).
    Never raises; reads only named fields."""
    if known is None or not isinstance(event, dict):
        return
    try:
        typ, d, sid = event.get("type"), event.get("data"), str(event.get("subject_id") or "")
        if not isinstance(d, dict):
            return
        if typ == "decision":
            inv = _invoice_of(d)
            name = _name_in(_facts_of(d))
            if name and inv.get("vendor_id"):
                known.names.setdefault(str(inv["vendor_id"]), name)
        elif typ == "challenge" and isinstance(d.get("params"), dict):
            p = d["params"]
            if d.get("purpose") == "PAY" and p.get("payee_name") and sid:
                known.labels[sid] = (f"{clean(p['payee_name'], 60)} · {czk(p.get('amount_minor'))}",
                                     p.get("amount_minor"))
            elif d.get("purpose") in ("CHG", "CHG_REJECT") and p.get("vendor_name") and sid:
                known.labels.setdefault(sid, (clean(p["vendor_name"], 60), None))
        elif typ == "proposal":
            inv = d.get("invoice") if isinstance(d.get("invoice"), dict) else {}
            if sid and inv.get("vendor_id") and str(inv["vendor_id"]) in known.names:
                known.labels.setdefault(sid, (f"{known.vendor(inv['vendor_id'])} · {czk(inv.get('amount_minor'))}",
                                              inv.get("amount_minor")))
    except Exception:  # noqa: BLE001
        pass


def learn_body(body: Any, known: Known | None) -> None:
    """Fill `known` from a response body already in hand (POST /changes -> change, GET /vendors -> names and domains;
    never the registry IBANs: a partial IBAN set would make an honest payment look like a breach). Never raises."""
    if known is None or not isinstance(body, dict):
        return
    try:
        rows = [body["change"]] if isinstance(body.get("change"), dict) else []
        rows += [c for c in body.get("changes") or [] if isinstance(c, dict)] if isinstance(body.get("changes"),
                                                                                         list) else []
        for c in rows:
            if c.get("change_id"):
                known.changes[str(c["change_id"])] = {k: c.get(k) for k in ("change_id", "vendor_id", "vendor_name",
                                                                           "new_iban", "old_iban", "email_id",
                                                                           "state", "facts")}
                if c.get("vendor_id") and c.get("vendor_name"):
                    known.names.setdefault(str(c["vendor_id"]), str(c["vendor_name"]))
        for v in body.get("vendors") or [] if isinstance(body.get("vendors"), list) else []:
            if isinstance(v, dict) and v.get("vendor_id"):
                known.names[str(v["vendor_id"])] = str(v.get("name") or v["vendor_id"])
                if v.get("domain"):
                    known.domains[str(v["domain"]).lower()] = str(v.get("name") or v["vendor_id"])
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------- leaf explainers

def _x(level: str, kind: str, title: str, why: str = "", **kw: Any) -> Explained:
    kw["rule_ids"] = tuple(kw.get("rule_ids") or ())
    return Explained(level, kind, title, why, **kw)


def _dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _facts_of(d: dict[str, Any]) -> list[dict[str, Any]]:
    fs = _dict(_dict(_dict(d).get("inputs")).get("facts")).get("facts")
    return [f for f in fs if isinstance(f, dict)] if isinstance(fs, list) else []


def _invoice_of(d: dict[str, Any]) -> dict[str, Any]:
    return _dict(_dict(_dict(_dict(d).get("inputs")).get("subject")).get("invoice"))


def _deny_kind(rule_ids: list[str], facts: list[dict[str, Any]]) -> tuple[str, str]:
    """(level, kind) of a denied payment: hostile BLOCK facts -> ATTACK, bookkeeping blocks -> BLOCKED. Only the
    BLOCK-severity facts count: rule_ids also carry WARN facts (F-VOP close match / scheme down, F-ANOM), and an honest
    duplicate from a supplier with a WARN VoP answer is bookkeeping, not an attack. rule_ids only when facts are
    missing."""
    blocks = [f.get("id") for f in facts if _is_fact(f, ("BLOCK",))]
    # without facts the severity is unknown: only ids that are BLOCK whenever they show up at all count as hostile
    ids = set(blocks) if facts else {r for r in rule_ids if r in BLOCK_ONLY_FACTS or not r.startswith("F-")
                                     or r not in HOSTILE_FACTS}
    for fid in HOSTILE_FACTS:
        if fid in ids:
            return ATTACK, FACT_KINDS[fid]
    for fid in ("F-DUP", "F-AMOUNT-DOC", "F-SPLIT", "F-MANDATE"):
        if fid in ids:
            return BLOCKED, FACT_KINDS[fid]
    rid = next((r for r in rule_ids if r.startswith("I-")), None)
    return BLOCKED, RULE_WORDS.get(rid or "", "payment refused")


def _hint_text(hints: list[dict[str, Any]]) -> str:
    return " ".join(str(h.get("text") or h.get("display_line") or "") for h in hints or [] if isinstance(h, dict))


def injected(hints: list[dict[str, Any]]) -> bool:
    """Agent hints that carry an instruction or an account number: the agent read text written by an attacker."""
    t = _hint_text(hints)
    return bool(_INJECTION.search(t) or (find_iban(t) and re.search(r"\bpay\b|account", t, re.I)))


def _sig(d: dict[str, Any], ev: dict[str, Any], known: Known | None, fi: bool, seq: int | None = None) -> Explained:
    who = "Clerk" if d.get("role") == "clerk" else "Treasury" if d.get("role") == "treasury" else str(d.get("role"))
    what = PURPOSES.get(d.get("purpose"), str(d.get("purpose")))
    subj = ev.get("subject_id")
    lab = known.label(subj) if known is not None and subj else None
    target, money = "", None
    if lab and d.get("purpose") in ("PAY", "CHG", "CHG_REJECT"):  # 'the payment Delta Stavby s.r.o. · 91 200.00 CZK'
        noun = "payment" if d.get("purpose") == "PAY" else "bank-account change for"
        what, money = f"the {noun} {lab[0]} ({subj})", lab[1]
        target = f" for {what}"
    addr = d.get("signer_address")
    nonce = d.get("nonce")
    extra = {"signer": short_addr(addr), "purpose": d.get("purpose"), "nonce": nonce}
    if d.get("accepted"):
        if known is not None and nonce:
            known.accepted[str(nonce)] = seq
        dev = (known.devices.get(str(addr or "").lower()) if known else None) or "enrolled device"
        return _x(OK, "approval", f"{who} approved {what} on {dev} {short_addr(addr)}", money_minor=money, extra=extra)
    raw = str(d.get("error") or "")
    used = known is not None and str(nonce) in known.accepted
    at = (f" at seq {known.accepted[str(nonce)]}" if used and known.accepted.get(str(nonce)) is not None else "")
    if raw == "expired" and used:
        # an approval that was already accepted, resent after its challenge expired: a replay, not a slow clerk. The
        # rule id stays the executor's own ("expired"); the replay is the inference, stated in the evidence
        return _x(ATTACK, "replayed approval", f"{SIG_TITLES['nonce_reused']}{target}",
                  f"an approval that was already accepted was sent again after its challenge expired; every signature "
                  f"works once; nothing was approved{rules_txt([raw])}", rule_ids=[raw], money_minor=money,
                  extra=extra, layer=L_HW, evidence=f"expired: challenge {nonce} was already accepted{at}, so this is "
                                                     "a resent (replayed) approval")
    level, kind = SIG_KINDS.get(raw, (BLOCKED, "approval refused"))
    if raw.startswith("rule_violation:"):
        return _x(BLOCKED, "re-check refused", f"{who}'s approval of {what} refused: the payment no longer passes "
                  "the hard rules", f"re-checked at signing time{rules_txt([raw.split(':', 1)[1]])}", rule_ids=[raw],
                  money_minor=money, extra=extra)
    title, why = SIG_ATTACKS.get(raw, (f"{who}'s approval of {what} refused", raw.replace("_", " ")))
    if raw in SIG_TITLES:
        title = SIG_TITLES[raw] + target  # 'Forged approval for the payment Delta Stavby s.r.o. · 91 200.00 CZK'
    if raw == "expired":
        title, why = (f"Approval of {what} arrived after its challenge expired",
                      "approvals are valid for minutes and only once; a slow clerk, or someone resending a captured "
                      "approval")
    if raw in ("unknown_signer", "bad_signature"):
        why += f" (key {short_addr(addr)})" if addr else ""
    kw: dict[str, Any] = {}
    if raw == "nonce_reused":
        done = f"accepted{at}" if at else "used once"
        kw = {"layer": L_HW, "evidence": f"nonce_reused: challenge {nonce} was already {done} (approvals work once)"}
    return _x(level, kind, title, f"{why}; nothing was approved{rules_txt([raw])}", rule_ids=[raw],
              money_minor=money, extra=extra, **kw)


def _transition(d: dict[str, Any], ev: dict[str, Any], known: Known | None, fi: bool) -> Explained:
    cid = d.get("change_id") or ev.get("subject_id")
    c = _dict(known.changes.get(str(cid)) if known else None)
    lab = known.label(cid) if known is not None else None
    name_ = c.get("vendor_name") or (known.vendor(c.get("vendor_id")) if known and c.get("vendor_id") else None) or (
        lab[0] if lab else None)
    who = f"{name_} ({cid})" if name_ else cid  # "Bank-account change for ACME s.r.o. (chg_4)" / "... for chg_4"
    sup = name_ or "the supplier"
    new = f" to {iban(c['new_iban'], fi)}" if c.get("new_iban") else ""
    name, to, reason = d.get("event"), d.get("to"), str(d.get("reason") or "")
    extra = {"new_iban": iban(c["new_iban"], fi)} if c.get("new_iban") else {}
    if known and known.sender_of(cid):
        extra["sender_domain"] = known.sender_of(cid)
    if name == "CREATE" and to == "REJECTED":
        blocks = re.findall(r"F-[A-Z-]+[A-Z]", reason)
        hostile = next((FACT_KINDS[b] for b in HOSTILE_FACTS if b in blocks), None)
        facts = c.get("facts") if isinstance(c.get("facts"), list) else []
        why = reasons(facts, hostile_first=bool(hostile)) or ", ".join(
            FACT_KINDS.get(b, RULE_WORDS.get(b, b)) for b in blocks) or plain_reason(reason)
        if hostile is None:  # e.g. F-VAT unreliable VAT payer: a hard block about the supplier, not an attack
            return _x(BLOCKED, "account change refused", f"Bank-account change for {who}{new} refused on arrival",
                      f"{why}; {NO_SIGN}{rules_txt(blocks)}", rule_ids=blocks, extra=extra)
        return _x(ATTACK, hostile, f"Bank-account change for {who}{new} rejected on arrival",
                  f"{why}; {NO_SIGN}{rules_txt(blocks)}", rule_ids=blocks, extra=extra)
    if name == "CREATE":
        return _x(INFO, "account change", f"Bank-account change requested for {who}{new}",
                  "held until 2 of 3 independent confirmations (supplier ERP, supplier's bank, registry); no button "
                  "until then" if to == "PENDING_ATTEST" else "held until the supplier confirms by callback", extra=extra)
    if name == "TRIPWIRE_NOT_US":
        return _x(ATTACK, "mailbox takeover", f"Mailbox takeover ({cid}): {sup}'s registered contact "
                  "answered “not us”", f"the bank-account change request{new} came from {sup}'s own mailbox "
                  "(hacked); rejected", extra=extra)
    if name in ("CALLBACK_DENY", "CALLBACK_ATTEMPTS_EXCEEDED"):
        if name == "CALLBACK_DENY":
            return _x(ATTACK, "mailbox takeover", f"Supplier denied the bank-account change for {who} on callback",
                      f"the request{new} did not come from them; rejected", extra=extra)
        return _x(ATTACK, "callback code guessing", f"Bank-account change for {who} rejected: 3 wrong callback codes",
                  "someone guessed the supplier's callback code; rejected", extra=extra)
    if name == "VC_REVOKED":
        return _x(BLOCKED, "attestation revoked", f"Bank-account change for {who} rejected: a confirmation was revoked",
                  plain_reason(reason), extra=extra)
    if name == "CLERK_REJECT_SIGNED":
        return _x(BLOCKED, "rejected by clerk", f"Clerk rejected the bank-account change for {who} on the Trezor",
                  clean(reason, 120, full_iban=fi), extra=extra)
    if name == "EXPIRE" or to == "EXPIRED":
        return _x(BLOCKED, "expired", f"Bank-account change for {who} expired", plain_reason(reason), extra=extra)
    if to == "COOLING":
        return _x(INFO, "account change", f"Bank-account change for {who}: confirmations complete, cooling-off "
                  "started", plain_reason(reason), extra=extra)
    if to == "SIG_CLERK":
        return _x(HUMAN, "account change", f"Bank-account change for {who} needs the clerk's Trezor",
                  "cooling-off over; clerk and treasury must each confirm on their own device", extra=extra)
    if to == "SIG_TREASURY":
        return _x(HUMAN, "account change", f"Bank-account change for {who}: clerk confirmed, waiting for treasury",
                  "second, different person on their own device", extra=extra)
    if to == "ACTIVE":
        return _x(OK, "account change", f"New bank account active for {who}{new}",
                  "2 of 3 confirmations, cooling-off, clerk + treasury on hardware", extra=extra)
    return _x(INFO, "account change", f"Bank-account change {cid}: {d.get('from')} -> {to}", plain_reason(reason),
              extra=extra)


def _change_who(cid: Any, known: Known | None) -> str:
    """'ACME s.r.o. (chg_7)' when the supplier is known, else 'chg_7'."""
    lab = known.label(cid) if known is not None else None
    return f"{lab[0]} ({cid})" if lab else str(cid)


def _change_event(d: dict[str, Any], ev: dict[str, Any], known: Known | None, fi: bool) -> Explained:
    cid, name = d.get("change_id") or ev.get("subject_id"), d.get("event")
    det = d.get("detail") if isinstance(d.get("detail"), dict) else {}
    who = _change_who(cid, known)
    if name == "facts_computed":
        b = det.get("block") or []
        return _x(NOISE, "facts", f"Facts computed for {cid}: max severity {det.get('max_severity')}",
                  f"blocking: {', '.join(b)}" if b else "", rule_ids=b)
    if name == "vc_rejected":
        err = str(det.get("error") or "?")
        if err == "break_glass_required":
            return _x(BLOCKED, "attestation refused", f"Attestation for {who} refused: supplier is off-network",
                      "use the callback path", rule_ids=[err])
        return _x(ATTACK, "fake attestation", f"Fake supplier attestation for {who}",
                  f"the confirmation did not verify: {VC_WORDS.get(err, err.replace('_', ' '))}; it does not count, "
                  f"the change stays blocked{rules_txt([err])}", rule_ids=[err],
                  extra={"issuer_class": det.get("issuer_class")})
    if name == "vc_received":
        return _x(INFO, "attestation", f"Independent confirmation accepted for {who} ({det.get('issuer_class')})")
    if name == "callback_denied":
        return _x(BLOCKED, "callback denied", f"Callback for {cid} denied ({str(det.get('reason', '')).replace('_', ' ')})")
    words = {"tripwire_sent": "registered contact notified (tripwire)", "callback_issued": "callback code sent to the "
             "registered contact", "callback_confirmed": "supplier confirmed by callback", "break_glass":
             "break-glass declared (callback path)", "cooling_scheduled": "cooling-off scheduled"}
    return _x(INFO, "account change", f"Bank-account change for {who}: {words.get(str(name), str(name))}")


def recipient(to: Any) -> str:
    """An e-mail recipient for the log: the address when its local part is short and plain ('drop@acme-cz.com'), else
    only its domain ('…@evil.example'): a long local part can carry the data being exfiltrated."""
    t = clean(to, 120)
    local, at, dom = t.rpartition("@")
    if not at:
        return clean(t, 40)
    return f"{local}@{dom}" if re.fullmatch(r"[\w.+-]{1,24}", local) else f"…@{clean(dom, 60)}"


def tool_args(session: Any, step: Any, tool: str, args: Any) -> dict[str, str]:
    """What a log line may say about a refused mail tool call's arguments: the recipient (recipient()) and the first
    IBAN in the template vars, masked. The audit leaf only has args_sha256; the ops log (executor.oplog) and the
    attacker console take this from the request they hold. Never raises."""
    try:
        a = args if isinstance(args, dict) else {}
        out = {"to": recipient(a.get("to"))} if a.get("to") else {}
        ib = find_iban(" ".join(str(v) for v in _dict(a.get("vars")).values()))
        if ib:
            out["iban"] = mask_iban(ib)
        return out
    except Exception:  # noqa: BLE001
        return {}


def _tool(d: dict[str, Any], ev: dict[str, Any], known: Known | None, fi: bool) -> Explained:
    tool, res, rules = str(d.get("tool") or "?"), d.get("result"), list(d.get("rule_ids") or [])
    sess = clean(d.get("session_id"), 64) or None
    extra: dict[str, Any] = {"tool": tool, "session": sess, "step": d.get("step")}
    args = (known.tool_args.get(f"{d.get('session_id')}#{d.get('step')}") if known is not None else None) or {}
    if args.get("to"):
        extra["recipient"] = args["to"]
    if res == "forbidden":
        what = TOOL_ATTACKS.get(tool) or next((TOOL_ATTACKS[r] for r in rules if r in TOOL_ATTACKS), f"tried {tool}")
        if args.get("to") and "T-MAIL-ALLOWLIST" in rules:
            what = f"tried to email our data to {args['to']}"
        kind = "data exfiltration" if any(r.startswith("T-MAIL") for r in rules) else (
            "tampered tool manifest" if "T-MANIFEST" in rules else "replayed tool call" if "T-STEP-REUSE" in rules
            else "hijacked agent")
        why = "; ".join(RULE_WORDS.get(r, r) for r in rules) or "tool policy"
        ev_txt = ""
        if "T-MAIL-ALLOWLIST" in rules:
            ev_txt = (f"T-MAIL-ALLOWLIST: recipient {args['to']} is not on the allowlist" if args.get("to")
                      else f"T-MAIL-ALLOWLIST: the recipient is not on the allowlist ({tool})")
        elif "T-MAIL-IBAN" in rules:
            ev_txt = ("T-MAIL-IBAN: outgoing mail" + (f" to {args['to']}" if args.get("to") else "")
                      + (f" contained {args['iban']}" if args.get("iban") else " contained a bank account number"))
        return _x(ATTACK, kind, f"Hijacked agent {what}", f"refused by the tool policy: {why}{rules_txt(rules)}",
                  rule_ids=rules, extra=extra, **({"layer": L_PERM, "evidence": ev_txt} if ev_txt else {}))
    if res == "error":
        bad = "T-BAD-REQUEST" in rules
        return _x(BLOCKED, "malformed agent request" if bad else "tool error",
                  f"Agent tool call {tool} failed", "; ".join(RULE_WORDS.get(r, r) for r in rules), rule_ids=rules,
                  extra=extra, **({"layer": L_INPUT, "evidence": f"T-BAD-REQUEST: malformed tool request ({tool})"}
                                  if bad else {}))
    return _x(NOISE, "tool call", f"Agent called {tool} ({res})", rules_txt(rules).strip(), rule_ids=rules,
              extra=extra)


def _decision(d: dict[str, Any], ev: dict[str, Any], known: Known | None, fi: bool) -> Explained:
    pid, dec, rules = d.get("subject_id") or ev.get("subject_id"), d.get("decision"), list(d.get("rule_ids") or [])
    facts, inv = _facts_of(d), _invoice_of(d)
    amount = inv.get("amount_minor")
    vid = inv.get("vendor_id")
    name = known.names.get(str(vid)) if known is not None and vid else None
    what = f"{name or _name_in(facts) or vid or pid} · {czk(amount)}"
    extra: dict[str, Any] = {"invoice_no": clean(inv.get("invoice_no"), 64) or None, "vendor_id": vid}
    if known and known.sender_of(pid):
        extra["sender_domain"] = known.sender_of(pid)
    kw = {"rule_ids": rules, "money_minor": amount, "extra": extra}
    if dec == "allow":
        return _x(NOISE if d.get("recheck") else OK, "auto-pay", f"Inside the signed mandate: {what}",
                  "no human needed", **kw)
    if dec == "challenge":
        if d.get("recheck"):
            return _x(NOISE, "re-check", f"Re-checked at signing time: {what}", "still passes the hard rules", **kw)
        why = reasons(facts, ("BLOCK", "WARN")) or "outside the mandate"
        return _x(HUMAN, "needs approval", f"Needs a human on the Trezor: {what}",
                  f"{why}; the device shows the exact amount and account{rules_txt(rules)}", **kw)
    level, kind = _deny_kind(rules, facts)
    sender = f" (invoice email from {extra['sender_domain']})" if extra.get("sender_domain") else ""
    why = reasons(facts, hostile_first=level == ATTACK) or "; ".join(RULE_WORDS.get(r, r) for r in rules) or "policy"
    pre = "Re-check at signing refused" if d.get("recheck") else "Payment blocked"
    return _x(level, kind, f"{pre}: {what}{sender}", f"{why}; {NO_SIGN}{rules_txt(rules)}", **kw)


def explain(event: dict[str, Any], seq: int | None = None, *, known: Known | None = None,
            full_iban: bool = False) -> Explained | None:
    """Explain one audit leaf (v2 event). None only for a non-dict; never raises."""
    if not isinstance(event, dict):
        return None
    seq = seq if seq is not None else event.get("seq")
    seq = seq if isinstance(seq, int) and not isinstance(seq, bool) else None
    try:
        learn(event, known)
        out = _explain(event, known, full_iban, seq)
    except Exception as e:  # noqa: BLE001 - a reading aid must never break the caller
        out = _x(INFO, "unreadable", f"Audit event {event.get('type')!s:.40} (could not be explained: "
                 f"{type(e).__name__})")
    subject = out.subject or (str(event["subject_id"]) if event.get("subject_id") is not None else None)
    title, why, extra = out.title, out.why, out.extra
    try:
        if known is not None and subject:
            if out.level == ATTACK and out.kind in LINKED_KINDS:
                known.attacked[subject] = (out.kind, seq)
            elif out.level == HUMAN and subject in known.attacked:
                # the payment an attacker supplied is still waiting for a person: say so where the person looks
                k, s = known.attacked[subject]
                title = f"⚠ Linked to an attack ({k}{f', seq {s}' if s is not None else ''}): {title}"
                why = f"{why}; check it with the supplier by phone before approving, or reject it"
                extra = {**extra, "linked_attack": k}
    except Exception:  # noqa: BLE001
        pass
    res = Explained(out.level, out.kind, title, why, subject, out.money_minor, seq, out.rule_ids,
                    str(event.get("type") or "?"), event.get("actor"), event.get("ts"), extra, out.threat, out.layer,
                    out.evidence)
    return finish(res, event)


def _explain(ev: dict[str, Any], known: Known | None, fi: bool, seq: int | None = None) -> Explained:
    typ, d = ev.get("type"), ev.get("data") if isinstance(ev.get("data"), dict) else {}
    if typ == "enroll":
        dev, role, addr = d.get("device") or "?", d.get("role"), d.get("address")
        if known is not None and addr:
            known.devices[str(addr).lower()] = "software key (test)" if "software key" in str(d.get("label", "")) \
                else {"GENUINE": "the real Trezor", "EMULATOR": "the emulator"}.get(dev, str(dev))
        if d.get("active") is False:
            return _x(INFO, "signer", f"Signer revoked: {role} {short_addr(addr)}")
        return _x(INFO, "signer", f"Signer enrolled: {role} {short_addr(addr)} on {dev} {d.get('device_model') or ''}"
                  .rstrip(), clean(d.get("label"), 60))
    if typ == "ingest":
        dom, dk = str(d.get("from_domain") or "?"), d.get("dkim") or {}
        if known is not None and d.get("email_id"):
            known.senders[str(d["email_id"])] = dom
        imitated = lookalike_of(dom, known.domains) if known else None
        if imitated:
            return _x(ATTACK, "lookalike domain (BEC)", f"Email from a lookalike domain: {dom}",
                      f"imitates the registered supplier domain {imitated} ({known.domains[imitated]}); anything "
                      "it asks for is rejected on arrival", extra={"sender_domain": dom})
        return _x(INFO, "email", f"Email received from {dom}", f"DKIM {dk.get('result', '?')}",
                  extra={"sender_domain": dom})
    if typ == "challenge":
        p = d.get("params") if isinstance(d.get("params"), dict) else {}
        who = "clerk" if d.get("role") == "clerk" else str(d.get("role"))
        what = PURPOSES.get(d.get("purpose"), str(d.get("purpose")))
        amt = p.get("amount_minor")
        detail = f": {clean(p.get('payee_name'), 40)} · {czk(amt)} to {iban(p.get('iban'), fi)}" if amt else ""
        return _x(HUMAN, "approval request", f"Waiting for the {who}'s Trezor to approve {what}{detail}",
                  f"challenge {d.get('nonce')}, valid until {d.get('exp')}, works once", money_minor=amt)
    if typ == "mandate_signed":
        f = d.get("fields") or {}
        if d.get("status") == "ACTIVE":
            return _x(OK, "mandate", f"Mandate {ev.get('subject_id')} active: the agent may pay existing suppliers up "
                      f"to {czk(f.get('max_per_payment_minor'))} each, {czk(f.get('max_total_minor'))} in total, "
                      f"at most {f.get('max_count')} payments", "signed by clerk + treasury on hardware")
        return _x(HUMAN, "mandate", f"Mandate {ev.get('subject_id')} signed by the {d.get('role')} "
                  f"({d.get('sig_index')}/{d.get('sig_total')})", "waiting for the second signer")
    if typ == "proposal":
        inv = _dict(d.get("invoice"))
        hints = [h for h in d.get("hints") or [] if isinstance(h, dict)] if isinstance(d.get("hints"), list) else []
        if known is not None and inv.get("email_id"):
            known.cites[str(ev.get("subject_id"))] = str(inv["email_id"])
        what = f"{known.vendor(inv.get('vendor_id')) if known else inv.get('vendor_id')} · {czk(inv.get('amount_minor'))}"
        if injected(hints):
            return _x(ATTACK, "prompt injection", f"Hijacked agent passed on an instruction hidden in an invoice: {what}",
                      f"the agent said “{clean(_hint_text(hints), 130, full_iban=fi)}”; ignored, the agent's "
                      "words are never evidence and money can only go to the registered account",
                      money_minor=inv.get("amount_minor"),
                      extra={"invoice_no": clean(inv.get("invoice_no"), 64) or None})
        said = f"; agent said “{clean(_hint_text(hints), 60, full_iban=fi)}”" if hints else ""
        return _x(INFO, "proposal", f"Agent proposed a payment: {what}",
                  f"invoice {clean(inv.get('invoice_no'), 40)}{said}", money_minor=inv.get("amount_minor"))
    if typ == "facts":
        fs = d.get("facts") or []
        n = {s: sum(1 for f in fs if f.get("kind", "F") == "F" and f.get("severity") == s) for s in ("BLOCK", "WARN")}
        return _x(NOISE, "facts", f"Facts computed for {ev.get('subject_id')}: {n['BLOCK']} block, {n['WARN']} warn")
    if typ == "decision":
        return _decision(d, ev, known, fi)
    if typ == "state_transition":
        return _transition(d, ev, known, fi)
    if typ == "change_event":
        return _change_event(d, ev, known, fi)
    if typ == "signature":
        return _sig(d, ev, known, fi, seq)
    if typ == "attestation":
        # attest log twin of the change_event leaf, which carries the story
        ok = "verified" if d.get("verified") else f"NOT verified ({str(d.get('error') or '?').replace('_', ' ')})"
        return _x(NOISE, "attestation", f"Attestation from {d.get('issuer_class') or 'unknown issuer'} {ok} for "
                  f"{d.get('change_id')}")
    if typ == "egress_block":
        rules = list(d.get("rule_ids") or [])
        findings = "; ".join(clean(f.get("detail"), 60) for f in d.get("findings") or [] if isinstance(f, dict))
        tgt = target_host(d.get("target"))
        return _x(ATTACK, "data exfiltration", f"Outgoing {clean(d.get('tool'), 20)} to {tgt} blocked",
                  f"{findings or ', '.join(RULE_WORDS.get(r, r) for r in rules)}; nothing was sent"
                  f"{rules_txt(rules)}", rule_ids=rules, extra={"target": tgt})
    if typ == "execution":
        amt, acct = d.get("amount_minor"), d.get("iban")
        auth = d.get("authorization") or {}
        how = (f"approved on the clerk's Trezor {short_addr(auth.get('signer_address'))}"
               if auth.get("kind") == "stepup" else f"inside the signed mandate {auth.get('mandate_id')}")
        who = known.vendor(d.get("vendor_id")) if known else d.get("vendor_id")
        if known is not None and known.ibans and acct not in known.ibans:
            return _x(ERROR, "money to an unregistered account", f"PAID {czk(amt)} TO AN ACCOUNT OUTSIDE THE VENDOR "
                      f"MASTER: {iban(acct, fi)}", f"{how}; investigate now", money_minor=amt,
                      subject=d.get("proposal_id"), extra={"iban": iban(acct, fi), "tx_id": d.get("tx_id")})
        return _x(PAID, "payment", f"Paid {czk(amt)} to {who} ({iban(acct, fi)})", how, money_minor=amt,
                  subject=d.get("proposal_id"), extra={"tx_id": d.get("tx_id")})
    if typ == "rail_submitted":
        status = d.get("status")
        if status == "RJCT":
            return _x(ERROR, "bank rejected", f"Bank rejected payment order {d.get('tx_id')}",
                      "status RJCT: the bank refused the order, so no money moved; not an attack, check the order "
                      "with the bank")
        return _x(NOISE if status == "DUPL" else INFO, "bank", f"Payment order {d.get('tx_id')} sent to the bank "
                  f"({status})")
    if typ == "tool_call":
        return _tool(d, ev, known, fi)
    if typ == "iam_deny_mirror":
        what = f"{short_role(d.get('principal'))} {clean(d.get('action'), 40)} on {short_role(d.get('resource'))}"
        if d.get("source") == "simulate":
            return _x(INFO, "IAM evidence", f"IAM check: {what} is {d.get('decision')}", "simulated (evidence)")
        return _x(ATTACK, "stolen agent credentials", f"AWS refused {what}", f"IAM {d.get('decision')}")
    if typ == "attack_simulated":
        return _x(ATTACK, "drill", f"Drill: {clean(d.get('scenario'), 80)} ({clean(d.get('level'), 4)})",
                  clean(d.get("label"), 40))
    if typ == "witness_refusal":
        status = d.get("status")
        if status == 409:
            return _x(BLOCKED, "witness", f"Witness {clean(d.get('witness'), 60)} skipped a stale checkpoint",
                      f"size {d.get('size')} (it already cosigned a newer one)")
        return _x(ATTACK, "log fork / witness refusal", f"Witness {clean(d.get('witness'), 60)} REFUSED to cosign the "
                  "audit log", f"HTTP {status}: checkpoint {d.get('old_size')} -> {d.get('size')} is not an append-only "
                  "extension; the log may have been rewritten")
    if typ == "checkpoint":
        return _x(NOISE, "checkpoint", f"Audit checkpoint at size {d.get('size')}",
                  f"cosigned by {', '.join(d.get('cosigners') or []) or 'nobody yet'}")
    if typ == "anchor":
        return _x(NOISE, "anchor", f"Audit log anchored at size {d.get('tree_size')}", clean(d.get("s3_key"), 60))
    return _x(INFO, "event", f"Audit event {clean(typ, 40)}")


def target_host(target: Any) -> str:
    """Where an egress attempt went, for the log: the host of a URL (no path, query or userinfo: they can carry the
    encoded data), the recipient() of an e-mail address."""
    t = str(target or "")
    if "://" in t:
        from urllib.parse import urlsplit

        try:
            host = urlsplit(t).hostname or "?"
        except ValueError:
            host = "?"
        return clean(host, 60)
    return recipient(t) if "@" in t else clean(t.split("/")[0].split("?")[0], 60)


def short_role(arn: Any) -> str:
    s = str(arn or "?")
    return s.rsplit("/", 1)[-1] if "/" in s else s.rsplit(":", 1)[-1]


# ---------------------------------------------------------------- threat, layer, evidence

def _clause(why: str) -> str:
    """First clause of a why-line without its rule tail: 'Sender domain x imitates y; ... [F-DOMAIN]' -> 'Sender…'."""
    return re.sub(r"\s*\[[^\]]*\]$", "", str(why or "")).split("; ")[0].strip()


def _threat(x: Explained, ev: dict[str, Any]) -> str:
    if "caller_not_allowed" in x.rule_ids:  # a role calling what it may not: privilege escalation, whoever it is
        return PE
    if x.type == "tool_call" or (x.type == "request" and str((x.extra or {}).get("path", "")).startswith("/tools/")):
        rules = set(x.rule_ids)
        if any(r.startswith(("T-MAIL", "E-")) for r in rules):
            return DE
        if rules & {"T-DECOY", "T-TAINT", "T-LOOKUP-RATE"}:  # a decoy only an injected agent calls
            return PI
        return THREAT_BY_KIND.get(x.kind, PE)
    if x.kind == "drill":
        sc = str(_dict(ev.get("data")).get("scenario") or "").lower()
        return (PI if "inject" in sc else DE if "exfil" in sc else RF if re.search("nonce|replay|sign|forg", sc)
                else PE)
    return THREAT_BY_KIND.get(x.kind, PE)


def _first_fact(facts: list[dict[str, Any]], severities: tuple[str, ...] = ("BLOCK",)) -> str:
    fs = [f for f in facts if _is_fact(f, severities)]
    fs.sort(key=lambda f: HOSTILE_FACTS.index(f["id"]) if f.get("id") in HOSTILE_FACTS else 99)
    return f"{fs[0].get('id')}: {plain_fact(fs[0])}" if fs else ""


def _stopped(x: Explained, ev: dict[str, Any]) -> tuple[str, str]:
    """(layer, evidence) of an ATTACK / BLOCKED leaf, from the event alone (no store reads)."""
    d, rules = _dict(ev.get("data")), list(x.rule_ids)
    typ, r0 = x.type, (x.rule_ids[0] if x.rule_ids else "")
    if typ == "signature":
        err, nonce, who = str(d.get("error") or ""), d.get("nonce"), short_addr(d.get("signer_address"))
        if err.startswith("rule_violation:"):
            rid = err.split(":", 1)[1]
            return L_FACTS, f"{rid}: {RULE_WORDS.get(rid, 'hard rule')} (re-checked at signing time)"
        if x.kind == "replayed approval":
            return L_HW, f"{err}: challenge {nonce} was already used once (approvals work once)"
        return L_HW, {"unknown_signer": f"unknown_signer: signed by {who}, not an enrolled Trezor",
                      "bad_signature": "bad_signature: the signature does not verify for the issued text",
                      "render_mismatch": "render_mismatch: the Trezor signed a text the executor never issued "
                                         "(text hash differs)",
                      "expired": f"expired: challenge {nonce} was past its expiry"}.get(err, f"{err}: refused")
    if typ == "decision":
        facts = _facts_of(d)
        ids = {f.get("id") for f in facts if _is_fact(f, ("BLOCK", "WARN"))}
        layer = L_ANOM if "F-ANOM" in ids and x.kind == "hijacked agent" else (
            L_INPUT if x.kind == "amount not in invoice" else L_FACTS)
        return layer, _first_fact(facts) or (f"{r0}: {RULE_WORDS.get(r0, _clause(x.why))}" if r0 else _clause(x.why))
    if typ == "proposal":
        return L_INPUT, ("agent hints ignored: what the agent says is never evidence; the account comes only from the "
                         "vendor master")
    if typ == "state_transition":
        ev_name = d.get("event")
        if ev_name == "TRIPWIRE_NOT_US":
            return L_FACTS, "TRIPWIRE_NOT_US: the supplier's registered contact answered “not us”"
        if ev_name == "CALLBACK_DENY":
            return L_FACTS, "CALLBACK_DENY: the supplier denied the change on the registered callback"
        if ev_name == "CALLBACK_ATTEMPTS_EXCEEDED":
            return L_FACTS, "CALLBACK_ATTEMPTS_EXCEEDED: 3 wrong callback codes"
        return L_FACTS, (f"{r0}: {_clause(x.why)}" if r0 else _clause(x.why))
    if typ == "change_event":
        err = str(_dict(d.get("detail")).get("error") or r0)
        return L_FACTS, f"{err}: {VC_WORDS.get(err, err.replace('_', ' '))}"
    if typ == "tool_call":
        tool = str(d.get("tool") or "?")
        r = next((q for q in rules if q in ("T-DECOY", "T-TAINT", "T-LOOKUP-RATE")), r0)
        layer = L_ANOM if r in ("T-TAINT", "T-LOOKUP-RATE") else L_INPUT if r == "T-BAD-REQUEST" else L_PERM
        return layer, f"{r}: {RULE_WORDS.get(r, 'tool policy')} ({tool})" if r else f"tool policy ({tool})"
    if typ == "egress_block":
        target = target_host(d.get("target"))
        if "E-ALLOWLIST" in rules:
            return L_EGRESS, f"E-ALLOWLIST: recipient {target} is not on the allowlist"
        return L_EGRESS, f"{r0}: {_clause(x.why)}" if r0 else _clause(x.why)
    if typ == "iam_deny_mirror":
        return L_PERM, f"IAM {d.get('decision')}: {clean(d.get('action'), 40)} on {short_role(d.get('resource'))}"
    if typ in ("witness_refusal",):
        return L_TLOG, (f"HTTP {d.get('status')}: checkpoint {d.get('old_size')} -> {d.get('size')} is not an "
                        "append-only extension")
    if typ == "execution":
        return "", f"{(x.extra or {}).get('iban', '?')} is not in the vendor master"
    if typ == "ingest":
        return L_FACTS, f"F-DOMAIN: {_clause(x.why)}"
    if x.type in ("request", "response"):  # a refused request names a layer only when a check refused it
        return "", (f"{r0}: {_clause(x.why)}" if r0 else _clause(x.why))
    return (L_FACTS if x.level == BLOCKED else ""), (f"{r0}: {_clause(x.why)}" if r0 else _clause(x.why))


def finish(x: Explained, event: dict[str, Any] | None = None) -> Explained:
    """Fill threat (ATTACK and breach), layer and evidence (ATTACK / BLOCKED) where the explainer did not. Never
    raises."""
    try:
        if x.level not in (ATTACK, BLOCKED) and not is_breach(x):
            return x
        ev = event if isinstance(event, dict) else {}
        layer, evidence = x.layer, x.evidence
        if not (layer and evidence):
            l2, e2 = _stopped(x, ev)
            layer, evidence = layer or l2, evidence or e2
        threat = x.threat or (_threat(x, ev) if (x.level == ATTACK or is_breach(x)) else "")
        return replace(x, threat=threat, layer=layer, evidence=clip(evidence, 160))
    except Exception:  # noqa: BLE001
        return x


# ---------------------------------------------------------------- request-level explainers

def refusal(method: str, path: str, principal: str | None, status: int, error_code: str | None,
            message: str | None = "") -> Explained:
    """A refused request (4xx) or failure (5xx). Request-only refusals (caller_not_allowed, IBAN smuggling) are the
    only trace some attacks leave: there is no audit leaf for them."""
    try:
        return finish(_refusal(method.upper(), path.split("?")[0], principal, int(status), str(error_code or ""),
                               str(message or "")))
    except Exception as e:  # noqa: BLE001
        return _x(ERROR if status >= 500 else BLOCKED, "refused", f"{method} {path} -> {status} {error_code}",
                  type(e).__name__)


def _refusal(method: str, path: str, principal: str | None, status: int, code: str, raw: str) -> Explained:
    # never log a message as it comes: a validation error repeats the offending value (a callback code, a signature,
    # a VC); keep the field path and the kind of error only
    msg = schema_words(raw) if code == "invalid_request" else redact(raw)
    who = principal or "local caller"
    req = f"{method} {path} by {who}"
    kw = {"rule_ids": [code] if code else [], "extra": {"principal": principal, "status": status, "path": path}}
    if status >= 500:
        return _x(ERROR, "internal error", f"{req} failed ({status} {code})", msg or "see the traceback", **kw)
    if code == "caller_not_allowed":
        if path.startswith("/tools/"):
            if principal in ("agent", "tools"):
                return _x(ATTACK, "hijacked agent", f"Agent tool call refused: {req}", msg or "tool policy",
                          layer=L_PERM, evidence=f"caller_not_allowed: role '{who}' may not call {path}", **kw)
            return _x(ATTACK, "credential misuse",
                      f"The {who} role tried to use the AI agent's tools ({method} {path})",
                      f"only the agent's tool account may call them; nothing happened{rules_txt([code])}", layer=L_PERM,
                      evidence=f"caller_not_allowed: role '{who}' is not on the caller allowlist of {method} {path}",
                      **kw)
        if principal in ("agent", "tools"):
            role = "AI agent's account (agent)" if principal == "agent" else "AI agent's tool account (tools)"
            what = {"/signatures": "submit an approval (only a person on a Trezor can)",
                    "/mandates": "create a spending mandate (bank host only)"}.get(path, f"call {method} {path}")
            return _x(ATTACK, "stolen agent credentials", f"Stolen agent credentials? The {role} tried to {what}",
                      f"refused: that role may not do it; nothing happened{rules_txt([code])}", layer=L_PERM,
                      evidence=f"caller_not_allowed: role '{who}' is not on the caller allowlist of {method} {path}",
                      **kw)
        return _x(ATTACK, "credential misuse", f"{req} refused: this role may not call it",
                  f"{msg}; nothing happened{rules_txt([code])}", layer=L_PERM,
                  evidence=f"caller_not_allowed: role '{who}' is not on the caller allowlist of {method} {path}", **kw)
    if code in SIG_KINDS:
        level, kind = SIG_KINDS[code]
        title, why = SIG_ATTACKS.get(code, (f"{req} refused", code))
        return _x(level, kind, title if level == ATTACK else f"{req} refused: {kind}", f"{why}{rules_txt([code])}",
                  layer=L_PERM if code == "caller_not_allowed" else L_HW,
                  evidence=f"{code}: {_clause(why)}", **kw)
    if code == "invalid_request":
        # an unexpected field named like a bank account ('iban', 'payee_iban' ... was unexpected)
        if re.search(r"'[\w-]*iban[\w-]*'[^']{0,20}unexpected|unexpected[^']{0,20}'[\w-]*iban", raw, re.I) \
                and method == "POST" and path in ("/proposals", "/changes"):
            return _x(ATTACK, "IBAN injection", f"Someone tried to smuggle a bank account into {method} {path} "
                      f"(by {who})", "there is no such field: payments only ever go to the registered account; "
                      f"refused{rules_txt([code])}", layer=L_PERM,
                      evidence="invalid_request: there is no IBAN argument; money only goes to the vendor-master "
                               "account", **kw)
        return _x(BLOCKED, "malformed request", f"{req} refused: malformed request", msg, layer=L_INPUT,
                  evidence=f"invalid_request: {msg}", **kw)
    if code == "egress_blocked":
        return _x(ATTACK, "data exfiltration", f"Outgoing message blocked ({req})", msg, layer=L_EGRESS,
                  evidence=f"egress_blocked: {msg}", **kw)
    if code in ("attestation_insufficient", "kb_jwt_invalid", "issuer_not_pinned") and "/attestations" in path:
        return _x(ATTACK, "fake attestation", f"Supplier attestation refused ({req})", msg, layer=L_FACTS,
                  evidence=f"{code}: {VC_WORDS.get(code, msg)}", **kw)
    if code == "callback_attempts_exceeded":
        return _x(ATTACK, "callback code guessing", f"Too many wrong callback codes ({req})", msg, layer=L_FACTS,
                  evidence="callback_attempts_exceeded: 3 wrong codes", **kw)
    if code == "checkpoint_inconsistent":
        return _x(ATTACK, "log fork / witness refusal", f"Inconsistent checkpoint refused ({req})", msg,
                  layer=L_TLOG, evidence=f"checkpoint_inconsistent: {msg}", **kw)
    if code.startswith("rule_violation:"):
        rid = code.split(":", 1)[1]
        return _x(BLOCKED, "rule", f"{req} refused by rule {rid}", RULE_WORDS.get(rid, msg), layer=L_FACTS,
                  evidence=f"{rid}: {RULE_WORDS.get(rid, msg)}", **kw)
    words = {"not_found": "not found", "state_conflict": "not in the right state", "no_mandate": "no active mandate",
             "cooling_off": "cooling-off not over", "rate_limited": "rate limited",
             "sigs_insufficient": "needs a second, different signer", "emulator_not_allowed": "emulator key refused",
             "attestation_insufficient": "not enough independent confirmations yet",
             "missing_callback_attestation": "callback not confirmed yet", "callback_code_invalid":
             "wrong or expired callback code", "stale_checkpoint": "stale checkpoint",
             "break_glass_required": "supplier has no pinned confirmation service: use the callback path",
             "attestation_quorum": "the confirmations are not from enough different, independent services",
             "kb_jwt_invalid": "the holder proof is not valid", "issuer_not_pinned": "confirmation service not known",
             "egress_blocked": "outgoing message blocked", "internal_error": "internal error"}
    checks = {"sigs_insufficient": L_HW, "emulator_not_allowed": L_HW, "no_mandate": L_FACTS, "cooling_off": L_FACTS,
              "attestation_insufficient": L_FACTS, "attestation_quorum": L_FACTS, "callback_code_invalid": L_FACTS,
              "missing_callback_attestation": L_FACTS, "kb_jwt_invalid": L_FACTS, "issuer_not_pinned": L_FACTS,
              "egress_blocked": L_EGRESS}
    return _x(BLOCKED, words.get(code, code or "refused"), f"{req} refused: {words.get(code, code)}", msg,
              layer=checks.get(code, ""), evidence=f"{code}: {words.get(code, code)}" if code in checks else "",
              **kw)


_RED_FLAGS = ("F-VOP", "F-BANK", "F-VAT", "F-PSP")


_COUNTRIES = {"CZ": "Czechia", "SK": "Slovakia", "LT": "Lithuania", "LV": "Latvia", "EE": "Estonia", "PL": "Poland",
              "DE": "Germany", "AT": "Austria", "GB": "the UK", "IE": "Ireland", "NL": "the Netherlands",
              "CY": "Cyprus", "MT": "Malta", "BG": "Bulgaria", "RO": "Romania", "HU": "Hungary"}


def _flag_words(facts: list[dict[str, Any]]) -> list[str]:
    """Short plain words for the red flags of a new payee account (the full fact text stays in the console)."""
    return [w for _, w in _flags(facts)]


def _primary_flag(facts: list[dict[str, Any]], rules: list[str]) -> str:
    """'F-BANK: new account is at a foreign e-money institution (Lithuania) (+3 more red flags)': the evidence leads
    with one rule and its value."""
    fl = _flags(facts)
    if not fl:
        return f"{rules[0]}: red flag on the new account" if rules else ""
    more = len(set(rules) | {r for r, _ in fl}) - 1
    return f"{fl[0][0]}: {fl[0][1]}" + (f" (+{more} more red flag{'' if more == 1 else 's'})" if more > 0 else "")


def _flags(facts: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """(rule id, short plain words) per red flag of a new payee account, most telling first."""
    by = {f.get("id"): f for f in facts}
    out: list[tuple[str, str]] = []
    bank = _dict(by.get("F-BANK"))
    if bank.get("severity") in ("WARN", "BLOCK"):
        ev = _dict(bank.get("evidence"))
        cc = str(ev.get("country") or "")
        foreign = bool(cc and ev.get("vendor_country") and cc != ev.get("vendor_country"))
        kind = "e-money institution" if ev.get("kind") == "emi" else "bank"
        out.append(("F-BANK", f"new account is at a {'foreign ' if foreign else ''}{kind}"
                    + (f" ({_COUNTRIES.get(cc, cc)})" if cc else "")))
    vop = _dict(by.get("F-VOP"))
    if vop.get("severity") in ("WARN", "BLOCK"):
        code = str(_dict(vop.get("evidence")).get("code") or "")
        holder = re.search(r"holder is '([^']{1,60})'", str(vop.get("label") or ""))
        words = VOP_WORDS.get(code) or ("holder name only a close match" if "close match" in str(vop.get("label"))
                                        else "holder name does not match the supplier")
        out.append(("F-VOP", f"holder name '{clean(holder.group(1), 60)}' is only a close match"
                    if holder and code != "NMTC" else words))
    if _dict(by.get("F-VAT")).get("severity") in ("WARN", "BLOCK"):
        out.append(("F-VAT", "not in the VAT registry"))
    if _dict(by.get("F-PSP")).get("severity") in ("WARN", "BLOCK") and not out:
        out.append(("F-PSP", "its bank is not on the payment-scheme lists"))
    return out


def change_risk(change: dict[str, Any], *, full_iban: bool = False) -> Explained | None:
    """A payee change still pending confirmations whose new account carries red flags (Verification of Payee not a
    match, or a foreign/EMI bank not in the VAT registry): typical of a mailbox takeover. None otherwise; never
    raises."""
    try:
        r = _change_risk(change, full_iban)
        return finish(r) if r is not None else None
    except Exception:  # noqa: BLE001 - a reading aid must never break the caller
        return None


def _change_risk(change: dict[str, Any], full_iban: bool) -> Explained | None:
    if not isinstance(change, dict) or change.get("state") not in ("PENDING_ATTEST", "CALLBACK_PENDING"):
        return None
    allf = [f for f in change.get("facts") or [] if isinstance(f, dict)] if isinstance(change.get("facts"), list) \
        else []
    facts = [f for f in allf if f.get("kind", "F") == "F"]
    sev = {f.get("id"): f.get("severity") for f in facts}
    vop_bad = sev.get("F-VOP") in ("WARN", "BLOCK")
    if not (vop_bad or (sev.get("F-BANK") == "WARN" and sev.get("F-VAT") == "WARN")):
        return None
    flags = ", ".join(_flag_words(facts)) or "; ".join(
        plain_fact(f) for f in facts if f.get("id") in _RED_FLAGS and f.get("severity") != "INFO")
    who = change.get("vendor_name") or change.get("vendor_id") or "?"
    claim = [f for f in allf if f.get("kind") == "H"]
    said = (f"; the agent claimed “{clean(claim[0].get('display_line'), 60, full_iban=full_iban)}” "
            "(ignored)") if claim else ""
    n = change.get("attest_count") if isinstance(change.get("attest_count"), int) else 0
    detail = "; ".join(plain_fact(f) for f in facts if f.get("id") in _RED_FLAGS and f.get("severity") != "INFO")
    return _x(ATTACK, "mailbox takeover?", f"Suspicious bank-account change for {who} "
              f"({change.get('change_id')}) to {iban(change.get('new_iban'), full_iban)}",
              f"{flags}{said}; held: {n} of 3 independent confirmations, so there is no approval button",
              layer=L_FACTS, evidence=_primary_flag(facts, [r for r in _RED_FLAGS if sev.get(r) in ("WARN", "BLOCK")]),
              subject=change.get("change_id"), rule_ids=[r for r in _RED_FLAGS if sev.get(r) in ("WARN", "BLOCK")],
              extra={"new_iban": iban(change.get("new_iban"), full_iban), "email_id": change.get("email_id"),
                     "vendor_id": change.get("vendor_id"), "detail": detail})


def response(method: str, path: str, principal: str | None, status: int, body: Any) -> Explained | None:
    """A successful request whose response says more than its leaves: a held payee change with red flags."""
    try:
        if method.upper() == "POST" and path.split("?")[0] == "/changes" and status in (200, 201) \
                and isinstance(body, dict):
            return change_risk(body.get("change") or {})
    except Exception:  # noqa: BLE001
        return None
    return None


# ---------------------------------------------------------------- incidents (console Security view, alerts)

@dataclass
class Incident:
    """One attack (or breach) with its steps, newest step last. `who` = sender domain / signer / agent session."""

    kind: str
    title: str
    subject: str | None
    level: str  # ATTACK or ERROR
    steps: list[Explained]
    who: dict[str, Any] = field(default_factory=dict)
    money_minor: int | None = None

    @property
    def first_seq(self) -> int | None:
        return min((s.seq for s in self.steps if s.seq is not None), default=None)

    @property
    def last_seq(self) -> int | None:
        return max((s.seq for s in self.steps if s.seq is not None), default=None)

    @property
    def how_stopped(self) -> list[str]:
        return [s.why for s in self.steps if s.why]

    @property
    def main(self) -> Explained | None:
        """The step that names the attack best: of this incident's kind, not the lookalike email, newest."""
        steps = [s for s in self.steps if s.threat] or self.steps
        own = [s for s in steps if s.kind == self.kind and s.type != "ingest"] or [s for s in steps
                                                                                   if s.type != "ingest"] or steps
        return own[-1] if own else None

    @property
    def threat(self) -> str:
        return (self.main.threat if self.main else "") or THREAT_BY_KIND.get(self.kind, PE)

    @property
    def layer(self) -> str:
        return self.main.layer if self.main else ""

    @property
    def evidence(self) -> str:
        return self.main.evidence if self.main else ""

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "title": self.title, "subject": self.subject, "level": self.level,
                "threat": self.threat, "layer": self.layer, "evidence": self.evidence,
                "who": self.who, "money_minor": self.money_minor, "first_seq": self.first_seq,
                "last_seq": self.last_seq, "how_stopped": self.how_stopped, "steps": [s.as_dict() for s in self.steps]}


def explain_all(leaves: Iterable[dict[str, Any]], vendors: Iterable[dict[str, Any]] = (),
                changes: Iterable[dict[str, Any]] = (), proposals: Iterable[dict[str, Any]] = (), *,
                full_iban: bool = False, tool_calls: dict[str, dict[str, str]] | None = None) -> list[Explained]:
    """Every leaf of an export bundle (`{"seq", "event"}` rows) explained, oldest first, with console context.
    tool_calls: {"session#step": tool_args(...)} from requests the caller holds (the leaf has only args_sha256)."""
    known = known_from(vendors, changes, proposals)
    known.tool_args.update(tool_calls or {})
    out = [explain(_dict(le.get("event")), _seq(le), known=known, full_iban=full_iban) for le in _rows(leaves)]
    return [e for e in out if e is not None]


def _seq(le: dict[str, Any]) -> int | None:
    q = le.get("seq")
    return q if isinstance(q, int) and not isinstance(q, bool) else None


def _rows(leaves: Iterable[Any]) -> list[dict[str, Any]]:
    """Export rows oldest first; anything that is not a {"seq", "event"} dict, or has no int seq, sorts first."""
    try:
        rows = [le for le in leaves or [] if isinstance(le, dict)]
    except TypeError:
        return []
    return sorted(rows, key=lambda le: -1 if _seq(le) is None else _seq(le))


def is_breach(x: Any) -> bool:
    """An explanation / incident / card that means money reached an account outside the vendor master."""
    kind = x.get("kind") if isinstance(x, dict) else getattr(x, "kind", None)
    level = x.get("level") if isinstance(x, dict) else getattr(x, "level", None)
    return level == ERROR and kind == BREACH_KIND


def incidents(leaves: Iterable[dict[str, Any]], vendors: Iterable[dict[str, Any]] = (),
              changes: Iterable[dict[str, Any]] = (), proposals: Iterable[dict[str, Any]] = (), *,
              full_iban: bool = False) -> list[Incident]:
    """ATTACK explanations and breaches (BREACH_KIND) grouped per (subject, kind), newest first; other ERRORs (a
    bank rejection) are operational, not incidents. A lookalike-domain email is folded into the payment / change
    that cites it (who = sender domain). Held payee changes with red flags (change_risk, from GET /changes) are
    incidents too: no leaf says "attack" for them until the supplier answers "not us". Never raises on odd rows."""
    try:
        return _incidents(leaves, vendors, changes, proposals, full_iban)
    except Exception:  # noqa: BLE001 - a reading aid must never take the console down
        return []


def _incidents(leaves: Iterable[dict[str, Any]], vendors: Iterable[dict[str, Any]],
               changes: Iterable[dict[str, Any]], proposals: Iterable[dict[str, Any]],
               full_iban: bool) -> list[Incident]:
    changes = [c for c in changes or [] if isinstance(c, dict)]
    proposals = [p for p in proposals or [] if isinstance(p, dict)]
    known = known_from([v for v in vendors or [] if isinstance(v, dict)], changes, proposals)
    rows = _rows(leaves)
    cites: dict[str, str] = {}  # email_id -> subject that cites it
    for c in changes:
        if c.get("email_id") and c.get("change_id"):
            cites.setdefault(str(c["email_id"]), str(c["change_id"]))
    for p in proposals:
        em = _dict(p.get("invoice")).get("email_id")
        if em and p.get("proposal_id"):
            cites.setdefault(str(em), str(p["proposal_id"]))
    for le in rows:  # the email is ingested before the proposal that cites it: collect the citations first
        ev = _dict(le.get("event"))
        if ev.get("type") == "proposal":
            em = _dict(_dict(ev.get("data")).get("invoice")).get("email_id")
            if em:
                cites.setdefault(str(em), str(ev.get("subject_id")))
    groups: dict[tuple[str | None, str], Incident] = {}
    for le in rows:
        ev = _dict(le.get("event"))
        x = explain(ev, _seq(le), known=known, full_iban=full_iban)
        if x is None or not (x.level == ATTACK or is_breach(x)):
            continue
        subj = x.subject
        if x.type == "ingest":
            subj = cites.get(str(ev.get("subject_id")), subj)
        if x.type == "tool_call":
            subj = (x.extra or {}).get("session") or subj
        _add(groups, subj, x)
    seen = {k[0] for k in groups}
    for c in changes:
        r = change_risk(c, full_iban=full_iban)
        if r is not None and c.get("change_id") not in seen:
            _add(groups, c.get("change_id"), r)
    out = list(groups.values())
    for inc in out:
        doms = [s.extra.get("sender_domain") for s in inc.steps if (s.extra or {}).get("sender_domain")]
        c = known.changes.get(str(inc.subject)) or {}
        if not doms and c.get("email_id") and known.senders.get(c["email_id"]):
            doms = [known.senders[c["email_id"]]]
        for key, val in (("sender_domain", doms[0] if doms else None),
                         ("signer", next((s.extra.get("signer") for s in inc.steps
                                          if s.extra.get("signer") not in (None, "", "?")), None)),
                         ("tool", next((s.extra.get("tool") for s in inc.steps if s.extra.get("tool")), None)),
                         ("new_iban", next((s.extra.get("new_iban") for s in inc.steps if s.extra.get("new_iban")),
                                           None))):
            if val:
                inc.who[key] = val
        inc.money_minor = next((s.money_minor for s in reversed(inc.steps) if s.money_minor), None)
    return sorted(out, key=lambda i: (i.last_seq if i.last_seq is not None else 10**9), reverse=True)


def _add(groups: dict[tuple[str | None, str], Incident], subj: str | None, x: Explained) -> None:
    key = (subj, x.kind)
    inc = groups.get(key)
    if inc is None:
        # an ingest lookalike folded into a payment/change keeps the later, more specific kind of that subject
        same = [k for k in groups if k[0] == subj and subj is not None]
        if same and (x.type == "ingest" or groups[same[0]].steps[0].type == "ingest"):
            inc = groups[same[0]]
            if inc.steps[0].type == "ingest" and x.type != "ingest":
                inc.kind, inc.title = x.kind, x.title
            inc.steps.append(x)
            return
        groups[key] = Incident(x.kind, x.title, subj, x.level, [x])
        return
    if inc.steps[0].type == "ingest" and x.type != "ingest" and all(s.type == "ingest" for s in inc.steps):
        inc.title = x.title  # the payment / change the email asked for says more than "email from a lookalike"
    inc.steps.append(x)
    if is_breach(x):
        inc.level = ERROR
