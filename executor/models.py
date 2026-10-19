"""Shared enums and TypedDicts mirroring CONTRACTS.md §2–§7. Owner: all (edit only together with the doc).

Pure contract data, no logic.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, NotRequired, TypedDict


class Kind(str, Enum):
    F = "F"
    H = "H"


class Severity(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    BLOCK = "BLOCK"


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    CHALLENGE = "challenge"


class Purpose(str, Enum):
    MANDATE = "MANDATE"
    CHG = "CHG"
    PAY = "PAY"
    VENDOR_ATTEST = "VENDOR_ATTEST"


class Role(str, Enum):
    CLERK = "clerk"
    TREASURY = "treasury"
    DIRECTOR = "director"
    ACCOUNTANT = "accountant"
    FINANCE = "finance"


BANK_ROLES = frozenset({Role.CLERK, Role.TREASURY})
VENDOR_ROLES = frozenset({Role.DIRECTOR, Role.ACCOUNTANT, Role.FINANCE})


class ChangeState(str, Enum):
    REQUESTED = "REQUESTED"
    FACTS_DONE = "FACTS_DONE"
    ATTESTATION_CHECK = "ATTESTATION_CHECK"
    TRIPWIRE_SENT = "TRIPWIRE_SENT"
    CALLBACK_PENDING = "CALLBACK_PENDING"
    CALLBACK_CONFIRMED = "CALLBACK_CONFIRMED"
    CALLBACK_DENIED = "CALLBACK_DENIED"
    COOLING = "COOLING"
    SIG_CLERK = "SIG_CLERK"
    SIG_TREASURY = "SIG_TREASURY"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REJECTED = "REJECTED"


TERMINAL_STATES = frozenset({ChangeState.ACTIVE, ChangeState.EXPIRED, ChangeState.REJECTED})


class MandateStatus(str, Enum):
    PENDING_SIG = "PENDING_SIG"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    SUPERSEDED = "SUPERSEDED"


class ProposalStatus(str, Enum):
    EXECUTED = "EXECUTED"
    DENIED = "DENIED"
    PENDING_SIG = "PENDING_SIG"
    EXPIRED = "EXPIRED"
    REJECTED = "REJECTED"


class AttestationStatus(str, Enum):
    PENDING_SIGS = "PENDING_SIGS"
    PUBLISHED = "PUBLISHED"
    REVOKED = "REVOKED"
    SUPERSEDED = "SUPERSEDED"


class AuditEventType(str, Enum):
    ENROLL = "enroll"
    INGEST = "ingest"
    CHALLENGE = "challenge"
    MANDATE_SIGNED = "mandate_signed"
    PROPOSAL = "proposal"
    FACTS = "facts"
    DECISION = "decision"
    STATE_TRANSITION = "state_transition"
    SIGNATURE = "signature"
    ATTESTATION = "attestation"
    EGRESS_BLOCK = "egress_block"
    EXECUTION = "execution"
    ANCHOR = "anchor"


class Actor(str, Enum):
    EXECUTOR = "executor"
    AGENT = "agent"
    HOST = "host"
    VENDOR_PORTAL = "vendor_portal"
    INGEST = "ingest"
    WITNESS = "witness"
    TOOL = "tool"


class EgressRule(str, Enum):
    ALLOWLIST = "E-ALLOWLIST"
    DLP_IBAN = "E-DLP-IBAN"
    DLP_ICO = "E-DLP-ICO"
    DLP_NAME = "E-DLP-NAME"
    DLP_CARD = "E-DLP-CARD"
    DLP_COUNT = "E-DLP-COUNT"
    ENCODED = "E-ENCODED"
    URLDATA = "E-URLDATA"


class EffectType(str, Enum):
    MANDATE_ACTIVATED = "mandate_activated"
    PAYMENT_EXECUTED = "payment_executed"
    CHANGE_ADVANCED = "change_advanced"
    ATTESTATION_SIGNED = "attestation_signed"
    ATTESTATION_PUBLISHED = "attestation_published"


# Display tiebreak order for F facts (CONTRACTS.md §2.1 / §5.4). Unknown ids sort after, lexicographic.
FACT_ORDER: list[str] = [
    "F-MANDATE",
    "F-ATTEST",
    "F-CALLBACK",
    "F-DOMAIN",
    "F-DKIM",
    "F-FIRSTSEEN",
    "F-BANK",
    "F-VAT",
    "F-VOP",
    "F-DUP",
    "F-SPLIT",
    "F-Z",
]
H_FACT_IDS: list[str] = ["H-AGENT", "H-UI"]

RULE_IDS: list[str] = [
    "I-MANDATE", "I-EXP", "I-PER", "I-BUDGET", "I-COUNT",
    "I-PAYEE", "I-NONCE", "I-DUP", "I-SPLIT", "I-Z",
]


class Fact(TypedDict):
    id: str
    kind: str  # "F" | "H"
    severity: str  # "INFO" | "WARN" | "BLOCK"
    label: str
    display_line: str
    evidence: NotRequired[dict[str, Any]]


class ChallengeRef(TypedDict):
    nonce: str
    purpose: str
    role: str
    subject_id: str
    exp: str
    text: str
    text_sha256: str
    width: int
    line_count: int
    used: NotRequired[bool]
    created_at: NotRequired[str]


class DecisionObj(TypedDict):
    decision: str  # "allow" | "deny" | "challenge"
    rule_ids: list[str]
    facts: list[Fact]
    mandate_id: str | None
    policy_hash: str
    challenge: NotRequired[ChallengeRef]


class Mandate(TypedDict):
    mandate_id: str
    mandate_no: int
    status: str
    max_per_payment_minor: int
    max_total_minor: int
    max_count: int
    payee_scope: str
    valid_until: str
    currency: str
    policy_hash: str
    signer_address: str | None
    spent_minor: int
    count: int
    challenge_nonce: str
    created_at: str
    activated_at: str | None


class Invoice(TypedDict):
    invoice_no: str
    issue_date: str
    vendor_ico: str
    vendor_name: str
    iban: str
    amount_minor: int
    currency: str
    due_date: NotRequired[str]
    vs: NotRequired[str]
    email_id: NotRequired[str]
    attachment_sha256: NotRequired[str]


class Hint(TypedDict):
    source: str  # "agent" | "ui"
    text: str


class Proposal(TypedDict):
    proposal_id: str
    proposal_no: int
    vendor_id: str | None
    status: str
    invoice: Invoice
    hints: list[Hint]
    facts: list[Fact]
    decision: DecisionObj
    challenge_nonce: str | None
    tx_id: str | None
    created_at: str


class ChangeSignature(TypedDict):
    role: str
    address: str
    nonce: str
    signed_at: str


class Transition(TypedDict):
    to: str
    at: str
    reason: str
    # "from" is a keyword; access via dict key "from".


class Change(TypedDict):
    change_id: str
    change_no: int
    vendor_id: str
    vendor_ico: str
    vendor_name: str
    old_iban: str
    new_iban: str
    state: str
    in_network: bool
    facts: list[Fact]
    not_before: str | None
    expires_at: str
    callback: dict[str, Any]
    signatures: list[ChangeSignature]
    pending_challenge: ChallengeRef | None
    history: list[dict[str, str]]
    email_id: NotRequired[str]
    created_at: str


class IbanHistoryEntry(TypedDict):
    iban: str
    to: str | None
    change_id: str | None


class Vendor(TypedDict):
    vendor_id: str
    ico: str
    name: str
    domain: str
    iban: str
    country: str
    phone: str
    contact_email: str
    registered_since: str
    in_network: bool
    iban_history: list[dict[str, Any]]
    bic: NotRequired[str]
    updated_at: NotRequired[str]


class Authorization(TypedDict):
    kind: str  # "mandate" | "stepup"
    mandate_id: NotRequired[str]
    nonce: NotRequired[str]
    signer_address: NotRequired[str]


class LedgerTx(TypedDict):
    tx_id: str
    proposal_id: str
    vendor_id: str
    iban: str
    amount_minor: int
    currency: str
    authorization: Authorization
    leaf_index: int
    executed_at: str
    vs: NotRequired[str]


class AuditEvent(TypedDict):
    v: int
    log_id: str  # "audit" | "attest"
    seq: int
    ts: str
    type: str
    actor: str
    subject_id: str | None
    data: dict[str, Any]
