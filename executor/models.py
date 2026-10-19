"""Shared enums and TypedDicts mirroring CONTRACTS.md v2 §2–§11. Owner: all (edit only together with the doc).

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
    PENDING = "pending"  # payee change accepted into the FSM, no challenge yet (CONTRACTS §2.2)


class Purpose(str, Enum):
    MANDATE = "MANDATE"
    CHG = "CHG"
    PAY = "PAY"
    VENDOR_ATTEST = "VENDOR_ATTEST"
    ENROLL = "ENROLL"
    CHG_REJECT = "CHG_REJECT"


class Role(str, Enum):
    CLERK = "clerk"
    TREASURY = "treasury"
    DIRECTOR = "director"
    ACCOUNTANT = "accountant"
    FINANCE = "finance"


BANK_ROLES = frozenset({Role.CLERK, Role.TREASURY})
VENDOR_ROLES = frozenset({Role.DIRECTOR, Role.ACCOUNTANT, Role.FINANCE})


class ChangeState(str, Enum):
    PENDING_ATTEST = "PENDING_ATTEST"
    CALLBACK_PENDING = "CALLBACK_PENDING"
    COOLING = "COOLING"
    SIG_CLERK = "SIG_CLERK"
    SIG_TREASURY = "SIG_TREASURY"
    ACTIVE = "ACTIVE"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


TERMINAL_STATES = frozenset({ChangeState.ACTIVE, ChangeState.EXPIRED, ChangeState.REJECTED})


class ChangeEvent(str, Enum):
    """FSM triggers (CONTRACTS §6.1)."""

    CREATE = "CREATE"
    VC_RECEIVED = "VC_RECEIVED"
    BREAK_GLASS = "BREAK_GLASS"
    CALLBACK_CONFIRM = "CALLBACK_CONFIRM"
    CALLBACK_DENY = "CALLBACK_DENY"
    CALLBACK_ATTEMPTS_EXCEEDED = "CALLBACK_ATTEMPTS_EXCEEDED"
    COOLING_ELAPSED = "COOLING_ELAPSED"
    CLERK_SIGNED = "CLERK_SIGNED"
    TREASURY_SIGNED = "TREASURY_SIGNED"
    TRIPWIRE_NOT_US = "TRIPWIRE_NOT_US"
    VC_REVOKED = "VC_REVOKED"
    CLERK_REJECT_SIGNED = "CLERK_REJECT_SIGNED"
    EXPIRE = "EXPIRE"


class ChangeEventKind(str, Enum):
    """`change_event` leaf kinds (the v1 transient states, CONTRACTS §7.2)."""

    FACTS_COMPUTED = "facts_computed"
    TRIPWIRE_SENT = "tripwire_sent"
    CALLBACK_ISSUED = "callback_issued"
    CALLBACK_CONFIRMED = "callback_confirmed"
    CALLBACK_DENIED = "callback_denied"
    VC_RECEIVED = "vc_received"
    VC_REJECTED = "vc_rejected"
    BREAK_GLASS = "break_glass"
    COOLING_SCHEDULED = "cooling_scheduled"


class MandateStatus(str, Enum):
    PENDING_SIG_CLERK = "PENDING_SIG_CLERK"
    PENDING_SIG_TREASURY = "PENDING_SIG_TREASURY"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    SUPERSEDED = "SUPERSEDED"


class ProposalStatus(str, Enum):
    EXECUTED = "EXECUTED"
    DENIED = "DENIED"
    PENDING_SIG = "PENDING_SIG"
    EXPIRED = "EXPIRED"
    REJECTED = "REJECTED"


class ReasonCode(str, Enum):
    DUE = "DUE"
    PARTIAL = "PARTIAL"
    ADVANCE = "ADVANCE"
    OTHER = "OTHER"


class AttestationStatus(str, Enum):
    """Hardware issuer profile (v1 vendor_attest path, kept)."""

    PENDING_SIGS = "PENDING_SIGS"
    PUBLISHED = "PUBLISHED"
    REVOKED = "REVOKED"
    SUPERSEDED = "SUPERSEDED"


class IssuerClass(str, Enum):
    SUPPLIER_ERP = "supplier-erp"
    SUPPLIER_BANK = "supplier-bank"
    REGISTRY = "registry"


class VopCode(str, Enum):
    MTCH = "MTCH"
    CMTC = "CMTC"
    NMTC = "NMTC"
    NOAP = "NOAP"


class DeviceAuthenticity(str, Enum):
    GENUINE = "GENUINE"
    EMULATOR = "EMULATOR"


class RailStatus(str, Enum):
    PENDING = "PENDING"
    ACTC = "ACTC"
    ACSC = "ACSC"
    RJCT = "RJCT"
    DUPL = "DUPL"


class AuditEventType(str, Enum):
    ENROLL = "enroll"
    INGEST = "ingest"
    CHALLENGE = "challenge"
    MANDATE_SIGNED = "mandate_signed"
    PROPOSAL = "proposal"
    FACTS = "facts"
    DECISION = "decision"
    STATE_TRANSITION = "state_transition"
    CHANGE_EVENT = "change_event"
    SIGNATURE = "signature"
    ATTESTATION = "attestation"
    EGRESS_BLOCK = "egress_block"
    EXECUTION = "execution"
    RAIL_SUBMITTED = "rail_submitted"
    TOOL_CALL = "tool_call"
    IAM_DENY_MIRROR = "iam_deny_mirror"
    ATTACK_SIMULATED = "attack_simulated"
    WITNESS_REFUSAL = "witness_refusal"
    CHECKPOINT = "checkpoint"
    ANCHOR = "anchor"


# Events that must carry policy_hash / inputs_digest / facts_digest / hints_digest (CONTRACTS §7.2).
DECISION_RELEVANT_EVENTS = frozenset({
    AuditEventType.PROPOSAL, AuditEventType.FACTS, AuditEventType.DECISION, AuditEventType.CHALLENGE,
    AuditEventType.SIGNATURE, AuditEventType.EXECUTION, AuditEventType.CHANGE_EVENT,
    AuditEventType.STATE_TRANSITION,
})


class Actor(str, Enum):
    EXECUTOR = "executor"
    AGENT = "agent"
    HOST = "host"
    VENDOR_PORTAL = "vendor_portal"
    INGEST = "ingest"
    WITNESS = "witness"
    TOOLS = "tools"
    ISSUER = "issuer"
    CHECKPOINTER = "checkpointer"
    RAIL = "rail"
    SCHEDULER = "scheduler"
    AUDITOR = "auditor"


class EgressRule(str, Enum):
    ALLOWLIST = "E-ALLOWLIST"
    DLP_IBAN = "E-DLP-IBAN"
    DLP_ICO = "E-DLP-ICO"
    DLP_NAME = "E-DLP-NAME"
    DLP_CARD = "E-DLP-CARD"
    DLP_COUNT = "E-DLP-COUNT"
    ENCODED = "E-ENCODED"
    URLDATA = "E-URLDATA"
    GUARDRAILS = "E-GUARDRAILS"
    SIZE = "E-SIZE"
    RATE = "E-RATE"


class EffectType(str, Enum):
    MANDATE_SIGNED = "mandate_signed"  # first of a 2/2 mandate
    MANDATE_ACTIVATED = "mandate_activated"
    PAYMENT_EXECUTED = "payment_executed"
    CHANGE_ADVANCED = "change_advanced"
    CHANGE_REJECTED = "change_rejected"
    ATTESTATION_SIGNED = "attestation_signed"
    ATTESTATION_PUBLISHED = "attestation_published"
    ENROLLED = "enrolled"


class BenchArm(str, Enum):
    A0 = "A0"
    A1 = "A1"
    A2 = "A2"
    A3 = "A3"


ATTACKER_LEVELS: list[str] = ["H0", "H1", "H2", "H3", "H4", "H5", "H6"]
HUMAN_POLICIES: list[str] = ["diligent", "rubber_stamp"]
AGENT_MODES: list[str] = ["naive", "quarantined"]

# Device display order of F facts (CONTRACTS §2.1 table order / §5.4). Unknown ids sort after, by id.
FACT_ORDER: list[str] = [
    "F-MANDATE",
    "F-ATTEST",
    "F-CALLBACK",
    "F-DOMAIN",
    "F-DKIM",
    "F-DOMAIN-AGE",
    "F-WARNLIST",
    "F-SANCTION",
    "F-VOP",
    "F-PSP",
    "F-VAT",
    "F-BANK",
    "F-FIRSTSEEN",
    "F-DUP",
    "F-AMOUNT-DOC",
    "F-SPLIT",
    "F-Z",
    "F-ANOM",
    "F-NAME-TRANSLIT",
]
H_FACT_IDS: list[str] = ["H-AGENT", "H-UI"]

# Cedar @id rule ids (CONTRACTS §8.1). P-* permits are never reported in rule_ids.
RULE_IDS: list[str] = [
    "I-PAYEE", "I-DUP", "I-BLOCK",
    "I-MANDATE", "I-EXP", "I-PER", "I-BUDGET", "I-COUNT", "I-REGISTRY", "I-VOP", "I-ANOM", "I-SPLIT", "I-Z", "I-WARN",
    "I-ATTEST", "I-CALLBACK", "I-COOLOFF",
    "I-NONCE",
]

SNAPSHOT_NAMES: list[str] = ["mostlyright", "adis", "dns", "whois", "bank_codes", "registry", "vop", "toollog"]


class Fact(TypedDict):
    id: str
    kind: str  # "F" | "H"
    severity: str  # "INFO" | "WARN" | "BLOCK"
    label: str
    display_line: str  # ASCII, <= 18 chars
    evidence: NotRequired[dict[str, Any]]
    prov: NotRequired[str]  # sha256 hex of the source snapshot


class FactSet(TypedDict):
    subject_id: str
    computed_at: str
    facts: list[Fact]
    facts_digest: str
    snapshots: dict[str, str]
    max_severity: str


class ChallengeRef(TypedDict):
    nonce: str  # 8 uppercase hex
    purpose: str
    role: str
    subject_id: str
    deployment: str
    profile: str
    exp: str
    text: str
    text_sha256: str
    subject_hash: str
    width: int
    lines_per_page: int
    pages: int
    line_count: int
    used: NotRequired[bool]
    created_at: NotRequired[str]


class DecisionObj(TypedDict):
    decision: str  # "allow" | "deny" | "challenge" | "pending"
    rule_ids: list[str]
    facts: list[Fact]
    facts_digest: str
    mandate_id: str | None
    policy_hash: str
    challenge: NotRequired[ChallengeRef]


class MandateSigner(TypedDict):
    role: str
    address: str
    nonce: str
    signed_at: str


class Mandate(TypedDict):
    mandate_id: str
    mandate_no: int
    status: str
    max_per_payment_minor: int
    max_total_minor: int
    max_count: int
    payee_scope: str
    valid_from: str
    valid_until: str
    currency: str
    require_vop: list[str]
    max_anom: int
    payee_registry_version: int
    payee_registry_hash: str
    policy_hash: str
    sig_required: int
    signers: list[MandateSigner]
    spent_minor: int
    count: int
    challenge_nonce: str
    created_at: str
    activated_at: str | None


class Invoice(TypedDict):
    """proposal_create.request.invoice — no IBAN, no vendor name (P3)."""

    vendor_id: str
    invoice_no: str
    invoice_ref: str
    issue_date: str
    amount_minor: int
    currency: str
    reason_code: str
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
    vendor_id: str
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


class AttestSummary(TypedDict):
    issuer_class: str
    iss: str
    verified: bool
    error: str | None
    verified_at: str


class AttestResult(TypedDict):
    ok: bool
    issuer_class: str | None
    iss: str | None
    error: str | None
    disclosed: dict[str, str]
    vc_sha256: str


class Change(TypedDict):
    change_id: str
    change_no: int
    vendor_id: str
    vendor_ico: str
    vendor_name: str
    old_iban: str
    old_since: str
    new_iban: str
    state: str
    in_network: bool
    break_glass: bool
    change_nonce: str
    aud: str
    facts: list[Fact]
    attestations: list[AttestSummary]
    attest_count: int
    not_before: str | None
    expires_at: str
    callback: dict[str, Any]  # {status, code_exp, attempts}
    tripwire_sent_at: str | None
    signatures: list[ChangeSignature]
    pending_challenge: ChallengeRef | None
    history: list[dict[str, Any]]  # {from, to, at, reason, actor}
    email_id: str | None
    created_at: str


class Vendor(TypedDict):
    """Row of the `registry` table (was `vendors`)."""

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
    issuer_pins: list[dict[str, Any]]
    iban_history: list[dict[str, Any]]
    bic: NotRequired[str]
    updated_at: NotRequired[str]


class Authorization(TypedDict):
    kind: str  # "mandate" | "stepup"
    mandate_id: NotRequired[str]
    nonce: NotRequired[str]
    signer_address: NotRequired[str]


class LedgerTx(TypedDict):
    tx_id: str  # tx_<16 hex> = sha256(auth_ref|proposal_id)[:16]
    proposal_id: str
    vendor_id: str
    iban: str
    amount_minor: int
    currency: str
    authorization: Authorization
    seq: int
    executed_at: str
    rail: dict[str, Any]  # {status, xml_c14n_sha256?}
    vs: NotRequired[str | None]


class AuditEvent(TypedDict):
    v: int  # 2
    log_id: str  # "audit" | "attest"
    seq: int
    ts: str
    type: str
    actor: str
    subject_id: str | None
    data: dict[str, Any]
    policy_hash: str | None
    inputs_digest: str | None
    facts_digest: str | None
    hints_digest: str | None


class Approval(TypedDict):
    """host.signer.SignerDriver.sign() result (CONTRACTS §6)."""

    nonce: str
    address: str
    sig: str
    displayed_text: str
    device: str  # GENUINE | EMULATOR


class BenchCase(TypedDict):
    id: str
    arm: str
    attacker_level: str
    vector: str
    goal: str
    seed: int
    expected: dict[str, Any]


class BenchResult(TypedDict):
    case_id: str
    arm: str
    model: str
    agent_mode: str
    human_policy: str
    utility_ok: bool
    attack_success: bool
    money_moved_minor: int
    bytes_exfil: int
    rule_ids: list[str]
    steps: int
    latency_ms: int
    tokens: int
    cost_usd_micros: int
    git_sha: str
