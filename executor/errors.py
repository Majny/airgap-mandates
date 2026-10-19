"""API error codes and ApiError. Owner: WS-A. Implements CONTRACTS.md v2 §2.4 and §4.4.

Pure contract data: every error code the executor (and W1 witness) may return, with its HTTP status.
"""
from __future__ import annotations

from typing import Any


class ErrorCode:
    INVALID_REQUEST = "invalid_request"
    NOT_FOUND = "not_found"
    NO_MANDATE = "no_mandate"
    RENDER_MISMATCH = "render_mismatch"
    BAD_SIGNATURE = "bad_signature"
    UNKNOWN_SIGNER = "unknown_signer"
    NONCE_REUSED = "nonce_reused"
    EXPIRED = "expired"
    MISSING_CALLBACK_ATTESTATION = "missing_callback_attestation"
    ATTESTATION_INSUFFICIENT = "attestation_insufficient"  # replaces v1 vendor_attestation_missing
    KB_JWT_INVALID = "kb_jwt_invalid"
    ISSUER_NOT_PINNED = "issuer_not_pinned"
    BREAK_GLASS_REQUIRED = "break_glass_required"
    CALLBACK_ATTEMPTS_EXCEEDED = "callback_attempts_exceeded"
    EMULATOR_NOT_ALLOWED = "emulator_not_allowed"
    ATTESTATION_QUORUM = "attestation_quorum"  # hardware issuer profile
    COOLING_OFF = "cooling_off"
    SIGS_INSUFFICIENT = "sigs_insufficient"
    RULE_VIOLATION_PREFIX = "rule_violation:"  # e.g. "rule_violation:I-DUP"
    EGRESS_BLOCKED = "egress_blocked"
    CALLBACK_CODE_INVALID = "callback_code_invalid"
    CALLER_NOT_ALLOWED = "caller_not_allowed"
    STATE_CONFLICT = "state_conflict"
    STALE_CHECKPOINT = "stale_checkpoint"  # witness 409
    CHECKPOINT_INCONSISTENT = "checkpoint_inconsistent"  # witness 422
    RATE_LIMITED = "rate_limited"
    INTERNAL_ERROR = "internal_error"

    @staticmethod
    def rule_violation(rule_id: str) -> str:
        """Return the error code for a violated rule id, e.g. 'rule_violation:I-DUP'."""
        return f"{ErrorCode.RULE_VIOLATION_PREFIX}{rule_id}"


HTTP_STATUS: dict[str, int] = {
    ErrorCode.INVALID_REQUEST: 400,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.NO_MANDATE: 404,
    ErrorCode.RENDER_MISMATCH: 403,
    ErrorCode.BAD_SIGNATURE: 403,
    ErrorCode.UNKNOWN_SIGNER: 403,
    ErrorCode.NONCE_REUSED: 403,
    ErrorCode.EXPIRED: 403,
    ErrorCode.MISSING_CALLBACK_ATTESTATION: 403,
    ErrorCode.ATTESTATION_INSUFFICIENT: 403,
    ErrorCode.KB_JWT_INVALID: 403,
    ErrorCode.ISSUER_NOT_PINNED: 403,
    ErrorCode.BREAK_GLASS_REQUIRED: 403,
    ErrorCode.CALLBACK_ATTEMPTS_EXCEEDED: 403,
    ErrorCode.EMULATOR_NOT_ALLOWED: 403,
    ErrorCode.ATTESTATION_QUORUM: 403,
    ErrorCode.COOLING_OFF: 403,
    ErrorCode.SIGS_INSUFFICIENT: 403,
    ErrorCode.EGRESS_BLOCKED: 403,
    ErrorCode.CALLBACK_CODE_INVALID: 403,
    ErrorCode.CALLER_NOT_ALLOWED: 403,
    ErrorCode.STATE_CONFLICT: 409,
    ErrorCode.STALE_CHECKPOINT: 409,
    ErrorCode.CHECKPOINT_INCONSISTENT: 422,
    ErrorCode.RATE_LIMITED: 429,
    ErrorCode.INTERNAL_ERROR: 500,
}

ERROR_CODES: list[str] = list(HTTP_STATUS)


def status_for(code: str) -> int:
    """HTTP status for an error code (rule_violation:<ID> -> 403)."""
    if code.startswith(ErrorCode.RULE_VIOLATION_PREFIX):
        return 403
    return HTTP_STATUS[code]


class ApiError(Exception):
    """Raised anywhere in the executor; handler.dispatch turns it into an error body."""

    def __init__(self, code: str, message: str = "", details: dict[str, Any] | None = None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.details = details or {}
        self.status = status_for(code)

    def to_body(self) -> dict[str, Any]:
        body: dict[str, Any] = {"error": self.code, "message": self.message}
        if self.details:
            body["details"] = self.details
        return body
