"""Payee-change state machine (M2). Owner: WS-A. Implements CONTRACTS.md §6.1 (S4).

ALLOWED_TRANSITIONS is contract data; any transition not listed is forbidden.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from executor.models import TERMINAL_STATES, Change, ChangeState, Role

S = ChangeState

_NON_TERMINAL = [s for s in ChangeState if s not in TERMINAL_STATES]

ALLOWED_TRANSITIONS: dict[ChangeState, set[ChangeState]] = {
    S.REQUESTED: {S.FACTS_DONE},
    S.FACTS_DONE: {S.ATTESTATION_CHECK},
    S.ATTESTATION_CHECK: {S.COOLING, S.TRIPWIRE_SENT},
    S.TRIPWIRE_SENT: {S.CALLBACK_PENDING},
    S.CALLBACK_PENDING: {S.CALLBACK_CONFIRMED, S.CALLBACK_DENIED},
    S.CALLBACK_CONFIRMED: {S.COOLING},
    S.CALLBACK_DENIED: {S.REJECTED},
    S.COOLING: {S.SIG_CLERK},
    S.SIG_CLERK: {S.SIG_TREASURY},
    S.SIG_TREASURY: {S.ACTIVE},
    S.ACTIVE: set(),
    S.EXPIRED: set(),
    S.REJECTED: set(),
}
# Any non-terminal state may go to EXPIRED or REJECTED.
for _s in _NON_TERMINAL:
    ALLOWED_TRANSITIONS[_s] |= {S.EXPIRED, S.REJECTED}


class ForbiddenTransition(Exception):
    """Raised when a transition outside ALLOWED_TRANSITIONS is attempted."""


def is_allowed(src: ChangeState, dst: ChangeState) -> bool:
    """True iff src -> dst is in the transition table."""
    return dst in ALLOWED_TRANSITIONS[src]


def transition(change: Change, dst: ChangeState, *, at: datetime, reason: str) -> Change:
    """Apply one checked transition, append history and a state_transition audit leaf."""
    raise NotImplementedError("TODO WS-A")


def create_change(vendor_ico: str, new_iban: str, *, email_id: str | None, hints: list[dict[str, Any]], at: datetime) -> Change:
    """REQUESTED -> FACTS_DONE -> ATTESTATION_CHECK (+ auto steps); returns change with preview clerk challenge."""
    raise NotImplementedError("TODO WS-A")


def advance(change: Change, *, at: datetime) -> Change:
    """Lazy advance: expiry, attestation re-check, COOLING -> SIG_CLERK when now >= not_before."""
    raise NotImplementedError("TODO WS-A")


def on_callback(change: Change, *, code: str, outcome: str, at: datetime) -> Change:
    """CALLBACK_PENDING -> CALLBACK_CONFIRMED | CALLBACK_DENIED (403 callback_code_invalid on bad code)."""
    raise NotImplementedError("TODO WS-A")


def on_signature(change: Change, *, role: Role, signer_address: str, nonce: str, at: datetime) -> Change:
    """Guards for CHG signatures (§6.1): vendor_attestation_missing / missing_callback_attestation /
    cooling_off / sigs_insufficient; SIG_CLERK -> SIG_TREASURY -> ACTIVE."""
    raise NotImplementedError("TODO WS-A")


def reject(change: Change, *, reason: str, at: datetime) -> Change:
    """Any non-terminal -> REJECTED (409 state_conflict if terminal)."""
    raise NotImplementedError("TODO WS-A")
