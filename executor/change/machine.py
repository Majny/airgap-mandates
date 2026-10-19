"""Payee-change state machine v2. Owner: WS-D. Implements CONTRACTS.md v2 §6.1 (S4, R0).

ALLOWED_TRANSITIONS, INITIAL_STATES and EVENT_TRANSITIONS are contract data; any transition not listed is
forbidden. The v1 transient states are now `change_event` leaves (models.ChangeEventKind), not states.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from executor.models import TERMINAL_STATES, Change, ChangeEvent, ChangeState, FactSet

S = ChangeState
E = ChangeEvent

_NON_TERMINAL = [s for s in ChangeState if s not in TERMINAL_STATES]

# States a change can be created in (the "(create)" rows of §6.1).
INITIAL_STATES: frozenset[ChangeState] = frozenset({S.REJECTED, S.PENDING_ATTEST, S.CALLBACK_PENDING})

ALLOWED_TRANSITIONS: dict[ChangeState, set[ChangeState]] = {
    S.PENDING_ATTEST: {S.COOLING, S.CALLBACK_PENDING},
    S.CALLBACK_PENDING: {S.COOLING},
    S.COOLING: {S.SIG_CLERK},
    S.SIG_CLERK: {S.SIG_TREASURY},
    S.SIG_TREASURY: {S.ACTIVE},
    S.ACTIVE: set(),
    S.REJECTED: set(),
    S.EXPIRED: set(),
}
# Any non-terminal state may go to REJECTED or EXPIRED.
for _s in _NON_TERMINAL:
    ALLOWED_TRANSITIONS[_s] |= {S.REJECTED, S.EXPIRED}

# (state, event) -> destination. Guards are in CONTRACTS §6.1 and implemented by transition().
EVENT_TRANSITIONS: dict[tuple[ChangeState, ChangeEvent], ChangeState] = {
    (S.PENDING_ATTEST, E.VC_RECEIVED): S.COOLING,
    (S.PENDING_ATTEST, E.BREAK_GLASS): S.CALLBACK_PENDING,
    (S.CALLBACK_PENDING, E.CALLBACK_CONFIRM): S.COOLING,
    (S.CALLBACK_PENDING, E.CALLBACK_DENY): S.REJECTED,
    (S.CALLBACK_PENDING, E.CALLBACK_ATTEMPTS_EXCEEDED): S.REJECTED,
    (S.COOLING, E.COOLING_ELAPSED): S.SIG_CLERK,
    (S.SIG_CLERK, E.CLERK_SIGNED): S.SIG_TREASURY,
    (S.SIG_TREASURY, E.TREASURY_SIGNED): S.ACTIVE,
}
for _s in _NON_TERMINAL:
    EVENT_TRANSITIONS[(_s, E.TRIPWIRE_NOT_US)] = S.REJECTED
    EVENT_TRANSITIONS[(_s, E.VC_REVOKED)] = S.REJECTED
    EVENT_TRANSITIONS[(_s, E.CLERK_REJECT_SIGNED)] = S.REJECTED
    EVENT_TRANSITIONS[(_s, E.EXPIRE)] = S.EXPIRED


class ForbiddenTransition(Exception):
    """Raised when a transition outside ALLOWED_TRANSITIONS / EVENT_TRANSITIONS is attempted."""


def is_allowed(src: ChangeState, dst: ChangeState) -> bool:
    """True iff src -> dst is in the transition table."""
    return dst in ALLOWED_TRANSITIONS[src]


def next_state(src: ChangeState, event: ChangeEvent) -> ChangeState:
    """Destination of `event` in state `src` (table lookup only, no guards); raises ForbiddenTransition."""
    try:
        dst = EVENT_TRANSITIONS[(src, event)]
    except KeyError:
        raise ForbiddenTransition(f"{event.value} not allowed in {src.value}") from None
    assert is_allowed(src, dst)
    return dst


def create(req: dict[str, Any], facts: FactSet, vendor: dict[str, Any], *, store: Any, settings: Any,
           now: datetime) -> Change:
    """POST /changes: initial state REJECTED (any F BLOCK) | PENDING_ATTEST (in_network) | CALLBACK_PENDING;
    tripwire to the registered contact on every create; change_event + state_transition leaves."""
    raise NotImplementedError("TODO WS-D")


def transition(change_id: str, event: ChangeEvent, *, payload: dict[str, Any] | None = None, store: Any,
               settings: Any, now: datetime) -> Change:
    """Apply one guarded event (CONTRACTS §6.1); appends state_transition (and change_event) leaves.
    Raises ForbiddenTransition / ApiError(state_conflict | attestation_insufficient | ...)."""
    raise NotImplementedError("TODO WS-D")


def advance(change: Change, *, store: Any, settings: Any, now: datetime) -> Change:
    """Lazy advance on read: EXPIRE when now >= expires_at; COOLING_ELAPSED when now >= not_before
    (policy set `change` must allow; issues the clerk CHG challenge)."""
    raise NotImplementedError("TODO WS-D")


def on_signature(change: Change, *, role: str, signer_address: str, nonce: str, store: Any, settings: Any,
                 now: datetime) -> Change:
    """Guards for CHG signatures (§6.1): attestation_insufficient / missing_callback_attestation /
    cooling_off / sigs_insufficient / emulator_not_allowed; SIG_CLERK -> SIG_TREASURY -> ACTIVE."""
    raise NotImplementedError("TODO WS-D")
