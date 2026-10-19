"""Payee-change FSM v2 (CONTRACTS §6.1). S4 over the contract tables. Owner: WS-D.

The guards themselves (VC verification, callback codes, cooling-off) are tested by WS-D once
machine.transition() is implemented; these tests freeze the table every workstream codes against.
"""
from __future__ import annotations

import itertools

import pytest
from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from executor.change import machine as M
from executor.models import TERMINAL_STATES, ChangeEvent, ChangeState

S, E = ChangeState, ChangeEvent

EXPECTED = {
    (S.PENDING_ATTEST, S.COOLING), (S.PENDING_ATTEST, S.CALLBACK_PENDING),
    (S.CALLBACK_PENDING, S.COOLING),
    (S.COOLING, S.SIG_CLERK),
    (S.SIG_CLERK, S.SIG_TREASURY),
    (S.SIG_TREASURY, S.ACTIVE),
} | {(s, d) for s in S if s not in TERMINAL_STATES for d in (S.REJECTED, S.EXPIRED)}


def test_states_v2():
    assert [s.value for s in S] == ["PENDING_ATTEST", "CALLBACK_PENDING", "COOLING", "SIG_CLERK", "SIG_TREASURY",
                                    "ACTIVE", "REJECTED", "EXPIRED"]
    assert TERMINAL_STATES == {S.ACTIVE, S.REJECTED, S.EXPIRED}
    assert M.INITIAL_STATES == {S.REJECTED, S.PENDING_ATTEST, S.CALLBACK_PENDING}
    for gone in ("REQUESTED", "FACTS_DONE", "ATTESTATION_CHECK", "TRIPWIRE_SENT", "CALLBACK_CONFIRMED",
                 "CALLBACK_DENIED"):
        assert gone not in S.__members__


def test_s4_forbidden_transitions():
    for src, dst in itertools.product(S, S):
        assert M.is_allowed(src, dst) == ((src, dst) in EXPECTED), (src, dst)


def test_s4_active_only_via_dual_control():
    assert {s for s in S if M.is_allowed(s, S.ACTIVE)} == {S.SIG_TREASURY}
    assert {s for s in S if M.is_allowed(s, S.SIG_TREASURY)} == {S.SIG_CLERK}
    assert {s for s in S if M.is_allowed(s, S.SIG_CLERK)} == {S.COOLING}
    assert {s for s in S if M.is_allowed(s, S.COOLING)} == {S.PENDING_ATTEST, S.CALLBACK_PENDING}


def test_terminal_states_have_no_exits():
    for t in TERMINAL_STATES:
        assert M.ALLOWED_TRANSITIONS[t] == set()
        for e in E:
            with pytest.raises(M.ForbiddenTransition):
                M.next_state(t, e)


def test_event_table_is_subset_of_transitions():
    for (src, _event), dst in M.EVENT_TRANSITIONS.items():
        assert M.is_allowed(src, dst)
    assert {(s, d) for (s, _), d in M.EVENT_TRANSITIONS.items()} == EXPECTED


@pytest.mark.parametrize("src,event,dst", [
    (S.PENDING_ATTEST, E.VC_RECEIVED, S.COOLING),
    (S.PENDING_ATTEST, E.BREAK_GLASS, S.CALLBACK_PENDING),
    (S.CALLBACK_PENDING, E.CALLBACK_CONFIRM, S.COOLING),
    (S.CALLBACK_PENDING, E.CALLBACK_DENY, S.REJECTED),
    (S.CALLBACK_PENDING, E.CALLBACK_ATTEMPTS_EXCEEDED, S.REJECTED),
    (S.COOLING, E.COOLING_ELAPSED, S.SIG_CLERK),
    (S.SIG_CLERK, E.CLERK_SIGNED, S.SIG_TREASURY),
    (S.SIG_TREASURY, E.TREASURY_SIGNED, S.ACTIVE),
    (S.SIG_TREASURY, E.TRIPWIRE_NOT_US, S.REJECTED),
    (S.COOLING, E.VC_REVOKED, S.REJECTED),
    (S.SIG_CLERK, E.CLERK_REJECT_SIGNED, S.REJECTED),
    (S.PENDING_ATTEST, E.EXPIRE, S.EXPIRED),
])
def test_event_rows(src, event, dst):
    assert M.next_state(src, event) == dst


@pytest.mark.parametrize("src,event", [
    (S.PENDING_ATTEST, E.CLERK_SIGNED),       # no signature before attestation (R0)
    (S.PENDING_ATTEST, E.CALLBACK_CONFIRM),   # callback only on the break-glass/off-network path
    (S.COOLING, E.CLERK_SIGNED),              # cooling-off first
    (S.SIG_CLERK, E.TREASURY_SIGNED),         # treasury before clerk
    (S.CALLBACK_PENDING, E.VC_RECEIVED),
])
def test_forbidden_events(src, event):
    with pytest.raises(M.ForbiddenTransition):
        M.next_state(src, event)


class ChangeWalk(RuleBasedStateMachine):
    """Random event sequences over the table: ACTIVE always implies attest-or-callback, cooling, clerk, treasury."""

    def __init__(self):
        super().__init__()
        self.state = S.PENDING_ATTEST
        self.path = [self.state]

    @rule(start=st.sampled_from(sorted(M.INITIAL_STATES - {S.REJECTED})))
    def restart(self, start):
        self.state = start
        self.path = [start]

    @rule(event=st.sampled_from(list(E)))
    def fire(self, event):
        try:
            self.state = M.next_state(self.state, event)
        except M.ForbiddenTransition:
            return
        self.path.append(self.state)

    @invariant()
    def active_requires_full_path(self):
        if self.state == S.ACTIVE:
            p = self.path
            assert p[-3:] == [S.SIG_CLERK, S.SIG_TREASURY, S.ACTIVE]
            assert p[-4] == S.COOLING
            assert p[-5] in (S.PENDING_ATTEST, S.CALLBACK_PENDING)


TestChangeWalk = ChangeWalk.TestCase
TestChangeWalk.settings = settings(max_examples=200, stateful_step_count=20, deadline=None)
