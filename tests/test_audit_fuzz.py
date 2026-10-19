"""Security invariant tests (CONTRACTS.md v2 §8.2). Owners: WS-A (S6), WS-B (S6 lag, S12)."""
import pytest


def test_s6_crash_between():
    pytest.skip("TODO WS-A: crash injection around tx_execute; no ledger row without its execution leaf")


def test_s6_checkpoint_lag():
    pytest.skip("TODO WS-B: every execution covered by a witnessed checkpoint within 60 s")


def test_s12_replay():
    pytest.skip("TODO WS-B: verify_audit --replay reproduces every decision at its policy_hash")
