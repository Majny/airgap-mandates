"""S8 witness tests (C2SP tlog-witness, CONTRACTS.md v2 §7.3, §8.2). Owner: WS-B."""
import pytest


def test_s8_fork_refused():
    pytest.skip("TODO WS-B: inconsistent checkpoint -> 422 + witness_refusal leaf")


def test_s8_stale_409():
    pytest.skip("TODO WS-B: old size != witness size -> 409 text/x.tlog.size")
