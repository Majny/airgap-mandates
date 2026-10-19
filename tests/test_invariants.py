"""Security invariant tests (CONTRACTS.md v2 §8.2). Owners: WS-A (S1, S3), WS-A/WS-D (R0)."""
import pytest


def test_s1_ledger_rows_have_authorization():
    pytest.skip("TODO WS-A")


def test_s3_hint_monotonicity():
    pytest.skip("TODO WS-A: hypothesis perturbation of hints only ever moves toward deny")


def test_r0_no_challenge_on_block():
    pytest.skip("TODO WS-A/WS-D: any BLOCK fact (incl. F-ATTEST < 2) => decision deny, no challenge")
