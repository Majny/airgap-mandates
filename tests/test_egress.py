"""Security invariant tests (CONTRACTS.md v2 §8.2). Owner: WS-E."""
import os

import pytest


def test_s9_exfil_corpus_zero_success():
    pytest.skip("TODO WS-E")


def test_s9_benign_pass():
    pytest.skip("TODO WS-E")


@pytest.mark.skipif(os.environ.get("AIRGAP_BACKEND") != "aws", reason="S10 is proven on AWS only")
def test_s10_no_route():
    pytest.skip("TODO WS-E: httpx.get('https://example.com') from the agent VPC fails; Flow Logs REJECT")
