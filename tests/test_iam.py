"""Security invariant tests (CONTRACTS.md v2 §8.2). Owner: WS-E."""
import os

import pytest


@pytest.mark.skipif(os.environ.get("AIRGAP_BACKEND") != "aws", reason="S7 is proven on AWS only")
def test_s7_simulate_principal_policy():
    pytest.skip("TODO WS-E: iam simulate-principal-policy + live boto3 AccessDenied")
