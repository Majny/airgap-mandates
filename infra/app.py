#!/usr/bin/env python3
"""CDK app entry. `cd infra && npx aws-cdk@2 synth` (no AWS calls) / `deploy` (needs approval). Owner: WS-E."""
import aws_cdk as cdk

from airgap_stack import AirgapStack

app = cdk.App()
AirgapStack(app, "AirgapMandates", env=cdk.Environment(account="503002144042", region="eu-central-1"),
            description="AirGap Mandates hackathon demo (FinTechers 2026). Teardown: infra/teardown.sh")
cdk.Tags.of(app).add("project", "airgap-mandates")
app.synth()
