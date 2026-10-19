#!/usr/bin/env bash
# After `cdk deploy`: set AIRGAP_W1_LOG_VKEY on W1 from the KMS log key, print vkeys and URLs. Owner: WS-E.
set -euo pipefail
cd "$(dirname "$0")/.."
export AWS_PROFILE=${AWS_PROFILE:-hackathon} AWS_REGION=${AWS_REGION:-eu-central-1}
.venv/bin/python -m infra.post_deploy | tee infra/evidence/post_deploy.json
