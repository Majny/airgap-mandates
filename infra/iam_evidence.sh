#!/usr/bin/env bash
# S7 evidence table (identity policies of each airgap role). See infra/iam_evidence.py. Owner: WS-E.
set -euo pipefail
cd "$(dirname "$0")/.."
export AWS_PROFILE=${AWS_PROFILE:-hackathon} AWS_REGION=${AWS_REGION:-eu-central-1}
.venv/bin/python -m infra.iam_evidence
