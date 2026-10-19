#!/usr/bin/env bash
# S7 evidence: simulate-principal-policy for the agent (and host) roles against the money/state actions.
# Output: infra/evidence/iam_simulate.json + a table. Read-only IAM API. Owner: WS-E.
set -euo pipefail
cd "$(dirname "$0")"
export AWS_PROFILE=${AWS_PROFILE:-hackathon} AWS_REGION=${AWS_REGION:-eu-central-1}
ACCT=$(aws sts get-caller-identity --query Account --output text)
API=$(aws cloudformation describe-stacks --stack-name AirgapMandates --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue" --output text | sed -E 's#https://([^.]+)\..*#\1#')
T="arn:aws:dynamodb:eu-central-1:$ACCT:table/airgap-"
X="arn:aws:execute-api:eu-central-1:$ACCT:$API/prod"
mkdir -p evidence
sim() {  # role action resource
  aws iam simulate-principal-policy --policy-source-arn "arn:aws:iam::$ACCT:role/$1" --action-names "$2" \
    --resource-arns "$3" --query "EvaluationResults[0].[EvalActionName,EvalResourceName,EvalDecision]" --output text \
    | awk -v r="$1" '{printf "%-14s %-26s %-16s %s\n", r, $1, $3, $2}'
}
{
  printf "%-14s %-26s %-16s %s\n" ROLE ACTION DECISION RESOURCE
  for a in dynamodb:PutItem dynamodb:UpdateItem dynamodb:TransactWriteItems dynamodb:GetItem; do
    for t in ledger mandates audit registry main; do sim airgap-agent "$a" "$T$t"; done; done
  sim airgap-agent kms:Sign "arn:aws:kms:eu-central-1:$ACCT:key/*"
  sim airgap-agent secretsmanager:GetSecretValue "arn:aws:secretsmanager:eu-central-1:$ACCT:secret:*"
  for p in "POST/signatures" "POST/mandates" "POST/proposals" "POST/changes" "POST/egress" "POST/changes/x/approve"; do
    sim airgap-agent execute-api:Invoke "$X/$p"; done
  sim airgap-agent bedrock:InvokeModel "arn:aws:bedrock:eu-central-1:$ACCT:inference-profile/eu.anthropic.claude-sonnet-4-5-20250929-v1:0"
  sim airgap-host dynamodb:PutItem "${T}ledger"
  sim airgap-host kms:Sign "arn:aws:kms:eu-central-1:$ACCT:key/*"
  sim airgap-host execute-api:Invoke "$X/POST/signatures"
  sim airgap-tools dynamodb:PutItem "${T}ledger"
  sim airgap-tools execute-api:Invoke "$X/POST/signatures"
  sim airgap-executor-api kms:Sign "arn:aws:kms:eu-central-1:$ACCT:key/*"
} | tee evidence/iam_simulate.txt
echo "NOTE: KMS key policies are not evaluated by simulate-principal-policy; the KMS boundary is the key policy (see 'aws kms get-key-policy')."
