#!/usr/bin/env bash
# Tear down everything the stack created. Order: stop the scheduled writers (tick/anchor) and block the checkpointer,
# empty the Object Lock bucket (--bypass-governance-retention) and the inbox, cdk destroy, delete leftover Lambda log
# groups, optionally the CDK bootstrap stack (--with-bootstrap). KMS keys go to PendingDeletion (7 days). Owner: WS-E.
set -euo pipefail
export AWS_PROFILE=${AWS_PROFILE:-hackathon} AWS_REGION=${AWS_REGION:-eu-central-1}
ACCT=$(aws sts get-caller-identity --query Account --output text)
[ "$ACCT" = "503002144042" ] || { echo "refusing: account $ACCT is not the team account"; exit 1; }
read -r -p "Delete stack AirgapMandates and all its data in $ACCT? type 'teardown': " ok
[ "$ok" = "teardown" ] || exit 1
for s in airgap-tick airgap-anchor; do
  aws scheduler delete-schedule --name "$s" 2>/dev/null && echo "deleted schedule $s" || true
done
aws lambda put-function-concurrency --function-name airgap-checkpointer --reserved-concurrent-executions 0 \
  >/dev/null 2>&1 || true
sleep 65  # let an in-flight checkpointer/anchor run finish before emptying its bucket
empty() {  # bucket [bypass]
  aws s3api head-bucket --bucket "$1" 2>/dev/null || return 0
  while :; do
    J=$(aws s3api list-object-versions --bucket "$1" --max-items 500 \
      --query '{Objects: [Versions[].{Key:Key,VersionId:VersionId}, DeleteMarkers[].{Key:Key,VersionId:VersionId}][]}' --output json)
    [ "$(echo "$J" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["Objects"] or []))')" = 0 ] && break
    aws s3api delete-objects --bucket "$1" --delete "$J" ${2:+--bypass-governance-retention} >/dev/null
  done
}
empty "airgap-log-$ACCT" bypass
empty "airgap-inbox-$ACCT"
(cd "$(dirname "$0")" && npx --yes aws-cdk@2 destroy --force AirgapMandates)
for g in $(aws logs describe-log-groups --log-group-name-prefix /aws/lambda/airgap- --query 'logGroups[].logGroupName' --output text) \
         $(aws logs describe-log-groups --log-group-name-prefix /airgap- --query 'logGroups[].logGroupName' --output text); do
  aws logs delete-log-group --log-group-name "$g" && echo "deleted log group $g"
done
if [ "${1:-}" = "--with-bootstrap" ]; then
  B=$(aws cloudformation describe-stacks --stack-name CDKToolkit --query "Stacks[0].Outputs[?OutputKey=='BucketName'].OutputValue" --output text)
  empty "$B"
  aws cloudformation delete-stack --stack-name CDKToolkit && echo "deleting CDKToolkit"
fi
echo "Leftovers check:"
aws kms list-aliases --query "Aliases[?starts_with(AliasName,'alias/airgap-')].AliasName" --output text
aws dynamodb list-tables --query "TableNames[?starts_with(@,'airgap-')]" --output text
