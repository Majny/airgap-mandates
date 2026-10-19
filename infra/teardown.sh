#!/usr/bin/env bash
# Tear down everything the stack created. Object Lock (GOVERNANCE) objects are removed with
# --bypass-governance-retention; KMS keys go to PendingDeletion (7 days). Owner: WS-E.
set -euo pipefail
export AWS_PROFILE=${AWS_PROFILE:-hackathon} AWS_REGION=${AWS_REGION:-eu-central-1}
ACCT=$(aws sts get-caller-identity --query Account --output text)
read -r -p "Delete stack AirgapMandates and all its data in $ACCT? type 'teardown': " ok
[ "$ok" = "teardown" ] || exit 1
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
aws kms list-aliases --query "Aliases[?starts_with(AliasName,'alias/airgap-')].[AliasName,TargetKeyId]" --output text
echo "Leftovers check:"
aws dynamodb list-tables --query "TableNames[?starts_with(@,'airgap-')]" --output text
aws logs describe-log-groups --log-group-name-prefix /aws/lambda/airgap- --query 'logGroups[].logGroupName' --output text
