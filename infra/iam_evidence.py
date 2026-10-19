"""S7 evidence: evaluate each airgap role's own IAM policies (inline + managed) with simulate-custom-policy.

simulate-principal-policy also folds in the organisation's SCPs (unreadable for us) and then reports explicitDeny
with no matched statement, which is not evidence of OUR split. Here each row names the statement that decided.
Output: infra/evidence/iam_simulate.txt. Read-only IAM APIs. Owner: WS-E.
"""
from __future__ import annotations

import json
from pathlib import Path

import boto3

iam = boto3.client("iam")
ACCT = boto3.client("sts").get_caller_identity()["Account"]
REGION = "eu-central-1"
OUT = Path(__file__).resolve().parent / "evidence" / "iam_simulate.txt"


def policies(role: str) -> list[str]:
    docs = [json.dumps(iam.get_role_policy(RoleName=role, PolicyName=n)["PolicyDocument"])
            for n in iam.list_role_policies(RoleName=role)["PolicyNames"]]
    for p in iam.list_attached_role_policies(RoleName=role)["AttachedPolicies"]:
        v = iam.get_policy(PolicyArn=p["PolicyArn"])["Policy"]["DefaultVersionId"]
        docs.append(json.dumps(iam.get_policy_version(PolicyArn=p["PolicyArn"], VersionId=v)["PolicyVersion"]["Document"]))
    return docs


def main() -> None:
    api = boto3.client("cloudformation", region_name=REGION).describe_stacks(StackName="AirgapMandates")["Stacks"][0]
    out = {o["OutputKey"]: o["OutputValue"] for o in api["Outputs"]}
    api_id = out["ApiUrl"].split("//")[1].split(".")[0]
    tbl = f"arn:aws:dynamodb:{REGION}:{ACCT}:table/airgap-"
    x = f"arn:aws:execute-api:{REGION}:{ACCT}:{api_id}/prod"
    key = f"arn:aws:kms:{REGION}:{ACCT}:key/{out['LogKeyId']}"
    sonnet = f"arn:aws:bedrock:{REGION}:{ACCT}:inference-profile/eu.anthropic.claude-sonnet-4-5-20250929-v1:0"
    cases = [("airgap-agent", a, tbl + t) for a in ("dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:GetItem")
             for t in ("ledger", "mandates", "audit", "registry", "main")]
    cases += [("airgap-agent", "kms:Sign", key),
              ("airgap-agent", "secretsmanager:GetSecretValue", f"arn:aws:secretsmanager:{REGION}:{ACCT}:secret:x"),
              *[("airgap-agent", "execute-api:Invoke", f"{x}/POST/{p}")
                for p in ("signatures", "mandates", "proposals", "changes", "egress", "changes/x/approve")],
              ("airgap-agent", "bedrock:InvokeModel", sonnet),
              ("airgap-host", "execute-api:Invoke", f"{x}/POST/signatures"),
              ("airgap-host", "execute-api:Invoke", f"{x}/POST/proposals"),
              ("airgap-host", "dynamodb:PutItem", tbl + "ledger"),
              ("airgap-host", "kms:Sign", key),
              ("airgap-tools", "execute-api:Invoke", f"{x}/POST/proposals"),
              ("airgap-tools", "execute-api:Invoke", f"{x}/POST/signatures"),
              ("airgap-tools", "dynamodb:PutItem", tbl + "ledger"),
              ("airgap-executor-api", "dynamodb:PutItem", tbl + "ledger"), ("airgap-executor-api", "dynamodb:ConditionCheckItem", tbl + "mandates"),
              ("airgap-executor-api", "dynamodb:PutItem", tbl + "witness_state"),
              ("airgap-witness", "dynamodb:PutItem", tbl + "ledger")]
    cache: dict[str, list[str]] = {}
    lines = [f"{'ROLE':<20} {'ACTION':<30} {'DECISION':<13} {'STATEMENT':<18} RESOURCE"]
    for role, action, res in cases:
        docs = cache.setdefault(role, policies(role))
        r = iam.simulate_custom_policy(PolicyInputList=docs, ActionNames=[action], ResourceArns=[res])["EvaluationResults"][0]
        sid = ",".join(m.get("SourcePolicyId", "")[:18] for m in r.get("MatchedStatements", [])) or "-"
        lines.append(f"{role:<20} {action:<30} {r['EvalDecision']:<13} {sid:<18} {res.split(':')[-1][-60:]}")
    lines.append("Identity policies only (simulate-custom-policy). KMS: key policies name role ARNs directly "
                 "(aws kms get-key-policy); org SCPs are an extra layer we cannot read.")
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
