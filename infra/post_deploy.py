"""Post-deploy wiring (needs AWS; run by infra/post_deploy.sh). Owner: WS-E.

Reads stack outputs, derives the signed-note vkeys from the KMS Ed25519 public keys, sets AIRGAP_W1_LOG_VKEY on the
W1 (witness) function and prints the vkeys + URLs the host / auditor / W2 need.
"""
from __future__ import annotations

import json
import os

import boto3

from executor.audit import checkpoint
from executor.config import Settings

REGION = os.environ.get("AWS_REGION", "eu-central-1")


def outputs() -> dict[str, str]:
    cf = boto3.client("cloudformation", region_name=REGION)
    return {o["OutputKey"]: o["OutputValue"] for o in cf.describe_stacks(StackName="AirgapMandates")["Stacks"][0]["Outputs"]}


def set_env(function: str, extra: dict[str, str]) -> None:
    lam = boto3.client("lambda", region_name=REGION)
    env = lam.get_function_configuration(FunctionName=function).get("Environment", {}).get("Variables", {})
    lam.update_function_configuration(FunctionName=function, Environment={"Variables": {**env, **extra}})


def main() -> None:
    out = outputs()
    settings = Settings.from_env({**os.environ, "AIRGAP_BACKEND": "aws", "AWS_REGION": REGION,
                                  "AIRGAP_KMS_KEY_ID": out["LogKeyId"], "AIRGAP_WITNESS_KMS_KEY_ID": out["W1KeyId"]})
    vk = checkpoint.vkeys(settings)
    set_env("airgap-witness", {"AIRGAP_W1_LOG_VKEY": vk["log"]})
    print(json.dumps({"api_url": out["ApiUrl"], "agent_tools_url": out["AgentToolsUrl"], "vkeys": vk,
                      "code_sha256": out["CodeSha256"], "w2_instance": out.get("W2InstanceId"),
                      "next": ["infra/w2_ctl.sh trust '<log vkey>'", "infra/w2_ctl.sh vkey -> AIRGAP_W2_VKEY",
                               "infra/iam_evidence.sh"]}, indent=2))


if __name__ == "__main__":
    main()
