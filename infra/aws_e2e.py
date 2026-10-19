"""Drive the demo beat S1 (executor.e2e.run) against the deployed AWS stack. Owner: WS-E.

Each call assumes the IAM role of its principal (airgap-host, airgap-tools) and SigV4-signs the request to the
regional API, so the executor sees the real role ARN. `--seed` writes the demo registry and two enrolled software
signer keys (kept in .local/aws_e2e_keys.json, git-ignored) into the real tables with the operator's credentials.
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
import httpx
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from eth_account import Account

REGION = "eu-central-1"
KEYS = Path(".local/aws_e2e_keys.json")
_creds: dict[str, Credentials] = {}


EXPECTED_ACCOUNT = "503002144042"  # the hackathon team account; destructive helpers refuse any other


def require_team_account() -> None:
    os.environ.setdefault("AWS_PROFILE", "hackathon")
    acct = boto3.client("sts").get_caller_identity()["Account"]
    if acct != EXPECTED_ACCOUNT:
        raise SystemExit(f"refusing: credentials are for account {acct}, expected {EXPECTED_ACCOUNT}")


def role_creds(who: str) -> Credentials:
    if who not in _creds:
        acct = boto3.client("sts").get_caller_identity()["Account"]
        c = boto3.client("sts").assume_role(RoleArn=f"arn:aws:iam::{acct}:role/airgap-{who.replace('_', '-')}",
                                            RoleSessionName=f"e2e-{who}")["Credentials"]
        _creds[who] = Credentials(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"])
    return _creds[who]


def signed_call(base: str):
    client = httpx.Client(timeout=60)

    def call(m: str, p: str, b: Any, who: str) -> tuple[int, Any]:
        data = None if b is None else json.dumps(b).encode()
        req = AWSRequest(method=m, url=base + p, data=data, headers={"content-type": "application/json"})
        SigV4Auth(role_creds(who), "execute-api", REGION).add_auth(req)
        r = client.request(m, base + p, content=data, headers=dict(req.headers.items()))
        return r.status_code, r.json() if "json" in r.headers.get("content-type", "") else r.text

    return call


def aws_settings() -> Any:
    from executor.config import Settings

    acct = boto3.client("sts").get_caller_identity()["Account"]
    out = {o["OutputKey"]: o["OutputValue"] for o in boto3.client("cloudformation", region_name=REGION)
           .describe_stacks(StackName="AirgapMandates")["Stacks"][0]["Outputs"]}
    # like the Lambdas: only the scheduled checkpointer signs checkpoints, never this operator process
    return Settings.from_env({**os.environ, "AIRGAP_BACKEND": "aws", "AWS_REGION": REGION,
                              "AIRGAP_INBOX_BUCKET": f"airgap-inbox-{acct}", "AIRGAP_DATA_DIR": "data",
                              "AIRGAP_KMS_KEY_ID": out["LogKeyId"], "AIRGAP_WITNESS_KMS_KEY_ID": out["W1KeyId"],
                              "AIRGAP_CHECKPOINT_EVERY_N_LEAVES": "1000000000",
                              "AIRGAP_CHECKPOINT_MAX_SECONDS": "1000000000"})


def seed(*, fallback_clerk: bool = False, stage: bool = False) -> tuple[Any, Any]:
    """Registry (vendors.json + issuer pins), enrolled signers and inbox via WS-D's tools.seed_data, then the two
    e2e software signer keys (enroll leaf labelled 'software key, aws e2e')."""
    from executor.store import get_store
    from tools import seed_data

    keys = json.loads(KEYS.read_text()) if KEYS.exists() else {
        "clerk": Account.create().key.hex(), "treasury": Account.create().key.hex()}
    KEYS.parent.mkdir(exist_ok=True)
    KEYS.write_text(json.dumps(keys))
    s = aws_settings()
    st = get_store(s)
    if fallback_clerk:
        # activate the inactive EMULATOR clerk of data/enrollment.json AT seeding time: one enroll leaf per address
        # (re-enrolling afterwards would log a second leaf, which the offline verifier rejects)
        orig = seed_data.seed_signers

        def seed_signers(path: Any, *, store: Any, **kw: Any) -> int:
            doc = json.loads(Path(path).read_text())
            for row in doc.get("signers") or []:
                if row.get("role") == "clerk" and row.get("device") == "EMULATOR" and not row.get("active", True):
                    row["active"] = True
                    print("fallback clerk active:", row["address"])
            tmp = KEYS.parent / "enrollment.fallback.json"
            tmp.write_text(json.dumps(doc))
            return orig(tmp, store=store, **kw)

        seed_data.seed_signers = seed_signers
    try:
        print("seed_data:", seed_data.seed(settings=s, store=st))
    finally:
        if fallback_clerk:
            seed_data.seed_signers = orig
    clerk, treasury = Account.from_key(keys["clerk"]), Account.from_key(keys["treasury"])
    if not stage:  # stage: only the enrollment.json devices may appear as approvers in the sealed bundle
        enroll_software_keys(st, s, clerk, treasury)
    return clerk, treasury


def enroll_software_keys(st: Any, s: Any, clerk: Any, treasury: Any) -> None:
    """Honest enrol leaf for plain software keys: device EMULATOR (accepted by the demo profile only), no device
    model / firmware / attestation, labelled as software keys in the signed log."""
    from executor.store import signers

    for acct, role in ((clerk, "clerk"), (treasury, "treasury")):
        signers.enroll(st, {"address": acct.address, "role": role, "device": "EMULATOR",
                            "label": f"{role} (SOFTWARE key, aws e2e; no device)", "device_model": None,
                            "firmware_version": None, "derivation_path": None, "enroll_sig": "",
                            "enrolled_at": "2026-10-19T12:00:00Z"}, settings=s)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--seed", action="store_true")
    a = ap.parse_args()
    require_team_account()
    from executor import e2e

    clerk, treasury = seed() if a.seed else (lambda k: (Account.from_key(k["clerk"]), Account.from_key(k["treasury"])))(
        json.loads(KEYS.read_text()))
    call = signed_call(a.url.rstrip("/"))
    print(json.dumps(call("GET", "/health", None, "host")[1], indent=1))
    out = e2e.run(call, clerk, treasury, now=datetime.now(timezone.utc))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
