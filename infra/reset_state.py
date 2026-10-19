"""Fresh demo state on AWS: empty the 7 airgap-* tables (incl. witness_state, so W1 accepts the new log) and re-seed
the registry + the two enrolled software signers (.local/aws_e2e_keys.json). Stack, keys, URLs stay. Owner: WS-E.

Usage: python -m infra.reset_state --yes   (Object Lock anchors in S3 are kept: they expire after 1 day)
"""
from __future__ import annotations

import argparse
import sys

import boto3

REGION = "eu-central-1"
TABLES = ["ledger", "mandates", "audit", "registry", "witness_state", "main", "portal"]


def empty(table: str) -> int:
    t = boto3.resource("dynamodb", region_name=REGION).Table(table)
    keys = [k["AttributeName"] for k in t.key_schema]
    n, kw = 0, {"ProjectionExpression": ", ".join(f"#k{i}" for i in range(len(keys))),
                "ExpressionAttributeNames": {f"#k{i}": k for i, k in enumerate(keys)}}
    while True:
        page = t.scan(**kw)
        with t.batch_writer() as bw:
            for item in page["Items"]:
                bw.delete_item(Key={k: item[k] for k in keys})
                n += 1
        if "LastEvaluatedKey" not in page:
            return n
        kw["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--yes", action="store_true")
    if not ap.parse_args().yes:
        sys.exit("refusing without --yes (deletes all demo data in the airgap-* tables)")
    sch = boto3.client("scheduler", region_name=REGION)
    tick = sch.get_schedule(Name="airgap-tick")

    def set_tick(state: str) -> None:  # pause the 1-min checkpoint tick so it cannot race the wipe
        sch.update_schedule(Name="airgap-tick", State=state, ScheduleExpression=tick["ScheduleExpression"],
                            FlexibleTimeWindow=tick["FlexibleTimeWindow"], Target=tick["Target"])

    set_tick("DISABLED")
    try:
        for name in TABLES:
            print(f"airgap-{name}: deleted {empty('airgap-' + name)} items")
        from infra.aws_e2e import seed

        clerk, treasury = seed()
        print("re-seeded registry; signers", clerk.address, treasury.address)
    finally:
        set_tick("ENABLED")
        print("tick re-enabled")


if __name__ == "__main__":
    main()
