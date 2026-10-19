"""Fresh demo state on AWS: empty the 7 airgap-* tables (incl. witness_state, so W1 accepts the new log) and re-seed
the registry + the two enrolled software signers (.local/aws_e2e_keys.json). Stack, keys, URLs stay. Owner: WS-E.

Usage: python -m infra.reset_state --yes   (Object Lock anchors in S3 are kept: they expire after 1 day)
"""
from __future__ import annotations

import argparse
import sys
import time

import boto3

REGION = "eu-central-1"
CHECKPOINTER_TIMEOUT_S = 60  # airgap-checkpointer Lambda timeout (infra/airgap_stack.py)
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


def activate_fallback_clerk(st, settings) -> None:
    """Re-enrol the inactive EMULATOR clerk(s) of data/enrollment.json as active: a new, logged enroll leaf."""
    import json
    from pathlib import Path

    from executor.store import signers

    rows = json.loads(Path("data/enrollment.json").read_text()).get("signers", [])
    for row in rows:
        if row.get("role") == "clerk" and row.get("device") == "EMULATOR" and not row.get("active", True):
            signers.enroll(st, {**{k: v for k, v in row.items() if k not in ("ceremony", "leaf")}, "active": True},
                           settings=settings)
            print("fallback clerk activated:", row["address"])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--yes", action="store_true")
    ap.add_argument("--fallback-clerk", action="store_true",
                    help="also activate the emulator clerk from data/enrollment.json (physical clerk stays active)")
    a = ap.parse_args()
    if not a.yes:
        sys.exit("refusing without --yes (deletes all demo data in the airgap-* tables)")
    from infra.aws_e2e import require_team_account

    require_team_account()
    sch = boto3.client("scheduler", region_name=REGION)
    tick = sch.get_schedule(Name="airgap-tick")

    def set_tick(state: str) -> None:  # pause the 1-min checkpoint tick so it cannot race the wipe
        sch.update_schedule(Name="airgap-tick", State=state, ScheduleExpression=tick["ScheduleExpression"],
                            FlexibleTimeWindow=tick["FlexibleTimeWindow"], Target=tick["Target"])

    lam = boto3.client("lambda", region_name=REGION)
    set_tick("DISABLED")
    # no checkpointer may run during the wipe: an invocation already in flight would write a checkpoint over the
    # OLD leaves after the wipe, and the new (shorter) log would then never be checkpointed again
    lam.put_function_concurrency(FunctionName="airgap-checkpointer", ReservedConcurrentExecutions=0)
    time.sleep(CHECKPOINTER_TIMEOUT_S + 5)
    try:
        for name in TABLES:
            print(f"airgap-{name}: deleted {empty('airgap-' + name)} items")
        from executor.store import get_store
        from infra.aws_e2e import aws_settings, seed

        clerk, treasury = seed()
        print("re-seeded registry; signers", clerk.address, treasury.address)
        st = get_store(aws_settings())
        if a.fallback_clerk:
            activate_fallback_clerk(st, aws_settings())
        size = int((st.get("audit", {"log_id": "head#audit", "seq": 0}) or {}).get("next_seq", 0))
        stale = [c for c in st.query("checkpoints", ("log_id", "audit")) if int(c.get("size", 0)) > size]
        if stale:
            raise SystemExit(f"stale checkpoints larger than the new log ({size}): {[c.get('size') for c in stale]}")
        print(f"log size {size}, no stale checkpoints")
    finally:
        lam.delete_function_concurrency(FunctionName="airgap-checkpointer")
        set_tick(tick.get("State", "ENABLED"))  # restore whatever it was before the reset
        print(f"checkpointer re-enabled, tick {tick.get('State', 'ENABLED')}")


if __name__ == "__main__":
    main()
