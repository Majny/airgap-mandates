"""S3 Object Lock (GOVERNANCE, 1 day) copies of checkpoints and leaf batches + anchor leaf. CONTRACTS.md v2 §7.3.

Never COMPLIANCE: teardown deletes with s3:BypassGovernanceRetention. Owner: WS-B.
"""
from __future__ import annotations

import functools
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from executor.audit import checkpoint as cp
from executor.audit import log

RETENTION = timedelta(days=1)
LOCK_MODE = "GOVERNANCE"


@functools.lru_cache(maxsize=4)
def _s3_client(region: str) -> Any:
    import boto3

    return boto3.client("s3", region_name=region)


def s3_key(log_id: str, tree_size: int) -> str:
    return f"{log_id}/{tree_size:012d}.json"


def anchor(log_id: str, *, store: Any, settings: Any) -> dict[str, Any] | None:
    """Write <log_id>/<tree_size:012d>.json (latest checkpoint + the leaf hashes it covers) to AIRGAP_ANCHOR_BUCKET
    under Object Lock GOVERNANCE until now + 1 day, then append an `anchor` leaf. Returns the leaf data, or None if
    no checkpoint exists yet."""
    latest = cp.latest(log_id, store=store)
    if latest is None:
        return None
    size = int(latest["size"])
    rows = [r for r in log.leaves(log_id, store=store) if int(r["seq"]) < size]
    doc = {"log_id": log_id, "tree_size": size, "root_hash": latest["root_hash"], "note": latest["note"],
           "leaves": [{"seq": int(r["seq"]), "leaf_hash": r["leaf_hash"]} for r in rows]}
    key = s3_key(log_id, size)
    # Retention uses the wall clock, not AIRGAP_FAKE_NOW: S3 requires a future RetainUntilDate.
    _s3_client(settings.aws_region).put_object(
        Bucket=settings.anchor_bucket, Key=key, Body=json.dumps(doc, sort_keys=True).encode(),
        ContentType="application/json", ObjectLockMode=LOCK_MODE,
        ObjectLockRetainUntilDate=datetime.now(timezone.utc) + RETENTION)
    data = {"log_id": log_id, "tree_size": size, "root_hash": latest["root_hash"], "s3_key": key}
    log.append(log.make_event("anchor", data, subject_id=None, actor="checkpointer", log_id=log_id),
               store=store, settings=settings, checkpoint=False)
    return data
