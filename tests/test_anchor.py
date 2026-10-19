"""S3 Object Lock anchors (GOVERNANCE, 1 day) + anchor leaf, against moto. CONTRACTS.md v2 §7.3. Owner: WS-B."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from executor.audit import anchor, checkpoint, log, merkle
from tests.ws_b_store import FakeStore, make_settings

moto = pytest.importorskip("moto")
boto3 = pytest.importorskip("boto3")


def _event(i: int) -> dict:
    return log.make_event("witness_refusal", {"witness": "test", "status": 409, "old_size": i, "size": i},
                          subject_id=None, actor="witness")


@pytest.fixture
def s3(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing", "AWS_SESSION_TOKEN": "testing",
                 "AWS_DEFAULT_REGION": "eu-central-1"}.items():
        monkeypatch.setenv(k, v)
    anchor._s3_client.cache_clear()
    with moto.mock_aws():
        client = boto3.client("s3", region_name="eu-central-1")
        client.create_bucket(Bucket="airgap-log-test", ObjectLockEnabledForBucket=True,
                             CreateBucketConfiguration={"LocationConstraint": "eu-central-1"})
        yield client
    anchor._s3_client.cache_clear()


def test_anchor_object_lock_governance(tmp_path, s3):
    settings = make_settings(tmp_path, anchor_bucket="airgap-log-test")
    store = FakeStore()
    for i in range(3):
        log.append(_event(i), store=store, settings=settings)
    log.tick("audit", store=store, settings=settings)  # checkpoint leaves are appended too, so size > 3
    size = int(checkpoint.latest("audit", store=store)["size"])
    n_before = len(log.leaves("audit", store=store))
    data = anchor.anchor("audit", store=store, settings=settings)
    key = f"audit/{size:012d}.json"
    assert data["tree_size"] == size and data["s3_key"] == key

    obj = s3.get_object(Bucket="airgap-log-test", Key=data["s3_key"])
    doc = json.loads(obj["Body"].read())
    assert doc["tree_size"] == size and doc["root_hash"] == data["root_hash"]
    assert [x["seq"] for x in doc["leaves"]] == list(range(size))
    assert merkle.root([bytes.fromhex(x["leaf_hash"]) for x in doc["leaves"]]).hex() == doc["root_hash"]
    assert doc["note"].startswith(f"airgap.example/demo/audit\n{size}\n")
    head = s3.head_object(Bucket="airgap-log-test", Key=key)  # moto 5.2 GetObjectRetention 500s; HEAD carries both
    assert head["ObjectLockMode"] == "GOVERNANCE"
    until = head["ObjectLockRetainUntilDate"]
    now = datetime.now(timezone.utc)
    assert now + timedelta(hours=23) < until <= now + timedelta(days=1, minutes=5)

    rows = log.leaves("audit", store=store)
    last = json.loads(rows[-1]["event"])
    assert len(rows) == n_before + 1 and last["type"] == "anchor"
    assert last["data"] == {"log_id": "audit", "tree_size": size, "root_hash": data["root_hash"], "s3_key": key}


def test_anchor_without_checkpoint_is_noop(tmp_path, s3):
    settings = make_settings(tmp_path, anchor_bucket="airgap-log-test")
    store = FakeStore()
    assert anchor.anchor("audit", store=store, settings=settings) is None
    assert s3.list_objects_v2(Bucket="airgap-log-test").get("KeyCount", 0) == 0
    assert log.leaves("audit", store=store) == []
