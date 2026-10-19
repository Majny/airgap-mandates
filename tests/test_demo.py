"""Demo scene plumbing: WS-A's beats run unmodified through demo.aws_env.AwsEnv. Owner: WS-F.

The AWS transport is replaced by an in-process DemoEnv (memory backend); the real AWS run is `make demo-*`."""
from __future__ import annotations

from datetime import timedelta

import pytest

from demo.aws_env import AwsEnv
from executor import e2e, scenes
from executor.config import DemoNotReady


def _env() -> AwsEnv:
    inner = scenes.DemoEnv()

    def sleep(seconds: float) -> None:
        inner.at(inner.now + timedelta(seconds=seconds))

    env = AwsEnv(call=lambda m, p, b, who: inner.call(m, p, b, who), store=inner.store, settings=inner.settings,
                 keys={"clerk": inner.clerk.key.hex(), "treasury": inner.treasury.key.hex()},
                 sleep=sleep, clock=lambda: inner.now)
    return env


def test_scene_s2_through_aws_env():
    out = scenes.scene_s2(_env(), log=lambda s: None)
    assert out["money_to_attacker_minor"] == 0 and out["change"]["state"] == "REJECTED"


def test_scene_s3_through_aws_env():
    out = scenes.scene_s3(_env(), log=lambda s: None)
    assert out["takeover"]["state"] == "REJECTED" and out["legit"]["state"] == "ACTIVE"


def test_scene_s1_through_aws_env():
    env = _env()
    out = e2e.run(env.call, env.clerk, env.treasury, now=env.now, log=lambda s: None)
    assert out["tx_ids"]


def test_store_is_read_only():
    with pytest.raises(PermissionError):
        _env().store.put("ledger", {})


def test_scenes_refuse_local_backend(monkeypatch: pytest.MonkeyPatch):
    from demo import scene_s1, scene_s2
    from executor.config import Settings
    for mod in (scene_s1, scene_s2):
        with pytest.raises(DemoNotReady):
            mod.run(Settings(backend="memory"))
