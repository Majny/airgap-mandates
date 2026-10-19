"""Demo scene wrappers (demo/scene_*.py) over WS-A's beats. Owner: WS-F.

The beats run here on WS-A's in-process DemoEnv; on stage the same wrappers use executor.scenes.AwsEnv(url)."""
from __future__ import annotations

import pytest

from demo import scene_s1, scene_s2, scene_s3
from executor.config import DemoNotReady, Settings
from executor.scenes import DemoEnv


def test_s1_beat():
    assert scene_s1.beat(DemoEnv(), log=lambda s: None)["tx_ids"]


def test_s2_beat():
    out = scene_s2.beat(DemoEnv(), log=lambda s: None)
    assert out["money_to_attacker_minor"] == 0 and out["change"]["state"] == "REJECTED"


def test_s3_beat():
    out = scene_s3.beat(DemoEnv(), log=lambda s: None)
    assert out["takeover"]["state"] == "REJECTED" and out["legit"]["state"] == "ACTIVE"


@pytest.mark.parametrize("mod", [scene_s1, scene_s2, scene_s3])
def test_scenes_refuse_local_backend(mod):
    with pytest.raises(DemoNotReady):
        mod.run(Settings(backend="memory"))
