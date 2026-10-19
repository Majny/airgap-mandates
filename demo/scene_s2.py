"""Scene S2, ARCHITECTURE §14: WS-A's `executor.scenes.scene_s2` run unmodified against the deployed AWS stack
(`demo.aws_env.AwsEnv`: SigV4 per principal, real clock, read-only operator checks). Owner: WS-F."""
from __future__ import annotations

import json
from typing import Any, Callable

from executor.config import Settings, assert_demo_ready


def run(settings: Settings | None = None, *, env: Any = None, log: Callable[[str], None] = print, **kw: Any) -> dict:
    settings = settings or Settings.from_env()
    assert_demo_ready(settings)
    from demo.aws_env import AwsEnv
    from executor import scenes

    return scenes.scene_s2(env or AwsEnv(settings=settings), log, **kw)


if __name__ == "__main__":
    print(json.dumps(run(), indent=1))
