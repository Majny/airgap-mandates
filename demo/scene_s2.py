"""Scene S2, ARCHITECTURE §14: WS-A's `executor.scenes.scene_s2` on the deployed stack (`executor.scenes.AwsEnv`,
SigV4 per principal, real clock). Needs a fresh state (AWS owner: `python -m infra.reset_state --yes`). Owner: WS-F."""
from __future__ import annotations

import json
from typing import Any, Callable

from executor.config import Settings, assert_demo_ready


def beat(env: Any, log: Callable[[str], None] = print, **kw: Any) -> dict:
    from executor import scenes

    return scenes.scene_s2(env, log, **kw)


def run(settings: Settings | None = None, *, url: str | None = None, log: Callable[[str], None] = print,
        **kw: Any) -> dict:
    settings = settings or Settings.from_env()
    assert_demo_ready(settings)
    from executor.scenes import AwsEnv

    return beat(AwsEnv(url or settings.executor_url), log, **kw)


if __name__ == "__main__":
    print(json.dumps(run(), indent=1))
