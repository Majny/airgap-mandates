"""Scene S1 "normal day", ARCHITECTURE §14: invoices paid under the mandate, the over-cap one is a PAY step-up.

Software-key rehearsal of WS-A's beat `executor.e2e.run` on the deployed stack (`executor.scenes.AwsEnv`). On stage
the clerk signs on the physical Safe 3 instead: `python -m host.signer s1 --url $API` (docs/STAGE.md). Owner: WS-F.
"""
from __future__ import annotations

import json
from typing import Any, Callable

from executor.config import Settings, assert_demo_ready


def beat(env: Any, log: Callable[[str], None] = print) -> dict:
    from executor import e2e

    return e2e.run(env.call, env.clerk, env.treasury, now=env.now, log=log)


def run(settings: Settings | None = None, *, url: str | None = None, log: Callable[[str], None] = print) -> dict:
    settings = settings or Settings.from_env()
    assert_demo_ready(settings)
    from executor.scenes import AwsEnv

    return beat(AwsEnv(url or settings.executor_url), log)


if __name__ == "__main__":
    print(json.dumps(run(), indent=1))
