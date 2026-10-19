"""Scene S1 "normal day": invoices paid under mandate, the over-cap one lights the Safe 5. ARCHITECTURE §14.

Runs WS-A's beat `executor.e2e.run` against the deployed AWS stack (SigV4, real IAM roles). Owner: WS-F.
"""
from __future__ import annotations

from typing import Any, Callable

from executor.config import Settings, assert_demo_ready


def run(settings: Settings | None = None, *, env: Any = None, log: Callable[[str], None] = print) -> dict:
    settings = settings or Settings.from_env()
    assert_demo_ready(settings)
    from demo.aws_env import AwsEnv
    from executor import e2e

    env = env or AwsEnv(settings=settings)
    return e2e.run(env.call, env.clerk, env.treasury, now=env.now, log=log)


if __name__ == "__main__":
    print(run())
