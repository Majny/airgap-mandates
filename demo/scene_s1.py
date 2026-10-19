"""Scene S1 "normal day": 3 invoices paid under mandate, the 4th lights the Safe 5. ARCHITECTURE §14. Owner: WS-F."""
from __future__ import annotations

from executor.config import Settings, assert_demo_ready


def run(settings: Settings | None = None) -> None:
    settings = settings or Settings.from_env()
    assert_demo_ready(settings)
    raise NotImplementedError("TODO WS-F")
