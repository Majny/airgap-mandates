"""Scene S5 offline audit, ARCHITECTURE §14: seal the export from AWS (read-only, auditor role), then Wi-Fi off:
upstream Go `noteverify`, `verify_audit` with replay, a one-byte tamper that fails at seq N. Uses WS-B's
`tools.demo_bundle` unmodified; this script only sequences the commands. Owner: WS-F."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from executor.config import Settings, assert_demo_ready

OUT = Path(".local/demo/s5")  # git-ignored


def steps(url: str, out: Path = OUT) -> list[list[str]]:
    py = sys.executable
    return [[py, "-m", "tools.demo_bundle", "--from-aws", url, "--out", str(out)],
            [py, "-m", "tools.demo_bundle", "--tamper", str(out / "bundle.json"), str(out / "bundle.tampered.json")]]


def run(settings: Settings | None = None, *, url: str | None = None) -> int:
    settings = settings or Settings.from_env()
    assert_demo_ready(settings)
    for cmd in steps(url or settings.executor_url):
        print("$", " ".join(cmd))
        rc = subprocess.call(cmd)
        if rc:
            return rc
    print(f"Wi-Fi off now, then WS-B's stage check: bash tools/offline_demo.sh {OUT} "
          f"(noteverify + verify_audit --replay green; {OUT}/bundle.tampered.json red at seq N)")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
