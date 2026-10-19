"""Visual test of the operations console (`make ui-visual`): start Streamlit on the seeded in-process executor
(AIRGAP_EXECUTOR_URL=memory:), open it in headless Chromium, click every tab, check what a person must be able to
read there and save a screenshot per tab to .local/ui-visual/. Exit 1 on any missing text or page error.

Against AWS instead: `python -m tools.ui_visual --url <executor url>` (needs AWS credentials; text checks that
depend on the seeded scenes are skipped). Owner: orchestrator.
"""
from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent.parent
# tab -> texts that must be visible after the seeded scenes (executor.scenes: S1 normal day, S2 lookalike BEC with
# agent escalation, S3 mailbox takeover then a legitimate change)
CHECKS = {
    "Overview": ["Paid automatically", "Needs a human", "Account-change attack stopped", "Mailbox takeover stopped",
                 "Replay attack stopped", "Hijacked agent", "New account active", "Mandate signed on hardware"],
    "Payments": ["Paid · within mandate", "Paid · confirmed on Trezor", "Blocked", "Beta Servis", "imitates vendor domain"],
    "Payee changes": ["rejected", "active", "0 of 3 independent confirmations", "not us"],
    "Approvals": ["accepted", "refused: nonce_reused", "GENUINE"],
    "Mandate": ["Per payment", "80 000.00 CZK", "existing payees only"],
    "Audit": ["Latest signed checkpoint", "Verify the full audit log now"],
    "Reports": ["Attack benchmark"],
}
HEADER = ["AirGap Mandates", "Paid to registered suppliers", "Paid to unregistered accounts", "0.00 CZK",
          "Blocked attempts"]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_http(url: str, timeout: float = 60) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with urlopen(url, timeout=2):
                return
        except OSError:
            time.sleep(0.5)
    raise SystemExit(f"streamlit did not come up at {url}")


def run(url: str, out: Path, strict: bool) -> list[str]:
    from playwright.sync_api import sync_playwright

    port = _free_port()
    env = {**os.environ, "AIRGAP_EXECUTOR_URL": url, "AIRGAP_UI_REFRESH_S": "0", "PYTHONUNBUFFERED": "1"}
    srv = subprocess.Popen([sys.executable, "-m", "streamlit", "run", str(ROOT / "host" / "ui.py"),
                            "--server.headless", "true", "--server.port", str(port),
                            "--browser.gatherUsageStats", "false"],
                           cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    failures: list[str] = []
    out.mkdir(parents=True, exist_ok=True)
    try:
        _wait_http(f"http://127.0.0.1:{port}/_stcore/health")
        with sync_playwright() as p:
            page = p.chromium.launch().new_page(viewport={"width": 1600, "height": 1000})
            errors: list[str] = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(f"http://127.0.0.1:{port}/", wait_until="networkidle")
            page.get_by_text("Paid to registered suppliers").wait_for(timeout=120_000)
            for text in HEADER:
                if not page.get_by_text(text, exact=False).count():
                    failures.append(f"header: missing {text!r}")
            if page.locator("[data-testid='stException']").count():
                failures.append("header: Streamlit exception on the page")
            for i, (tab, texts) in enumerate(CHECKS.items()):
                page.get_by_role("tab", name=tab).click()
                page.wait_for_timeout(1200)
                panel = page.locator("[role='tabpanel']:visible").first
                if tab in ("Payments", "Payee changes"):  # open the fact expanders so the screenshot shows them
                    for exp in panel.get_by_text("Facts checked by the executor").all()[:3]:
                        exp.click()
                    page.wait_for_timeout(400)
                shot = out / f"{i + 1:02d}-{tab.lower().replace(' ', '-')}.png"
                page.screenshot(path=str(shot), full_page=True)
                content = panel.inner_text()
                for text in texts if strict else []:
                    if text not in content:
                        failures.append(f"{tab}: missing {text!r}")
                if panel.locator("[data-testid='stException']").count():
                    failures.append(f"{tab}: Streamlit exception")
                print(f"  {'OK  ' if not [f for f in failures if f.startswith(tab)] else 'FAIL'}  {tab:<14} {shot}")
            failures += [f"page error: {e}" for e in errors]
    finally:
        srv.terminate()
        srv.wait(timeout=10)
    return failures


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--url", default="memory:", help="executor URL (default: seeded in-process executor)")
    ap.add_argument("--out", default=str(ROOT / ".local" / "ui-visual"))
    a = ap.parse_args(argv)
    failures = run(a.url, Path(a.out), strict=a.url.startswith("memory:"))
    for f in failures:
        print(f"  FAIL  {f}")
    print("UI VISUAL: " + ("PASS" if not failures else f"{len(failures)} FAILURE(S)") + f"  (screenshots in {a.out})")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
