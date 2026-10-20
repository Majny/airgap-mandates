"""Visual end-to-end test of the attack demo (`make attack-visual`), no AWS. It starts a seeded local executor shared
over HTTP (tools.local_stack), the bank operations console (host/ui.py) and the attacker console (attacker/console.py),
then drives headless Chromium: click Launch on each attack in the attacker console, then open the bank console and
assert the Overview shows the corresponding blocked cards and that "Paid to unregistered accounts" stays 0.00 CZK.
Screenshots of both apps land in .local/attack-visual/. Exit 1 on any missing text or page error.

Mirrors tools/ui_visual.py (same subprocess + playwright helpers). Owner: WS-F.
"""
from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent.parent

# texts the bank console's Overview must show after the seeded scenes + the launched attacks
BANK_HEADER = ["AirGap Mandates", "Paid to registered suppliers", "Paid to unregistered accounts", "0.00 CZK"]
BANK_OVERVIEW = ["Account-change attack stopped", "Mailbox takeover stopped", "lookalike domain"]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_http(url: str, timeout: float = 90) -> None:
    end = time.time() + timeout
    last = ""
    while time.time() < end:
        try:
            with urlopen(url, timeout=2):
                return
        except OSError as e:
            last = str(e)
            time.sleep(0.5)
    raise SystemExit(f"service did not come up at {url}: {last}")


def _streamlit(app: str, port: int, env: dict) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", str(ROOT / app), "--server.headless", "true",
         "--server.port", str(port), "--browser.gatherUsageStats", "false"],
        cwd=ROOT, env={**os.environ, **env, "PYTHONUNBUFFERED": "1"},
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def run(out: Path) -> list[str]:
    from playwright.sync_api import sync_playwright

    ex_port, bank_port, atk_port = _free_port(), _free_port(), _free_port()
    ex_url = f"http://127.0.0.1:{ex_port}"
    failures: list[str] = []
    out.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(ROOT / ".local" / "implant", ignore_errors=True)  # start attack h from a clean implant state

    # attack h needs the test software clerk: the executor enrols it and the bank console signs with it (loopback only,
    # never AWS). Refresh off so the transient approval message is not cleared mid-interaction.
    soft = {"AIRGAP_TEST_SOFTWARE_CLERK": "1"}
    executor = subprocess.Popen([sys.executable, "-m", "tools.local_stack", "--port", str(ex_port)],
                                cwd=ROOT, env={**os.environ, **soft, "PYTHONUNBUFFERED": "1"},
                                stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    bank = _streamlit("host/ui.py", bank_port, {"AIRGAP_EXECUTOR_URL": ex_url, "AIRGAP_UI_REFRESH_S": "0", **soft})
    attacker = _streamlit("attacker/console.py", atk_port, {"AIRGAP_ATTACK_URL": ex_url})
    try:
        _wait_http(f"{ex_url}/health")
        _wait_http(f"http://127.0.0.1:{bank_port}/_stcore/health")
        _wait_http(f"http://127.0.0.1:{atk_port}/_stcore/health")
        with sync_playwright() as p:
            browser = p.chromium.launch()
            # 1. attacker console: launch every attack
            atk = browser.new_page(viewport={"width": 1500, "height": 1100})
            errors: list[str] = []
            atk.on("pageerror", lambda e: errors.append(str(e)))
            atk.goto(f"http://127.0.0.1:{atk_port}/", wait_until="networkidle")
            atk.get_by_text("ATTACKER WORKSTATION").wait_for(timeout=120_000)
            launch = atk.get_by_role("button", name="Launch")
            n = launch.count()
            if n < 7:
                failures.append(f"attacker console shows {n} Launch buttons, expected 7")
            for i in range(n):
                atk.get_by_role("button", name="Launch").nth(i).click()
                try:
                    atk.get_by_text("Money moved to attacker:").nth(i).wait_for(timeout=60_000)
                except Exception:  # noqa: BLE001
                    failures.append(f"attack #{i + 1}: no verdict rendered")
                atk.wait_for_timeout(300)
            body = atk.inner_text("body")
            for bad in ("ATTACK GOT THROUGH", "*** BREACH"):
                if bad in body:
                    failures.append(f"attacker console reports a breach: {bad!r}")
            # every verdict must read 0.00 CZK
            if body.count("Money moved to attacker: 0.00 CZK") < n:
                failures.append("not every attack verdict shows 0.00 CZK to the attacker")
            # attack h: arm the clerk-PC implant (the clerk approves on the bank console below)
            arm = atk.get_by_role("button", name="Arm implant")
            if arm.count():
                arm.first.click()
                try:
                    atk.get_by_text("implant armed").first.wait_for(timeout=30_000)
                except Exception:  # noqa: BLE001
                    failures.append("attack h: implant did not report armed")
            else:
                failures.append("attack h: no 'Arm implant' button on the attacker console")
            atk.screenshot(path=str(out / "01-attacker-console.png"), full_page=True)
            failures += [f"attacker page error: {e}" for e in errors]

            # 2. bank console: the attempts show up blocked and no attacker money
            bankpg = browser.new_page(viewport={"width": 1600, "height": 1100})
            berrors: list[str] = []
            bankpg.on("pageerror", lambda e: berrors.append(str(e)))
            bankpg.goto(f"http://127.0.0.1:{bank_port}/", wait_until="networkidle")
            bankpg.get_by_text("Paid to registered suppliers").wait_for(timeout=120_000)
            header = bankpg.inner_text("body")
            for text in BANK_HEADER:
                if text not in header:
                    failures.append(f"bank header: missing {text!r}")
            bankpg.get_by_role("tab", name="Overview").click()
            bankpg.wait_for_timeout(1500)
            panel = bankpg.locator("[role='tabpanel']:visible").first.inner_text()
            for text in BANK_OVERVIEW:
                if text not in panel:
                    failures.append(f"bank Overview: missing {text!r}")
            # the unregistered-accounts KPI must be 0.00 CZK
            if "Paid to unregistered accounts" in header and "0.00 CZK" not in header:
                failures.append("bank header: 'Paid to unregistered accounts' is not 0.00 CZK")
            if bankpg.locator("[data-testid='stException']").count():
                failures.append("bank console: Streamlit exception on the page")
            bankpg.screenshot(path=str(out / "02-bank-console.png"), full_page=True)

            # attack h: the clerk approves the waiting payment on the Trezor; the armed implant swaps the IBAN, so the
            # executor refuses it (render_mismatch). The bank screen must NOT reveal the implant; the Overview shows the
            # blocked card and no attacker money.
            bankpg.get_by_role("tab", name="Payments").click()
            bankpg.wait_for_timeout(1200)
            approve = bankpg.get_by_role("button", name="Approve on Trezor")
            if not approve.count():
                failures.append("attack h: no 'Approve on Trezor' button on the bank console (no pending payment?)")
            else:
                approve.first.click()
                try:
                    bankpg.get_by_text("Refused by the executor").first.wait_for(timeout=30_000)
                except Exception:  # noqa: BLE001 - the persistent Overview card is the real check below
                    pass
                bankpg.goto(f"http://127.0.0.1:{bank_port}/", wait_until="networkidle")
                bankpg.get_by_text("Paid to registered suppliers").wait_for(timeout=120_000)
                hdr2 = bankpg.inner_text("body")
                if "Paid to unregistered accounts" in hdr2 and "0.00 CZK" not in hdr2:
                    failures.append("attack h: 'Paid to unregistered accounts' is not 0.00 CZK after the swap")
                bankpg.get_by_role("tab", name="Overview").click()
                bankpg.wait_for_timeout(1500)
                panel2 = bankpg.locator("[role='tabpanel']:visible").first.inner_text()
                if "Tampered approval stopped" not in panel2:
                    failures.append("attack h: bank Overview missing 'Tampered approval stopped'")
                bankpg.screenshot(path=str(out / "03-bank-attack-h.png"), full_page=True)
                # attacker console: the outcome is refused, money to attacker 0.00 CZK
                atk.reload(wait_until="networkidle")
                atk.wait_for_timeout(2500)
                atkbody = atk.inner_text("body")
                if "Money to attacker: 0.00 CZK" not in atkbody:
                    failures.append("attack h: attacker console does not show 'Money to attacker: 0.00 CZK'")
                if "render_mismatch" not in atkbody and "refused" not in atkbody.lower():
                    failures.append("attack h: attacker console does not show the refused outcome")
                atk.screenshot(path=str(out / "04-attacker-h-outcome.png"), full_page=True)
            failures += [f"bank page error: {e}" for e in berrors]
    finally:
        for proc in (attacker, bank, executor):
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:  # noqa: BLE001
                proc.kill()
    return failures


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--out", default=str(ROOT / ".local" / "attack-visual"))
    a = ap.parse_args(argv)
    failures = run(Path(a.out))
    for f in failures:
        print(f"  FAIL  {f}")
    print("ATTACK VISUAL: " + ("PASS" if not failures else f"{len(failures)} FAILURE(S)") + f"  (screenshots in {a.out})")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
