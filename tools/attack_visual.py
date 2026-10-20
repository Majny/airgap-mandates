"""Visual end-to-end test of the attack demo (`make attack-visual`), no AWS. It starts a seeded local executor shared
over HTTP (tools.local_stack), the supplier console (supplier/console.py), the bank operations console (host/ui.py)
and the attacker console (attacker/console.py), then drives headless Chromium: the supplier sends a new over-cap
invoice (it waits for the Trezor), click Launch on each attack in the attacker console, then open the bank console and
assert the Overview shows the corresponding blocked cards and that "Paid to unregistered accounts" stays 0.00 CZK;
attack h (malware on the clerk PC) is run on the supplier's waiting invoice. Then the Security tab must show one
incident card per attack kind and the Audit tab's event log ("Attacks only") the refused approvals; the attacker
console must show, under every attack, the bank's own log lines for it (threat, layer, evidence). Before any attack
the bank console must not say "Under attack" (the seeded scenes are backdrop). Screenshots of all three apps land in
.local/attack-visual/. Exit 1 on any missing text or page error.

Mirrors tools/ui_visual.py (same subprocess + playwright helpers). Owner: WS-F.
"""
from __future__ import annotations

import argparse
import os
import re
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
# the Security tab after every attack (incl. h): one card per attack, in the explainer's words
BANK_SECURITY = ["Under attack", "NEWEST", "ATTACK STOPPED", "PROMPT INJECTION", "DATA EXFILTRATION",
                 "PRIVILEGE ESCALATION", "FRAUD & TAMPERING", "MOVED TO ATTACKERS", "0.00 CZK", "HOST TAMPERING",
                 "Tampered approval stopped", "Stopped by", "hardware signature", "render_mismatch",
                 "Deterministic: no LLM in the decision path", "tools.verify_audit", "EARLIER",
                 "Stolen agent credentials?", "no audit entry", "REPLAY / FORGERY", "ACCOUNT TAKEOVER",
                 "Demo backdrop"]
# the attacker console: under each attack, the bank's own log lines for it (read back from the executor)
ATTACKER_BANKLOG = ["THE BANK'S LOG", "PAYMENT FRAUD (BEC)", "ACCOUNT TAKEOVER", "PROMPT INJECTION",
                    "PRIVILEGE ESCALATION", "DATA EXFILTRATION", "REPLAY / FORGERY", "stopped by",
                    "caller_not_allowed", "unknown_signer", "nonce_reused", "F-DOMAIN"]
SUPPLIER_NAME, SUPPLIER_AMOUNT = "Delta Stavby s.r.o.", "118750"  # over the 80,000 CZK cap -> waits for the Trezor


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

    ex_port, bank_port, atk_port, sup_port = _free_port(), _free_port(), _free_port(), _free_port()
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
    supplier = _streamlit("supplier/console.py", sup_port, {"AIRGAP_SUPPLIER_URL": ex_url})
    try:
        _wait_http(f"{ex_url}/health")
        _wait_http(f"http://127.0.0.1:{bank_port}/_stcore/health")
        _wait_http(f"http://127.0.0.1:{atk_port}/_stcore/health")
        _wait_http(f"http://127.0.0.1:{sup_port}/_stcore/health")
        with sync_playwright() as p:
            browser = p.chromium.launch()
            # 0. supplier console: a registered supplier sends a new over-cap invoice email; it waits for the Trezor
            sup_pid, sup_failures = _supplier_sends(browser, sup_port, out)
            failures += sup_failures
            # 0b. bank console before anyone attacked: the seeded scenes are backdrop, so no red banner (issue: a
            # stack that opens "Under attack" before the pitch starts)
            pre = browser.new_page(viewport={"width": 1600, "height": 1000})
            pre.goto(f"http://127.0.0.1:{bank_port}/", wait_until="networkidle")
            pre.get_by_text("Paid to registered suppliers").wait_for(timeout=120_000)
            pre.wait_for_timeout(1000)
            if "Under attack" in pre.inner_text("body"):
                failures.append("bank console shows 'Under attack' before any live attack (backdrop counted)")
            pre.get_by_role("tab", name="Security").click()
            pre.wait_for_timeout(1200)
            if "No live attacks" not in pre.inner_text("body"):
                failures.append("bank Security before the attacks: missing 'No live attacks'")
            pre.screenshot(path=str(out / "00b-bank-before-attacks.png"))
            pre.close()
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
            for t in ATTACKER_BANKLOG:
                if t not in body:
                    failures.append(f"attacker console bank log: missing {t!r}")
            logs = atk.locator(".banklog")
            for i in range(min(logs.count(), 7)):
                logs.nth(i).scroll_into_view_if_needed()
                logs.nth(i).screenshot(path=str(out / f"01{chr(97 + i)}-attacker-banklog.png"))
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
            if sup_pid:  # attack h on the supplier's invoice: it must be waiting on the bank console
                mine = bankpg.locator(f".st-key-approve-{sup_pid} button")
                if mine.count():
                    approve = mine
                    inv_no = _sup_inv_no(sup_pid)
                    if inv_no and not bankpg.get_by_text(f"invoice {inv_no}").count():
                        failures.append(f"bank Payments: supplier invoice {inv_no} not shown")
                    if inv_no and bankpg.get_by_text(f"invoice {inv_no}").count():
                        bankpg.get_by_text(f"invoice {inv_no}").first.scroll_into_view_if_needed()
                    bankpg.wait_for_timeout(500)
                    bankpg.screenshot(path=str(out / "02b-bank-supplier-invoice-waiting.png"))
                else:
                    failures.append(f"supplier invoice {sup_pid} is not waiting for Approve on Trezor on the bank "
                                    "console")
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
                failures += _bank_security(bankpg, out)
                # attacker console: the outcome is refused, money to attacker 0.00 CZK
                atk.reload(wait_until="networkidle")
                atk.wait_for_timeout(2500)
                atkbody = atk.inner_text("body")
                if "Money to attacker: 0.00 CZK" not in atkbody:
                    failures.append("attack h: attacker console does not show 'Money to attacker: 0.00 CZK'")
                if "render_mismatch" not in atkbody and "refused" not in atkbody.lower():
                    failures.append("attack h: attacker console does not show the refused outcome")
                atk.screenshot(path=str(out / "04-attacker-h-outcome.png"), full_page=True)
                hlog = atk.locator(".banklog")
                if hlog.count():
                    hlog.last.scroll_into_view_if_needed()
                    hlog.last.screenshot(path=str(out / "04b-attacker-h-banklog.png"))
                    if "HOST TAMPERING" not in hlog.last.inner_text():
                        failures.append("attack h: the attacker console's bank log does not show HOST TAMPERING")
                else:
                    failures.append("attack h: no bank log under the implant outcome")
            failures += [f"bank page error: {e}" for e in berrors]
    finally:
        for proc in (supplier, attacker, bank, executor):
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:  # noqa: BLE001
                proc.kill()
    return failures


def _tall_shot(page, path: Path, width: int = 1600) -> None:  # noqa: ANN001 - playwright Page
    """Streamlit scrolls inside its own container, so full_page stops at the viewport: grow the viewport to the
    content height (capped) for the screenshot, then restore it."""
    h = page.evaluate("Math.max(...[...document.querySelectorAll('section, [data-testid=stMain], "
                      "[data-testid=stAppViewContainer]')].map(e => e.scrollHeight), 1000)")
    page.set_viewport_size({"width": width, "height": min(int(h) + 200, 9000)})
    page.wait_for_timeout(800)
    page.screenshot(path=str(path))
    page.set_viewport_size({"width": width, "height": 1100})


def _bank_security(bankpg, out: Path) -> list[str]:  # noqa: ANN001 - playwright Page
    """Security tab (incident cards) and the Audit tab's event log filtered to attacks, with screenshots."""
    failures: list[str] = []
    bankpg.get_by_role("tab", name="Security").click()
    bankpg.wait_for_timeout(1500)
    panel = bankpg.locator("[role='tabpanel']:visible").first
    text = bankpg.inner_text("body")
    for t in BANK_SECURITY:
        if t not in text:
            failures.append(f"bank Security: missing {t!r}")
    bankpg.set_viewport_size({"width": 1600, "height": 1000})
    bankpg.wait_for_timeout(500)
    bankpg.screenshot(path=str(out / "05a-bank-security-fold.png"))  # what a projector shows without scrolling
    lines = panel.locator("details.incl > summary")
    if lines.count():
        lines.first.click()  # an older incident opens into its full card
        bankpg.wait_for_timeout(400)
    _tall_shot(bankpg, out / "05-bank-security.png")
    cards = panel.locator(".inc")
    if cards.count():
        cards.first.screenshot(path=str(out / "05b-bank-security-card.png"))
    bankpg.get_by_role("tab", name="Audit").click()
    bankpg.wait_for_timeout(1200)
    panel = bankpg.locator("[role='tabpanel']:visible").first
    try:
        panel.get_by_text("Attacks only").first.click()
        bankpg.wait_for_timeout(1500)
    except Exception:  # noqa: BLE001
        failures.append("bank Audit: no 'Attacks only' event-log filter")
    log = bankpg.locator("[role='tabpanel']:visible").first.inner_text()
    for t in ("Event log", "Tampered approval stopped", "Forged approval stopped", "ATTACK"):
        if t not in log:
            failures.append(f"bank Audit event log: missing {t!r}")
    _tall_shot(bankpg, out / "06-bank-event-log.png")
    return failures


_SUP_INV: dict[str, str] = {}


def _sup_inv_no(pid: str) -> str | None:
    return _SUP_INV.get(pid)


def _supplier_sends(browser, port: int, out: Path) -> tuple[str | None, list[str]]:
    """Supplier console: pick Delta, enter an over-cap amount, Send invoice; expect "Waiting for the clerk to approve
    on the Trezor" and return the bank's proposal_id shown in the sent list."""
    failures: list[str] = []
    pg = browser.new_page(viewport={"width": 1400, "height": 1000})
    errors: list[str] = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.goto(f"http://127.0.0.1:{port}/", wait_until="networkidle")
    pg.get_by_text("Supplier mail").first.wait_for(timeout=120_000)
    body = pg.inner_text("body")
    for text in ("LOCAL", "pays automatically under its mandate", "80 000.00 CZK"):
        if text not in body:
            failures.append(f"supplier console: missing {text!r}")
    pg.get_by_label("Supplier (registered with the bank)").click()
    pg.get_by_role("option", name=SUPPLIER_NAME).click()
    amount = pg.get_by_label("Amount (CZK)")
    amount.fill(SUPPLIER_AMOUNT)
    amount.press("Enter")
    pg.wait_for_timeout(800)
    inv_no = pg.get_by_label("Invoice number").input_value()
    pg.get_by_role("button", name="Send invoice").click()
    pid = None
    try:
        pg.get_by_text("Waiting for the clerk to approve on the Trezor").first.wait_for(timeout=60_000)
        pg.wait_for_timeout(800)
        m = re.search(r"prp_\d+", pg.inner_text("body"))
        pid = m.group(0) if m else None
        if not pid:
            failures.append("supplier console: no proposal id in the sent list")
        else:
            _SUP_INV[pid] = inv_no
    except Exception:  # noqa: BLE001
        failures.append("supplier console: the over-cap invoice is not waiting for the Trezor")
    if pg.locator("[data-testid='stException']").count():
        failures.append("supplier console: Streamlit exception on the page")
    pg.screenshot(path=str(out / "00-supplier-console.png"), full_page=True)
    failures += [f"supplier page error: {e}" for e in errors]
    return pid, failures


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
