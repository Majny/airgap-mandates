"""Stage-laptop preflight: one green/red checklist before every demo run (`make preflight`). Owner: WS-C.

Checks, in stage order:
  device    physical Trezor Safe 3 on USB, GENUINE (fw vendor, bootloader locked), unlocked, auto-lock setting
  emulator  T3B1 emulator up for the treasury (udp:127.0.0.1:21324)
  mode      AIRGAP_TREZOR_PATH unset (physical clerk) or udp:... (FALLBACK: emulator clerk), printed loudly
  aws       operator credentials valid (sts), airgap-host assumable, GET /health 200 as host
  deploy    /health policy_hash == this checkout's policy_hash; code_sha256 == the deployed executor Lambda's;
            laptop HEAD == /health git_rev and the working tree is clean (the agent CLI reads local data/)
  data      data/mostlyright/snapshot.sqlite sha256 == committed snapshot.sha256 (else `make data`)
  offline   tools/noteverify built (.local/bin/noteverify), docs/audit/demo bundle present and verifying offline
  bedrock   planner + extractor model ids resolvable (control plane, no tokens); --deep: one 1-token call each

Read-only everywhere: no table writes, no resets, no signing. Exit 0 only if every required check is green.
Usage: python -m tools.preflight [--url API] [--deep] [--skip aws,bedrock,...]
"""
from __future__ import annotations

import argparse
import base64
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
REGION = "eu-central-1"
DEFAULT_URL = "https://ehhxkpbfcc.execute-api.eu-central-1.amazonaws.com/prod"
EMULATOR = "udp:127.0.0.1:21324"
GREEN, RED, AMBER, OFF = "\033[32m", "\033[31m", "\033[33m", "\033[0m"


class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str, bool]] = []  # (status, check, detail, required)

    def add(self, status: str, check: str, detail: str = "", required: bool = True) -> None:
        self.rows.append((status, check, detail, required))
        color = {"OK": GREEN, "FAIL": RED, "WARN": AMBER, "SKIP": AMBER}[status]
        print(f"  {color}{status:4}{OFF}  {check:28} {detail}", flush=True)

    @property
    def green(self) -> bool:
        return not any(s == "FAIL" and req for s, _, _, req in self.rows)


def _with_timeout(fn: Callable[[], Any], seconds: float) -> Any:
    out: dict[str, Any] = {}

    def run() -> None:
        try:
            out["v"] = fn()
        except BaseException as e:  # reported by the caller
            out["e"] = e

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        raise TimeoutError(f"no answer in {seconds:.0f}s")
    if "e" in out:
        raise out["e"]
    return out["v"]


def _features(path: str) -> Any:
    """Device features only: no session, so a locked device cannot block on a PIN prompt."""
    from trezorlib.client import get_default_client

    return get_default_client("airgap-preflight", path).features


# ------------------------------------------------------------------ checks


def check_device(r: Report) -> None:
    try:
        f = _with_timeout(lambda: _features("webusb"), 10)
    except Exception as e:
        r.add("FAIL", "Safe 3 on USB", f"{type(e).__name__}: {e} -> re-plug, close Trezor Suite, check the cable")
        return
    ver = f"{f.major_version}.{f.minor_version}.{f.patch_version}"
    genuine = f.fw_vendor != "EMULATOR" and bool(f.bootloader_locked)
    r.add("OK" if f.internal_model in ("T2B1", "T3B1") else "FAIL", "Safe 3 on USB", f"{f.model} {f.internal_model} fw {ver}")
    r.add("OK" if genuine else "FAIL", "device GENUINE", f"vendor {f.fw_vendor}, bootloader locked {f.bootloader_locked}"
          " (Optiga proof: docs/device/enroll_clerk_physical.json)")
    r.add("OK" if f.unlocked else "FAIL", "device unlocked", "" if f.unlocked else "enter the PIN on the device")
    mins = (f.auto_lock_delay_ms or 0) / 60000
    r.add("OK" if mins >= 60 else "WARN", "auto-lock delay", f"{mins:.0f} min" + (
        "" if mins >= 60 else " -> set to max on the device (Settings -> Auto-lock); unlock right before each beat"),
        required=False)


def check_emulator(r: Report) -> None:
    try:
        f = _with_timeout(lambda: _features(EMULATOR), 8)
    except Exception as e:
        r.add("FAIL", "treasury emulator", f"{type(e).__name__}: {e} -> tests/device/tenv.sh")
        return
    ok = f.fw_vendor == "EMULATOR" and f.internal_model == "T3B1"
    r.add("OK" if ok else "FAIL", "treasury emulator", f"{f.internal_model} {f.major_version}.{f.minor_version}."
          f"{f.patch_version} label {f.label!r}")


def check_mode(r: Report) -> None:
    p = os.environ.get("AIRGAP_TREZOR_PATH", "")
    if p.startswith("udp:"):
        r.add("WARN", "signing mode", f"{RED}FALLBACK: CLERK ON THE EMULATOR{OFF} (AIRGAP_TREZOR_PATH={p}); "
              "say it on stage", required=False)
    else:
        r.add("OK", "signing mode", "physical clerk over USB (AIRGAP_TREZOR_PATH unset)")


def check_aws(r: Report, url: str) -> dict | None:
    import boto3

    try:
        ident = _with_timeout(lambda: boto3.client("sts", region_name=REGION).get_caller_identity(), 15)
        r.add("OK", "AWS credentials", f"{ident['Arn'].split('/')[-2] if '/' in ident['Arn'] else ident['Arn']}"
              f" @ {ident['Account']}")
    except Exception as e:
        r.add("FAIL", "AWS credentials", f"{type(e).__name__} -> aws sso login --profile hackathon")
        return None
    try:
        from host.signer import executor_call

        st, health = _with_timeout(lambda: executor_call(url)("GET", "/health", None, "host"), 30)
    except Exception as e:
        r.add("FAIL", "GET /health as host", f"{type(e).__name__}: {e}")
        return None
    ok = st == 200 and health.get("status") == "ok" and health.get("backend") == "aws"
    r.add("OK" if ok else "FAIL", "GET /health as host", f"{st} backend={health.get('backend')} "
          f"deployment={health.get('deployment')} demo_profile={health.get('demo_profile')} "
          f"render={health.get('render_profile')}")
    return health if st == 200 else None


def check_git_rev(r: Report, health: dict) -> None:
    def git(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True).stdout.strip()

    head = git("rev-parse", "HEAD")
    dirty = [ln for ln in git("status", "--porcelain").splitlines() if ln.strip()]
    rev = health.get("git_rev")
    if not rev:
        r.add("WARN", "laptop rev == deployed", f"/health has no git_rev yet; HEAD {head[:12]}"
              + (f", {len(dirty)} uncommitted change(s)" if dirty else ""), required=False)
        return
    same = head.startswith(rev) or rev.startswith(head)
    r.add("OK" if same and not dirty else "FAIL", "laptop rev == deployed", f"HEAD {head[:12]} vs deployed {rev[:12]}"
          + ("" if same else f" -> git checkout {rev[:12]}")
          + (f"; working tree has {len(dirty)} uncommitted change(s) -> commit/stash them" if dirty else ""))


def check_deploy(r: Report, health: dict) -> None:
    import boto3

    from executor.policy.rules import policy_hash

    local = policy_hash()
    remote = health.get("policy_hash")
    r.add("OK" if remote == local else "FAIL", "policy_hash", f"deployed {str(remote)[:16]} vs checkout {local[:16]}"
          + ("" if remote == local else " -> redeploy or check out the deployed rev"))
    try:
        cfg = boto3.client("lambda", region_name=REGION).get_function_configuration(FunctionName="airgap-executor")
        want = base64.b64decode(cfg["CodeSha256"]).hex()
        got = health.get("code_sha256")
        r.add("OK" if got == want else "FAIL", "code_sha256", f"/health {str(got)[:16]} vs Lambda {want[:16]}")
    except Exception as e:
        r.add("WARN", "code_sha256", f"cannot read the Lambda config ({type(e).__name__})", required=False)


def check_data(r: Report) -> None:
    import hashlib

    d = ROOT / "data" / "mostlyright"
    db, pin = d / "snapshot.sqlite", d / "snapshot.sha256"
    if not pin.exists():
        r.add("FAIL", "MostlyRight snapshot", "data/mostlyright/snapshot.sha256 missing")
        return
    want = pin.read_text().split()[0]
    if not db.exists():
        r.add("FAIL", "MostlyRight snapshot", "snapshot.sqlite missing -> make data")
        return
    h = hashlib.sha256()
    with db.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    got = h.hexdigest()
    r.add("OK" if got == want else "FAIL", "MostlyRight snapshot", f"sha256 {got[:16]}" + (
        " == committed" if got == want else f" != committed {want[:16]} -> make data (stale after a rebase)"))


def check_offline(r: Report, run_verify: bool = True) -> None:
    nv = ROOT / ".local" / "bin" / "noteverify"
    r.add("OK" if nv.exists() else "FAIL", "noteverify built", str(nv.relative_to(ROOT)) if nv.exists()
          else "make offline-demo (needs Go, online once)")
    demo = ROOT / "docs" / "audit" / "demo"
    files = [demo / f for f in ("bundle.json", "trust-keys.json", "receipt.json", "checkpoint.txt")]
    if not all(f.exists() for f in files):
        r.add("FAIL", "demo bundle present", "make demo-bundle")
        return
    r.add("OK", "demo bundle present", "docs/audit/demo")
    if run_verify and nv.exists():
        p = subprocess.run(["bash", "tools/offline_demo.sh", "docs/audit/demo"], cwd=ROOT, capture_output=True,
                           text=True, timeout=180)
        tail = (p.stdout.strip().splitlines() or [""])[-1]
        r.add("OK" if p.returncode == 0 else "FAIL", "offline verify (Wi-Fi off)", tail[:90])


def check_bedrock(r: Report, deep: bool) -> None:
    import boto3

    from executor.config import Settings

    s = Settings.from_env()
    br = boto3.client("bedrock", region_name=REGION)
    for name, mid in (("planner (Sonnet)", s.bedrock_model_id), ("extractor (Qwen)", s.qwen_model)):
        try:
            if mid.startswith(("eu.", "us.", "apac.", "global.")):
                _with_timeout(lambda: br.get_inference_profile(inferenceProfileIdentifier=mid), 15)
            else:
                _with_timeout(lambda: br.get_foundation_model(modelIdentifier=mid), 15)
            detail = mid
            if deep:
                rt = boto3.client("bedrock-runtime", region_name=REGION)
                _with_timeout(lambda: rt.converse(modelId=mid, messages=[{"role": "user", "content": [{"text": "ok"}]}],
                                                  inferenceConfig={"maxTokens": 1}), 30)
                detail += " (1-token call OK)"
            r.add("OK", f"Bedrock {name}", detail)
        except Exception as e:
            r.add("FAIL", f"Bedrock {name}", f"{mid}: {type(e).__name__} {str(e)[:60]}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Stage preflight checklist (read-only).")
    ap.add_argument("--url", default=os.environ.get("AIRGAP_EXECUTOR_URL") if ".execute-api." in
                    os.environ.get("AIRGAP_EXECUTOR_URL", "") else DEFAULT_URL)
    ap.add_argument("--deep", action="store_true", help="also make one 1-token Bedrock call per model")
    ap.add_argument("--skip", default="", help="comma list: device,emulator,aws,deploy,data,offline,bedrock")
    a = ap.parse_args(argv)
    skip = {x.strip() for x in a.skip.split(",") if x.strip()}
    os.environ.setdefault("AWS_PROFILE", "hackathon")
    r = Report()
    print(f"AirGap Mandates preflight -> {a.url}")
    check_mode(r)
    for name, fn in (("device", lambda: check_device(r)), ("emulator", lambda: check_emulator(r))):
        if name in skip:
            r.add("SKIP", name, "", required=False)
        else:
            fn()
    health = None
    if "aws" in skip:
        r.add("SKIP", "aws", "", required=False)
    else:
        health = check_aws(r, a.url)
    if "deploy" in skip or health is None:
        r.add("SKIP", "deploy hashes", "" if "deploy" in skip else "no /health", required="deploy" in skip)
    else:
        check_deploy(r, health)
        check_git_rev(r, health)
    if "data" in skip:
        r.add("SKIP", "data", "", required=False)
    else:
        check_data(r)
    if "offline" in skip:
        r.add("SKIP", "offline", "", required=False)
    else:
        check_offline(r)
    if "bedrock" in skip:
        r.add("SKIP", "bedrock", "", required=False)
    else:
        check_bedrock(r, a.deep)
    print(f"\n{GREEN}PREFLIGHT GREEN{OFF}" if r.green else f"\n{RED}PREFLIGHT RED{OFF}: fix the FAIL rows (docs/STAGE.md)")
    return 0 if r.green else 1


if __name__ == "__main__":
    sys.exit(main())
