"""Pre-sealed offline demo bundle (tools/demo_bundle.py) and the "Wi-Fi off" stage check (tools/offline_demo.sh).
Owner: WS-B."""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from executor.audit import checkpoint as cp
from executor.audit import receipt as rc
from tests.ws_b_store import make_settings
from tools import demo_bundle as db
from tools import verify_audit as va

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def made(tmp_path_factory):
    """(sealed, out_dir, key_dir): one real S1 run, sealed (refuses unless green)."""
    base = tmp_path_factory.mktemp("demo")
    key_dir, out = base / "keys", base / "out"
    sealed = db.build(key_dir=str(key_dir))
    assert sealed.ok, sealed.problems
    assert db.write(sealed, out, allow_red=False) == 0
    return sealed, out, key_dir


def test_files_written(made):
    sealed, out, _ = made
    for name in db.FILES:
        assert (out / name).is_file(), name
    assert (out / db.RED).exists() == bool(sealed.problems)
    bundle = json.loads((out / "bundle.json").read_text())
    assert bundle == sealed.bundle and (out / "bundle.json").read_text() == db._dump(bundle)
    assert (out / "checkpoint.txt").read_text() == sealed.checkpoint_note == bundle["checkpoints"][-1]
    assert sealed.summary["tx_ids"][-1] == json.loads((out / "receipt.json").read_text())["tx"]["tx_id"]


def test_trust_keys_public_only_and_no_secret_in_out_dir(made):
    sealed, out, key_dir = made
    keys = json.loads((out / "trust-keys.json").read_text())
    assert set(keys) == {"log", "w1"}
    for role, vk in keys.items():
        cp.parse_vkey(vk)
        assert vk == sealed.bundle["pubkeys"][role]
    seeds = [p.read_bytes() for p in key_dir.glob("*.ed25519")]
    assert len(seeds) == 2 and sorted(sealed.secrets) == sorted(seeds)
    for f in out.iterdir():
        raw = f.read_bytes()
        assert b"PRIVATE" not in raw, f
        for s in seeds:
            assert s not in raw and s.hex().encode() not in raw, f
            assert base64.b64encode(s).rstrip(b"=") not in raw, f


def test_write_refuses_to_leak_a_seed(made, tmp_path):
    sealed, _, _ = made
    bad = db.Sealed({**sealed.bundle, "x": sealed.secrets[0].hex()}, sealed.trust_keys, sealed.receipt,
                    sealed.checkpoint_note, sealed.summary, [], sealed.secrets)
    with pytest.raises(RuntimeError, match="local seed"):
        db.write(bad, tmp_path / "leak", allow_red=True)
    assert not (tmp_path / "leak").exists()


def test_bundle_green_with_replay_receipt_green(made):
    """Pinned keys, decide() replay, re-render + EIP-191 recovery: all green on the real S1 run."""
    sealed, out, _ = made
    bundle = json.loads((out / "bundle.json").read_text())
    keys = json.loads((out / "trust-keys.json").read_text())
    rep = va.verify(bundle, replay=True, trusted_vkeys=keys)
    assert rep.ok and rep.problems == [], rep.problems
    assert rep.checked.get("replayed", 0) >= 4 and rep.checked.get("signer_recovered", 0) >= 3, rep.checked
    assert not (out / db.RED).exists()
    c = rep.checked
    assert c["leaf_hashes"] == c["leaves"] == len(bundle["leaves"])
    assert c["checkpoint_quorum"] == c["checkpoints"] == len(bundle["checkpoints"]) and c["uncovered_leaves"] == 0
    assert c["executions"] == 4 and rep.pinned
    r = json.loads((out / "receipt.json").read_text())
    assert rc.receipt_problems(r, trusted_vkeys=keys) == [] and rc.bundle_problems(r, bundle) == []


def test_refuses_to_seal_when_red(made, tmp_path):
    from dataclasses import replace

    red = replace(made[0], problems=["seq 3: something wrong"])
    assert db.write(red, tmp_path / "x", allow_red=False) == 1 and not (tmp_path / "x").exists()
    assert db.write(red, tmp_path / "y", allow_red=True) == 0 and (tmp_path / "y" / db.RED).exists()


def test_tamper_flips_one_byte_and_names_the_seq(made):
    _, out, _ = made
    text = (out / "bundle.json").read_text()
    new, seq, old_amt, new_amt = db.tamper(text)
    assert len(new) == len(text) and sum(a != b for a, b in zip(text, new)) == 1
    assert old_amt != new_amt and len(old_amt) == len(new_amt)
    bundle, bad = json.loads(text), json.loads(new)
    assert bad["leaves"][seq]["event"]["type"] == "execution"
    assert str(bad["leaves"][seq]["event"]["data"]["amount_minor"]) == new_amt
    rep = va.verify(bad, replay=False, trusted_vkeys=json.loads((out / "trust-keys.json").read_text()))
    assert f"seq {seq}: leaf hash mismatch (event bytes differ from the recorded leaf_hash)" in rep.problems
    before = set(va.verify(bundle, replay=False).problems)
    assert all(f"seq {seq}" in p or "checkpoint" in p for p in set(rep.problems) - before), rep.problems


# --- tools/offline_demo.sh end to end ----------------------------------------------------------------------------

@pytest.fixture(scope="module")
def stage(made, tmp_path_factory):
    if shutil.which("go") is None:
        pytest.skip("go not on PATH")
    _, out, _ = made
    nv = tmp_path_factory.mktemp("nv") / "noteverify"
    b = subprocess.run(["go", "build", "-o", str(nv), "."], cwd=ROOT / "tools" / "noteverify", capture_output=True,
                       env={**os.environ, "CGO_ENABLED": "0", "GOPROXY": "off", "GOTOOLCHAIN": "local",
                            "GOFLAGS": "-mod=readonly"}, timeout=300)
    if b.returncode:
        pytest.skip(f"noteverify does not build offline (cold Go module cache?): {b.stderr.decode()[-300:]}")
    # stock macOS userland only (POSIX cmp etc.): the stage laptop has no Homebrew GNU tools on PATH
    env = {"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", "/tmp"), "PY": sys.executable,
           "NOTEVERIFY": str(nv)}
    return subprocess.run(["bash", str(ROOT / "tools" / "offline_demo.sh"), str(out)], env=env, capture_output=True,
                          text=True, timeout=300)


def test_offline_demo_all_steps(stage):
    out = stage.stdout
    assert "PASS  ########  1 checkpoint signed by the log" in out, out
    assert "PASS  ########  2 bundle verifies" in out, out
    assert "PASS  ########  3 receipt verifies" in out, out
    assert "bytes changed: 1" in out and "PASS  ########  4 tamper caught at seq " in out, out
    assert stage.returncode == 0 and "ALL PASS" in out, out
    assert [line for line in out.splitlines() if len(line) > 80] == [], "keep projector lines short"


def test_offline_demo_missing_noteverify_fails_clearly(made, tmp_path):
    _, out, _ = made
    env = {**os.environ, "PY": sys.executable, "NOTEVERIFY": str(tmp_path / "nope")}
    r = subprocess.run(["bash", str(ROOT / "tools" / "offline_demo.sh"), str(out)], env=env, capture_output=True,
                       text=True, timeout=300)
    assert r.returncode == 1 and "noteverify binary not found" in r.stdout
    assert "FAIL  !!!!!!!!  1 checkpoint (noteverify missing)" in r.stdout



# --- --from-aws path, exercised offline: the executor's read API served in-process stands in for API Gateway -----

@pytest.fixture(scope="module")
def api(tmp_path_factory):
    import urllib.parse

    from executor import handler

    ctx, s, summary = db.run_inprocess(key_dir=str(tmp_path_factory.mktemp("apikeys")))

    def get(path: str):
        u = urllib.parse.urlsplit(path)
        status, body = handler.dispatch("GET", u.path, dict(urllib.parse.parse_qsl(u.query)), None,
                                        principal="auditor", ctx=ctx)
        assert status == 200, (path, status, body)
        return body.decode("utf-8") if isinstance(body, bytes) else body

    return get, cp.vkeys(s), summary


def test_from_api_seals_green_with_independent_keys(api, tmp_path):
    get, trust, summary = api
    sealed = db.build_from_api(get, trust, source="in-process API")
    assert sealed.ok, sealed.problems
    assert sealed.summary["tx_ids"][-1] == summary["tx_ids"][-1] and sealed.checkpoint_note.startswith("airgap.")
    assert db.write(sealed, tmp_path / "out") == 0 and (tmp_path / "out" / "bundle.json").exists()


def test_from_api_refuses_when_pinned_keys_disagree(api, tmp_path):
    get, trust, _ = api
    other = cp.vkeys(make_settings(tmp_path))
    sealed = db.build_from_api(get, {**trust, "log": other["log"]}, source="in-process API")
    assert not sealed.ok
    assert any(p.startswith("/health log_vkey") for p in sealed.problems), sealed.problems
