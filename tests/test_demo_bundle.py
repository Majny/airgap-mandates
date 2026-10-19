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
from tools import demo_bundle as db
from tools import verify_audit as va

ROOT = Path(__file__).resolve().parents[1]
GAPS = ("not enrolled before it", "accepted signature leaf carries no sig")
GAP_REASON = ("WS-A gaps: executor/handler.py logs accepted signature leaves with sig='' and seed.enroll_signer "
              "writes no 'enroll' leaf, so the real run cannot seal green; remove this marker when both land")


@pytest.fixture(scope="module")
def made(tmp_path_factory):
    """(sealed, out_dir, key_dir): one real S1 run written with --allow-red semantics."""
    base = tmp_path_factory.mktemp("demo")
    key_dir, out = base / "keys", base / "out"
    sealed = db.build(key_dir=str(key_dir))
    assert db.write(sealed, out, allow_red=True) == 0
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


def test_bundle_structurally_green_receipt_green(made):
    """Integrity (hashes, roots, quorum, coverage) is green; only the known WS-A gaps remain."""
    sealed, out, _ = made
    bundle = json.loads((out / "bundle.json").read_text())
    keys = json.loads((out / "trust-keys.json").read_text())
    rep = va.verify(bundle, replay=False, trusted_vkeys=keys)
    assert [p for p in rep.problems if not any(g in p for g in GAPS)] == []
    c = rep.checked
    assert c["leaf_hashes"] == c["leaves"] == len(bundle["leaves"])
    assert c["checkpoint_quorum"] == c["checkpoints"] == len(bundle["checkpoints"]) and c["uncovered_leaves"] == 0
    assert c["executions"] == 4 and rep.pinned
    r = json.loads((out / "receipt.json").read_text())
    assert rc.receipt_problems(r, trusted_vkeys=keys) == [] and rc.bundle_problems(r, bundle) == []


def test_refuses_to_seal_when_red(made, tmp_path):
    sealed, _, _ = made
    code = db.write(sealed, tmp_path / "x", allow_red=False)
    if sealed.problems:
        assert code == 1 and not (tmp_path / "x").exists()
    else:
        assert code == 0 and not (tmp_path / "x" / db.RED).exists()


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


@pytest.mark.xfail(strict=True, reason=GAP_REASON)
def test_bundle_seals_green(made):
    sealed, _, _ = made
    assert sealed.ok, sealed.problems


# --- tools/offline_demo.sh end to end ----------------------------------------------------------------------------

@pytest.fixture(scope="module")
def stage(made, tmp_path_factory):
    if shutil.which("go") is None:
        pytest.skip("go not on PATH")
    _, out, _ = made
    nv = tmp_path_factory.mktemp("nv") / "noteverify"
    subprocess.run(["go", "build", "-mod=readonly", "-o", str(nv), "."], cwd=ROOT / "tools" / "noteverify",
                   env={**os.environ, "CGO_ENABLED": "0"}, check=True, capture_output=True, timeout=300)
    env = {**os.environ, "PY": sys.executable, "NOTEVERIFY": str(nv)}
    return subprocess.run(["bash", str(ROOT / "tools" / "offline_demo.sh"), str(out)], env=env, capture_output=True,
                          text=True, timeout=300)


def test_offline_demo_steps_that_work_today(stage):
    out = stage.stdout
    assert "PASS  ########  1 checkpoint signed by the log" in out, out
    assert "PASS  ########  3 receipt verifies" in out, out
    assert "bytes changed: 1" in out and "PASS  ########  4 tamper caught at seq " in out, out
    assert [line for line in out.splitlines() if len(line) > 80] == [], "keep projector lines short"


def test_offline_demo_missing_noteverify_fails_clearly(made, tmp_path):
    _, out, _ = made
    env = {**os.environ, "PY": sys.executable, "NOTEVERIFY": str(tmp_path / "nope")}
    r = subprocess.run(["bash", str(ROOT / "tools" / "offline_demo.sh"), str(out)], env=env, capture_output=True,
                       text=True, timeout=300)
    assert r.returncode == 1 and "noteverify binary not found" in r.stdout
    assert "FAIL  !!!!!!!!  1 checkpoint (noteverify missing)" in r.stdout


@pytest.mark.xfail(strict=True, reason=GAP_REASON)
def test_offline_demo_all_green(stage):
    assert stage.returncode == 0, stage.stdout
    assert "ALL PASS" in stage.stdout
