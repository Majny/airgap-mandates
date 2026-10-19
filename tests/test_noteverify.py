"""Checkpoints verified by code we did not write: stock golang.org/x/mod/sumdb/note (tools/noteverify) and Merkle
roots/proofs cross-checked against golang.org/x/mod/sumdb/tlog. CONTRACTS.md v2 §7.3. Owner: WS-B.
Skipped when Go is not installed; the first run downloads golang.org/x/mod (pinned in go.sum)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from executor.audit import checkpoint, log, merkle
from tests.ws_b_store import FakeStore, make_settings

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "noteverify"
FIXTURES = ROOT / "contracts" / "fixtures"

pytestmark = pytest.mark.skipif(shutil.which("go") is None, reason="go not on PATH")


def _build(out: Path, pkg: str) -> Path:
    env = {**os.environ, "GOFLAGS": "-mod=mod", "CGO_ENABLED": "0"}
    subprocess.run(["go", "build", "-o", str(out), pkg], cwd=TOOL, env=env, check=True, capture_output=True,
                   timeout=300)
    return out


@pytest.fixture(scope="session")
def bins(tmp_path_factory) -> dict[str, Path]:
    d = tmp_path_factory.mktemp("noteverify")
    return {"noteverify": _build(d / "noteverify", "."), "tlogcheck": _build(d / "tlogcheck", "./tlogcheck")}


def _verify(bins, note: str, *vkeys: str) -> subprocess.CompletedProcess:
    return subprocess.run([str(bins["noteverify"]), "-", *vkeys], input=note.encode(), capture_output=True,
                          timeout=30)


@pytest.fixture
def logged(tmp_path):
    """A real cosigned checkpoint from the Python log path (FakeStore, in-process W1)."""
    store, settings = FakeStore(), make_settings(tmp_path)
    for i in range(5):
        log.append(log.make_event("checkpoint", {"n": i}, subject_id=None, actor="test"), store=store,
                   settings=settings, checkpoint=False)
    note = log.tick("audit", store=store, settings=settings)
    assert note is not None
    return note, checkpoint.vkeys(settings), settings


def test_stock_go_note_accepts_our_checkpoint(bins, logged):
    note, vk, _ = logged
    r = _verify(bins, note, vk["log"], vk["w1"])
    assert r.returncode == 0, r.stderr
    kid = vk["log"].split("+")[1]
    w1_kid = vk["w1"].split("+")[1]
    # 0x04 cosigner vkey is not a stock-note algorithm: reported UNCHECKED, verified by our Python verifier
    assert r.stdout.decode().splitlines() == [
        f"OK {checkpoint.origin('audit', logged[2])} {kid}",
        f"UNCHECKED {checkpoint.witness_name(logged[2])} {w1_kid} (stock sumdb/note cannot verify this signature type)"]
    assert set(checkpoint.verify_note(note, [vk["log"], vk["w1"]])["verified"]) == {
        checkpoint.origin("audit", logged[2]), checkpoint.witness_name(logged[2])}


def test_stock_go_note_rejects_flipped_body_byte(bins, logged):
    note, vk, _ = logged
    i = note.index("\n") + 1  # first byte of the tree size line
    bad = note[:i] + ("9" if note[i] != "9" else "8") + note[i + 1:]
    r = _verify(bins, bad, vk["log"])
    assert r.returncode != 0 and b"FAIL" in r.stderr


def test_stock_go_note_rejects_wrong_vkey(bins, logged, tmp_path):
    note, vk, settings = logged
    other = make_settings(tmp_path / "other")
    wrong = checkpoint.verifier_key(checkpoint.origin("audit", settings),
                                    checkpoint.kms.public_key(settings=other, key="log"))
    assert wrong != vk["log"]
    r = _verify(bins, note, wrong)
    assert r.returncode != 0 and b"FAIL" in r.stderr


def test_stock_go_note_accepts_contract_fixture(bins):
    note = json.loads((FIXTURES / "checkpoint_get" / "ok.json").read_text())["response"]
    vk = json.loads((FIXTURES / "receipts_get" / "ok.json").read_text())["response"]["vkeys"]
    r = _verify(bins, note, vk["log"], vk["w1"])
    assert r.returncode == 0, r.stderr
    assert r.stdout.decode().splitlines() == [  # fixture w1 vkey (0x04) matches the cosignature line's key id
        f"OK airgap.example/demo/audit {vk['log'].split('+')[1]}",
        "UNCHECKED airgap.example/demo/w1 7027bc92 (stock sumdb/note cannot verify this signature type)"]


def test_merkle_matches_go_tlog(bins):
    n = 17
    hashes = [merkle.leaf_hash(f"leaf {i}".encode()) for i in range(n)]
    r = subprocess.run([str(bins["tlogcheck"])], input="\n".join(h.hex() for h in hashes).encode(),
                       capture_output=True, timeout=60, check=True)
    go = json.loads(r.stdout)
    for size in range(1, n + 1):
        tree = hashes[:size]
        root = merkle.root(tree)
        assert root.hex() == go["roots"][str(size)], size
        for i in range(size):
            proof = merkle.inclusion_proof(i, tree)
            assert [p.hex() for p in proof] == go["inclusion"][f"{i}/{size}"], (i, size)
            assert merkle.verify_inclusion(i, size, tree[i], proof, root)
            if i:
                cproof = merkle.consistency_proof(i, tree)
                assert [p.hex() for p in cproof] == go["consistency"][f"{i}/{size}"], (i, size)
                assert merkle.verify_consistency(i, size, merkle.root(tree[:i]), root, cproof)


def test_bad_log_vkey_exits_2(bins, logged):
    note, vk, _ = logged
    bad = vk["log"][:-4] + "AAAA"
    r = _verify(bins, note, bad, vk["log"])
    assert r.returncode == 2 and b"bad vkey" in r.stderr
