"""Offline verifier (tools/verify_audit.py, CONTRACTS.md v2 §7.5): a real log verifies; every mutation is caught and
named. Uses tests/ws_b_store.FakeStore (WS-A's MemoryStore stand-in) and the inproc W1 witness. Owner: WS-B."""
from __future__ import annotations

import copy
import json

import pytest

from executor.audit import checkpoint as cp
from executor.audit import log
from executor.config import Settings
from tests.ws_b_store import CLERK, FakeStore, build_log, demo_events, make_settings
from tools import verify_audit as va


def _export(tmp_path, events=None, **kw):
    settings = make_settings(tmp_path, checkpoint_every_n_leaves=5, **kw)
    store = FakeStore()
    build_log(store, settings, events)
    return log.export("audit", store=store, settings=settings)


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    return _export(tmp_path_factory.mktemp("va"))


@pytest.fixture
def b(bundle):
    return copy.deepcopy(bundle)


def _fails(b, *needles, **kw):
    rep = va.verify(b, **kw)
    assert not rep.ok
    text = "\n".join(rep.problems)
    for n in needles:
        assert n in text, text
    return rep


def _seq_of(b, type_):
    return next(le["seq"] for le in b["leaves"] if le["event"]["type"] == type_)


def test_real_log_verifies(b):
    rep = va.verify(b)
    assert rep.ok, rep.problems
    c = rep.checked
    assert c["leaf_hashes"] == c["leaves"] == len(b["leaves"])
    assert c["checkpoints"] >= 5 and c["checkpoint_roots"] == c["checkpoint_quorum"] == c["checkpoints"]
    assert c["consistency"] == c["checkpoints"] - 1
    assert c["checkpoint_sig_w1"] == c["checkpoints"]
    assert c["covered_leaves"] == len(b["leaves"]) - 1  # only the last checkpoint's own leaf is not yet covered
    assert c["mandates_2of2"] == 1 and c["changes_cooled"] == 1 and c["executions"] == 2


def test_upstream_gaps_are_skipped_not_failed(b):
    rep = va.verify(b)
    if not va.decide_available():
        assert rep.checked["replay_unavailable"] == 2
        assert any("SKIPPED (not yet implemented upstream" in n for n in rep.notes)
    assert rep.checked["rerender_unavailable"] == 4  # signed text / params are not in the export (see report)


def test_edit_one_byte(b):
    seq = _seq_of(b, "execution")
    ev = b["leaves"][seq]["event"]
    ev["data"]["iban"] = ev["data"]["iban"][:-1] + ("8" if ev["data"]["iban"][-1] != "8" else "7")
    _fails(b, f"seq {seq}: leaf hash mismatch", f"(first bad leaf: seq {seq})")


def test_edit_with_recomputed_leaf_hash(b):
    seq = _seq_of(b, "decision")
    le = b["leaves"][seq]
    le["event"]["data"]["decision"] = "deny"
    le["leaf_hash"] = log.leaf_hash(le["event"])
    rep = _fails(b, "root mismatch")
    assert not any("leaf hash mismatch" in p for p in rep.problems)


def test_delete_leaf(b):
    seq = _seq_of(b, "decision")
    del b["leaves"][seq]
    _fails(b, f"seq {seq}: missing", "root mismatch")


def test_swap_two_leaves(b):
    lv = b["leaves"]
    lv[3], lv[9] = lv[9], lv[3]
    _fails(b, "seq 9: out of order (found at position 3)", "seq 3: out of order (found at position 9)")


def test_swap_two_events_keep_seq(b):
    lv = b["leaves"]
    lv[3]["event"], lv[9]["event"] = lv[9]["event"], lv[3]["event"]
    _fails(b, "seq 3: event carries seq 9", "seq 9: event carries seq 3", "seq 3: leaf hash mismatch")


def test_truncated_checkpoint(b):
    note = b["checkpoints"][2]
    b["checkpoints"][2] = note[:note.index("\n\n") + 1]  # body only, signatures cut off
    _fails(b, "checkpoint #2: malformed note")


def test_dropped_checkpoint(b):
    size = cp.parse_note(b["checkpoints"][2])["size"]
    del b["checkpoints"][2]
    _fails(b, f"checkpoint leaf for size {size} has no matching checkpoint")


def test_forged_log_signature(b):
    note = b["checkpoints"][1]
    body, sigs = note.split("\n\n", 1)
    first, rest = sigs.split("\n", 1)
    raw = cp._unb64(first.split(" ")[2])
    forged = raw[:10] + bytes([raw[10] ^ 1]) + raw[11:]
    b["checkpoints"][1] = f"{body}\n\n{cp.signature_line(first.split(' ')[1], forged)}{rest}"
    size = cp.parse_note(note)["size"]
    _fails(b, f"checkpoint size {size}: signature check failed")


def test_forged_root(b):
    """A checkpoint body with another root (signed by nobody) is rejected by the signature, not just the root."""
    note = b["checkpoints"][0]
    lines = note.split("\n")
    lines[2] = "A" * 43 + "="
    b["checkpoints"][0] = "\n".join(lines)
    _fails(b, "signature check failed")


def test_w1_cosignature_removed(b):
    w1 = cp.witness_name(Settings())
    b["checkpoints"] = ["".join(ln for ln in n.splitlines(keepends=True) if f" {w1} " not in ln)
                        for n in b["checkpoints"]]
    _fails(b, "signature quorum not met (valid: log; need log AND (w1 OR w2))")
    # with a log-only quorum the notes pass; only the checkpoint leaves still notice the stripped cosignature
    rep = va.verify(b, quorum=va.parse_quorum("log"))
    assert rep.problems and all("note_sha256 does not match" in p for p in rep.problems)


def test_wrong_pubkey(b, tmp_path):
    other = cp.vkeys(make_settings(tmp_path))
    b["pubkeys"]["log"] = other["log"]
    _fails(b, "signature quorum not met")


def test_policy_hash_removed(b):
    seq = _seq_of(b, "execution")
    le = b["leaves"][seq]
    le["event"]["policy_hash"] = None
    le["leaf_hash"] = log.leaf_hash(le["event"])
    _fails(b, f"seq {seq}: execution event lacks policy_hash")


def test_approver_mismatch(b):
    b["approvers"][0]["role"] = "treasury"
    _fails(b, f"approver {CLERK}: does not match an enroll leaf")


def test_mandate_2of2_same_signer(tmp_path):
    evs = demo_events()
    for ev in evs:
        if ev["type"] in ("mandate_signed", "signature") and ev["data"].get("signer_address") != CLERK \
                and ev["subject_id"] == "mnd_1":
            ev["data"]["signer_address"] = CLERK
            ev["data"]["role"] = "clerk"
    rep = _fails(_export(tmp_path, evs), "mandate mnd_1 signature 2/2 reuses signer")
    assert any("seq " in p for p in rep.problems)


def test_change_signed_before_cooling_off(tmp_path):
    evs = [ev for ev in demo_events()
           if not (ev["type"] == "state_transition" and ev["data"]["from"] == "COOLING")]
    for ev in evs:
        if ev["type"] == "state_transition" and ev["data"]["to"] == "SIG_TREASURY":
            ev["data"]["from"] = "COOLING"
    _fails(_export(tmp_path, evs), "change chg_1 signature accepted before cooling-off ended")


def test_cooling_off_left_early(tmp_path):
    evs = demo_events()
    for ev in evs:
        if ev["type"] == "state_transition" and ev["data"]["from"] == "COOLING":
            ev["ts"] = "2026-10-19T12:00:05.000Z"
    _fails(_export(tmp_path, evs), "left COOLING at 2026-10-19T12:00:05.000Z, before not_before")


def test_execution_after_deny(tmp_path):
    evs = demo_events()
    for ev in evs:
        if ev["type"] == "decision" and ev["subject_id"] == "prp_2":
            ev["data"]["decision"] = "deny"
    _fails(_export(tmp_path, evs), "execution of prp_2 after a deny decision")


def test_ledger_rows(b):
    ex = [le for le in b["leaves"] if le["event"]["type"] == "execution"]
    b["ledger"] = [{**le["event"]["data"], "seq": le["seq"]} for le in ex]
    assert va.verify(b).ok
    b["ledger"][0]["amount_minor"] += 1
    _fails(b, f"seq {ex[0]['seq']}: ledger row {ex[0]['event']['data']['tx_id']} does not match")
    b["ledger"] = b["ledger"][1:]
    _fails(b, f"seq {ex[0]['seq']}: execution {ex[0]['event']['data']['tx_id']} has no ledger row")


def test_cli_offline_demo(b, tmp_path, capsys):
    """Wi-Fi off demo: flip one byte in the exported file, the verifier goes red naming the leaf."""
    good = tmp_path / "bundle.json"
    good.write_text(json.dumps(b, ensure_ascii=False), encoding="utf-8")
    assert va.main([str(good)]) == 0
    assert "RESULT: OK" in capsys.readouterr().out
    text = good.read_text(encoding="utf-8")
    i = text.index('"FV-2"')
    bad = tmp_path / "bad.json"
    bad.write_text(text[:i + 4] + "3" + text[i + 5:], encoding="utf-8")
    seq = next(le["seq"] for le in b["leaves"] if le["event"]["data"].get("invoice", {}).get("invoice_no") == "FV-2")
    assert va.main([str(bad), "--no-replay"]) == 1
    out = capsys.readouterr().out
    assert "RESULT: FAIL" in out and f"seq {seq}: leaf hash mismatch" in out
    assert out.isascii()


def test_cli_unreadable_bundle(tmp_path, capsys):
    p = tmp_path / "x.json"
    p.write_text("{not json", encoding="utf-8")
    assert va.main([str(p)]) == 1
    assert "cannot read JSON" in capsys.readouterr().out


def test_parse_quorum():
    assert va.parse_quorum("log,w1|w2") == va.DEFAULT_QUORUM
    with pytest.raises(ValueError):
        va.parse_quorum("log,w3")
