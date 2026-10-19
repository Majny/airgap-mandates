"""Supervisor view (witness/supervisor.py): static HTML over verify_audit; per-signer columns, escaping, CLI.

Synthetic logs from tests/ws_b_store use replay=False (their decision leaves carry no data.inputs). Owner: WS-B."""
from __future__ import annotations

import copy
import json
import re

import pytest

from executor.audit import checkpoint as cp
from executor.audit import kms, log
from tests.ws_b_store import FakeStore, build_log, make_settings
from witness import supervisor as sv


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    settings = make_settings(tmp_path_factory.mktemp("sv"), checkpoint_every_n_leaves=5)
    store = FakeStore()
    build_log(store, settings)
    return settings, log.export("audit", store=store, settings=settings)


@pytest.fixture
def b(world):
    return copy.deepcopy(world[1])


def _row(page: str, i: int) -> str:
    m = re.search(rf'<tr id="cp-{i}">(.*?)</tr>', page, re.S)
    assert m, page
    return m.group(1)


def _cell(page: str, i: int, role: str) -> str:
    m = re.search(rf'<td class="(\w+) sig-{role}">(\w+)</td>', _row(page, i))
    assert m, _row(page, i)
    return m.group(2)


def _static_ok(page: str) -> None:
    low = page.lower()
    assert "<script" not in low and "http://" not in low and "https://" not in low
    assert page.isascii()
    assert page.startswith("<!DOCTYPE html>")


def test_green_page(b):
    page = sv.render_html(b, replay=False)
    _static_ok(page)
    assert 'class="banner verified"' in page and "VERIFIED" in page and "FAILED" not in page
    n = len(b["checkpoints"])
    assert n >= 5
    for i in range(n):
        assert _cell(page, i, "log") == "OK" and _cell(page, i, "w1") == "OK"
    assert "sig-w2" not in page  # no W2 key anywhere
    assert "keys taken from the bundle (not pinned)" in page
    assert "replay SKIPPED" in page
    assert "every leaf is covered" in page
    assert "<td>execution</td><td>2</td>" in page


def test_flipped_byte_is_red_with_seq(b):
    seq = next(le["seq"] for le in b["leaves"] if le["event"]["type"] == "execution")
    ev = b["leaves"][seq]["event"]
    ev["data"]["iban"] = ev["data"]["iban"][:-1] + ("8" if ev["data"]["iban"][-1] != "8" else "7")
    page = sv.render_html(b, replay=False)
    _static_ok(page)
    assert 'class="banner failed"' in page and "VERIFIED" not in page
    assert f'<span class="seq">seq {seq}</span>' in page


def test_missing_w1_line_attributed(b):
    i = 2
    note = b["checkpoints"][i]
    b["checkpoints"][i] = "".join(ln for ln in note.splitlines(keepends=True) if "/w1 " not in ln)
    page = sv.render_html(b, replay=False)
    assert _cell(page, i, "w1") == "missing" and _cell(page, i, "log") == "OK"
    assert _cell(page, i + 1, "w1") == "OK"
    assert 'class="banner failed"' in page  # quorum log AND (w1|w2) not met


def test_bad_w1_signature_attributed(b):
    i = 1
    lines = b["checkpoints"][i].splitlines(keepends=True)
    j = next(k for k, ln in enumerate(lines) if "/w1 " in ln)
    dash, name, sig = lines[j].rstrip("\n").split(" ")
    raw = bytearray(cp._unb64(sig))
    raw[-1] ^= 1
    lines[j] = f"{dash} {name} {cp._b64(bytes(raw))}\n"
    b["checkpoints"][i] = "".join(lines)
    page = sv.render_html(b, replay=False)
    assert _cell(page, i, "w1") == "BAD" and _cell(page, i, "log") == "OK"


def test_w2_cosignature_column(b, world, tmp_path):
    settings = world[0]
    w2 = make_settings(tmp_path / "w2", log_origin="supervisor.example")
    name = cp.witness_name(w2, "w2")
    w2_vkey = cp.verifier_key(name, kms.public_key(settings=w2, key="w1"), cp.SIG_COSIGNATURE)
    i = len(b["checkpoints"]) - 1
    body = cp.parse_note(b["checkpoints"][i])["body"]
    b["checkpoints"][i] += cp.cosign(body, name=name, settings=w2, key="w1", timestamp=1_790_000_000)
    trusted = {**cp.vkeys(settings), "w2": w2_vkey}
    page = sv.render_html(b, trusted, replay=False)
    _static_ok(page)
    assert "VERIFIED" in page, page
    assert "independent supervisor witness (simulated operator)" in page
    assert _cell(page, i, "w2") == "OK" and _cell(page, 0, "w2") == "missing"
    assert "keys pinned" in page and "not pinned" not in page


def test_escaping(b):
    evil = "<script>alert(1)</script>"
    b["leaves"][-1]["event"]["type"] = evil
    b["log_id"] = evil
    page = sv.render_html(b, replay=False, title=evil)
    _static_ok(page)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert 'class="banner failed"' in page  # the edit breaks the leaf hash


def test_no_host_banner_and_stable_verdict_id(b):
    """The host UI adds its own banner (WS-F); the verdict element is addressable for UI tests."""
    page = sv.render_html(b, replay=False)
    assert "Rendered by the host" not in page and 'id="verdict" data-ok="true"' in page
    assert "all performed checks passed" in page and "skipped check(s)" in page  # replay off is a SKIPPED note


def test_malformed_inputs_give_a_red_page_not_a_traceback(b):
    bad = copy.deepcopy(b)
    bad["checkpoints"][0] = bad["checkpoints"][0].replace("=\n", "\u00e9=\n", 1)  # non-ASCII inside base64
    page = sv.render_html(bad, replay=False)
    _static_ok(page)
    assert 'data-ok="false"' in page
    page = sv.render_html({**b, "leaves": 7}, replay=False)
    _static_ok(page)
    assert 'data-ok="false"' in page


def test_malformed_note_is_not_blamed_on_valid_signers(b):
    bad = copy.deepcopy(b)
    note = bad["checkpoints"][0]
    w1_line = next(x for x in note.splitlines() if "/w1 " in x)
    bad["checkpoints"][0] = note + w1_line + "\n"  # duplicate signature line: the note does not parse
    row = sv.render_html(bad, replay=False).split('id="cp-0"')[1].split("</tr>")[0]
    assert "malformed" in row and "BAD" not in row


def test_unpinned_w2_is_self_asserted_when_others_are_pinned(b, tmp_path):
    w2 = make_settings(tmp_path / "w2")
    name = "supervisor.example/w2"
    bb = copy.deepcopy(b)
    body = cp.parse_note(bb["checkpoints"][-1])["body"]
    bb["checkpoints"][-1] += cp.cosign(body, name=name, settings=w2)
    bb["pubkeys"]["w2"] = cp.verifier_key(name, kms.public_key(settings=w2, key="w1"), cp.SIG_COSIGNATURE)
    pinned = {"log": bb["pubkeys"]["log"], "w1": bb["pubkeys"]["w1"]}
    row = sv.render_html(bb, pinned, replay=False).split(f'id="cp-{len(bb["checkpoints"]) - 1}"')[1].split("</tr>")[0]
    assert 'class="neutral sig-w2">self-asserted' in row


def test_not_a_dict_is_red():
    page = sv.render_html([], replay=False)  # type: ignore[arg-type]
    _static_ok(page)
    assert "FAILED" in page


def test_cli_writes_file(b, world, tmp_path):
    src, out, keys = tmp_path / "bundle.json", tmp_path / "view.html", tmp_path / "keys.json"
    src.write_text(json.dumps(b))
    keys.write_text(json.dumps(cp.vkeys(world[0])))
    assert sv.main([str(src), "--trust-keys", str(keys), "--no-replay", "-o", str(out)]) == 0
    page = out.read_text(encoding="ascii")
    _static_ok(page)
    assert "VERIFIED" in page and "keys pinned" in page
    # with replay on the synthetic log is red, but the viewer still exits 0
    assert sv.main([str(src), "-o", str(out)]) == 0
    assert "FAILED" in out.read_text(encoding="ascii")
    assert sv.main([str(tmp_path / "nope.json")]) == 2
