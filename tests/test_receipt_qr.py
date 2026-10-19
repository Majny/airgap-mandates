"""Receipt QR transport (executor/audit/receipt.py qr_payload & co, CONTRACTS.md v2 §7.4). Owner: WS-B."""
from __future__ import annotations

import base64
import copy
import json
import xml.etree.ElementTree as ET
import zlib

import pytest

from executor.audit import log, receipt
from executor.canonical import canonical_json
from tests.ws_b_store import H, FakeStore, _ev, build_log, demo_events, make_settings
from tools import verify_audit as va

TX = f"tx_{1:016x}"


@pytest.fixture(scope="module")
def r(tmp_path_factory):
    settings = make_settings(tmp_path_factory.mktemp("qr"), checkpoint_every_n_leaves=5)
    store = FakeStore()
    build_log(store, settings, ledger=True)
    return receipt.receipt(TX, store=store, settings=settings)


def _receipt_in_tree(tmp_path, size: int) -> dict:
    """Receipt for an execution leaf in the middle of a `size`-leaf log (realistic proof length)."""
    settings = make_settings(tmp_path, checkpoint_every_n_leaves=10**9, checkpoint_max_seconds=10**9)
    store = FakeStore()
    ex = next(e for e in demo_events(1) if e["type"] == "execution")
    filler = [_ev("tool_call", {"session_id": "s1", "step": i, "tool": "list_vendors", "args_sha256": H,
                                "result": "ok", "rule_ids": [], "untrusted_read": False}, actor="agent")
              for i in range(size - 1)]
    for ev in filler[:size // 2] + [ex] + filler[size // 2:]:
        seq = log.append(ev, store=store, settings=settings, checkpoint=False)
        if ev is ex:
            store.put("ledger", {**{k: ev["data"][k] for k in receipt.TX_FIELDS}, "seq": seq,
                                 "executed_at": "2026-10-19T12:00:00Z", "rail": {"status": "ACTC"}})
    log.tick(store=store, settings=settings)
    return receipt.receipt(ex["data"]["tx_id"], store=store, settings=settings)


def _wrap(raw: bytes) -> str:
    return receipt.QR_PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def test_round_trip(r):
    p = receipt.qr_payload(r)
    assert p.startswith("AGR1:") and p.isascii() and "=" not in p
    back = receipt.parse_qr_payload(p)
    assert back == r
    assert receipt.verify_receipt(back), receipt.receipt_problems(back)
    assert receipt.parse_qr_payload(f"  {p}\n") == r  # scanner output with whitespace/newline
    assert len(p) < len(canonical_json(r))


def test_tampered_payload_byte(r):
    p = receipt.qr_payload(r)
    body = p[len(receipt.QR_PREFIX):]
    for i in (0, len(body) // 3, len(body) // 2, len(body) - 2):
        bad = receipt.QR_PREFIX + body[:i] + ("A" if body[i] != "A" else "B") + body[i + 1:]
        try:
            got = receipt.parse_qr_payload(bad)
        except ValueError:
            continue
        assert not receipt.verify_receipt(got)


def test_tampered_content_fails_verification(r):
    bad = copy.deepcopy(r)
    bad["entry"]["data"]["amount_minor"] += 1
    bad["tx"]["amount_minor"] += 1
    got = receipt.parse_qr_payload(receipt.qr_payload(bad))
    assert not receipt.verify_receipt(got)


@pytest.mark.parametrize("text", [
    "", "AGR1:", "AGR2:eJyrrgUAAXUA-Q", "agr1:eJyrrgUAAXUA-Q", '{"a":1}', "AGR1:eJyr rgUAAXUA-Q",
    "AGR1:eJyrrgUAAXUA+Q", "AGR1:eJyrrgUAAXUA-Q==", "AGR1:e", "AGR1:" + "A" * 20,
])
def test_rejects_malformed(text):
    with pytest.raises(ValueError):
        receipt.parse_qr_payload(text)


@pytest.mark.parametrize("raw", [
    zlib.compress(b"[1,2]"),                       # not an object
    zlib.compress(b'{"a":1.5}'),                   # float
    zlib.compress(b'{"a":NaN}'),                   # non-finite
    zlib.compress(b'{"b":1, "a":2}'),              # not canonical
    zlib.compress(b'{"a":1}') + b"x",              # trailing bytes
    zlib.compress(b'{"a":1}')[:-3],                # truncated stream
    zlib.compress(b'{"a":"\xff"}'),                # not UTF-8
    b"not zlib at all",
])
def test_rejects_bad_content(raw):
    with pytest.raises(ValueError):
        receipt.parse_qr_payload(_wrap(raw))


def test_rejects_zip_bomb():
    bomb = zlib.compress(b'{"a":"' + b"x" * (10 * 1024 * 1024) + b'"}', 9)
    assert len(_wrap(bomb)) < 30_000
    with pytest.raises(ValueError, match="more than"):
        receipt.parse_qr_payload(_wrap(bomb))
    ok = canonical_json({"a": "x" * (receipt.QR_MAX_JSON - 8)})
    assert len(ok) == receipt.QR_MAX_JSON and receipt.parse_qr_payload(_wrap(zlib.compress(ok)))


def test_png_and_svg(r):
    pytest.importorskip("segno")
    png = receipt.receipt_qr_png(r, scale=2, border=4)
    assert png.startswith(b"\x89PNG\r\n\x1a\n")
    svg = receipt.receipt_qr_svg(r)
    assert svg.isascii()
    assert ET.fromstring(svg.encode()).tag.endswith("svg")
    version, level = receipt.receipt_qr(r)
    assert 1 <= version <= 40 and level in {"L", "M", "Q", "H"}


def test_10000_leaf_receipt_fits(tmp_path):
    big = _receipt_in_tree(tmp_path, 10000)
    assert len(big["inclusion_proof"]) == 14
    assert receipt.verify_receipt(big), receipt.receipt_problems(big)
    p = receipt.qr_payload(big)
    assert receipt.parse_qr_payload(p) == big
    assert len(p) <= 2331  # byte capacity of a version 40 code at EC level M
    pytest.importorskip("segno")
    version, level = receipt.receipt_qr(big)
    assert version <= 40 and level in {"M", "Q", "H"}


def test_cli_agr1_text_file(r, tmp_path, capsys):
    good = tmp_path / "scan.txt"
    good.write_text(receipt.qr_payload(r) + "\n")
    assert va.main(["--receipt", str(good)]) == 0
    assert "RESULT: OK" in capsys.readouterr().out

    bad = copy.deepcopy(r)
    bad["tx"]["amount_minor"] += 1
    tampered = tmp_path / "tampered.txt"
    tampered.write_text(receipt.qr_payload(bad))
    assert va.main(["--receipt", str(tampered)]) == 1
    assert "does not match the logged execution" in capsys.readouterr().out

    body = receipt.qr_payload(r)
    garbled = tmp_path / "garbled.txt"
    garbled.write_text(body[:40] + "!" + body[41:])
    assert va.main(["--receipt", str(garbled)]) == 1
    out = capsys.readouterr().out
    assert "malformed receipt" in out and "RESULT: FAIL" in out and "Traceback" not in out


def test_cli_json_receipt_still_works(r, tmp_path, capsys):
    rp = tmp_path / "r.json"
    rp.write_text(json.dumps(r))
    assert va.main(["--receipt", str(rp)]) == 0
    assert "RESULT: OK" in capsys.readouterr().out


def test_missing_segno_is_a_clear_error(r, monkeypatch):
    monkeypatch.setitem(__import__("sys").modules, "segno", None)
    with pytest.raises(RuntimeError, match="pip install segno"):
        receipt.receipt_qr_png(r)
    assert receipt.parse_qr_payload(receipt.qr_payload(r)) == r  # payload needs no segno
