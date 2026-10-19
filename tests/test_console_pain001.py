"""Core-banking handoff from the console: per-payment pain.001 and the per-day zip (host/ui.py). Owner: WS-F."""
from __future__ import annotations

import io
import json
import zipfile
from typing import Any

import pytest

from host import ui


@pytest.fixture(scope="module")
def day() -> dict[str, Any]:
    from executor import e2e, scenes

    env = scenes.DemoEnv()
    e2e.run(env.call, env.clerk, env.treasury, now=env.now, log=lambda s: None)
    scenes.scene_s2(env, log=lambda s: None)
    txs = env.call("GET", "/ledger", None, "host")[1]["txs"]
    bundle = env.call("GET", "/audit/export?log_id=audit&from_seq=0", None, "auditor")[1]
    exports = {t["tx_id"]: env.call("GET", f"/export/pain001/{t['tx_id']}", None, "host")[1] for t in txs}
    return {"txs": txs, "bundle": bundle, "exports": exports}


def test_every_export_matches_its_audit_leaf(day: dict[str, Any]):
    logged = ui.rail_hashes(day["bundle"])
    assert day["txs"] and set(logged) >= {t["tx_id"] for t in day["txs"]}
    for t in day["txs"]:
        ok, why = ui.pain001_check(day["exports"][t["tx_id"]], logged[t["tx_id"]])
        assert ok, why
        assert ui.c14n_sha256(day["exports"][t["tx_id"]]["xml"]) == logged[t["tx_id"]][1]


def test_check_refuses_tampered_or_unlogged(day: dict[str, Any]):
    t = day["txs"][0]
    exp = dict(day["exports"][t["tx_id"]])
    logged = ui.rail_hashes(day["bundle"])[t["tx_id"]]
    assert ui.pain001_check(exp, None) == (False, "no rail_submitted entry in the audit log yet")
    assert not ui.pain001_check(exp, (logged[0], "0" * 64))[0]
    iban = exp["xml"].split("<IBAN>")[2].split("</IBAN>")[0]  # [1] = debtor, [2] = creditor
    tampered = {**exp, "xml": exp["xml"].replace(iban, "CZ5527000000001234567890")}
    ok, why = ui.pain001_check(tampered, logged)
    assert not ok and "does not match" in why  # recomputed hash != claimed hash
    tampered["xml_c14n_sha256"] = ui.c14n_sha256(tampered["xml"])  # a consistent forgery still differs from the log
    ok, why = ui.pain001_check(tampered, logged)
    assert not ok and "audit log" in why
    assert ui.pain001_check({**exp, "xml": "<not xml"}, logged)[0] is False


def test_day_zip_holds_exactly_the_logged_files(day: dict[str, Any]):
    d = ui.executed_on(day["txs"])[0]
    txs = [t for t in day["txs"] if t["executed_at"].startswith(d)]
    logged = ui.rail_hashes(day["bundle"])
    exports = dict(day["exports"])
    bad = txs[0]["tx_id"]
    exports[bad] = {**exports[bad], "xml_c14n_sha256": "0" * 64}  # one broken export must be left out, not shipped
    blob = ui.pain001_zip(d, txs, exports, logged)
    assert blob == ui.pain001_zip(d, txs, exports, logged)  # deterministic
    z = zipfile.ZipFile(io.BytesIO(blob))
    m = json.loads(z.read("manifest.json"))
    assert m["format"] == "pain.001.001.09" and m["date_utc"] == d
    assert [e["tx_id"] for e in m["excluded"]] == [bad]
    assert m["nb_of_txs"] == len(txs) - 1 == len(m["files"])
    assert m["ctrl_sum_minor"] == sum(t["amount_minor"] for t in txs if t["tx_id"] != bad)
    for f in m["files"]:
        xml = z.read(f["file"]).decode()
        assert xml == exports[f["tx_id"]]["xml"]
        assert ui.c14n_sha256(xml) == f["xml_c14n_sha256"] == logged[f["tx_id"]][1]
        assert f["audit_seq"] == logged[f["tx_id"]][0]
    assert "not merged" in z.read("README.txt").decode()


def test_payments_tab_offers_downloads(monkeypatch: pytest.MonkeyPatch):
    pytest.importorskip("streamlit")
    from pathlib import Path

    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("AIRGAP_EXECUTOR_URL", "memory:")
    monkeypatch.setenv("AIRGAP_UI_REFRESH_S", "0")
    at = AppTest.from_file(str(Path(ui.__file__).resolve()), default_timeout=60).run()
    assert not at.exception
    labels = [e.proto.label for e in at.get("download_button")]
    assert "pain.001 (ISO 20022)" in labels
    assert any(lab.startswith("Download ") and "pain.001 files (zip" in lab for lab in labels)
    assert any("hash matches the signed audit log" in c.value for c in at.caption)
