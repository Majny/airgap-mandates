"""MostlyRight loader + F-PSP / F-WARNLIST / F-SANCTION (CONTRACTS.md v2 §2.1). Owner: WS-D.

Unit tests run on the synthetic fixture tests/fixtures/mostlyright_sample.csv (fictitious names; one cp1250 record,
one UTF-8 record, one record split by a stray line break, one shifted fragment). The `real_*` tests run only when
the real snapshot data/mostlyright/snapshot.sqlite has been built (python -m tools.load_mostlyright load).
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from executor.facts import mostlyright as mr
from executor.facts.psp import psp_fact
from executor.facts.sanction import sanction_fact
from executor.facts.warnlist import warnlist_fact
from tools import load_mostlyright as loader

FIXTURE = Path(__file__).parent / "fixtures" / "mostlyright_sample.csv"
REAL = Path(__file__).resolve().parents[1] / "data" / "mostlyright" / "snapshot.sqlite"
REAL_BANK_CODES = REAL.parents[1] / "bank_codes.json"


def _iban(cc: str, bban: str) -> str:
    """Valid mod-97 IBAN for a synthetic BBAN."""
    num = "".join(str(int(c, 36)) for c in bban + cc + "00")
    return f"{cc}{98 - int(num) % 97:02d}{bban}"


@pytest.fixture(scope="module")
def snap(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("mr")
    src = out / "sample_2026-10-18.csv"  # dated name -> meta as_of
    shutil.copy(FIXTURE, src)
    loader.load(str(src), str(out))
    return out / "snapshot.sqlite"


@pytest.fixture(scope="module")
def bank_codes(tmp_path_factory: pytest.TempPathFactory) -> Path:
    p = tmp_path_factory.mktemp("bc") / "bank_codes.json"
    p.write_text(json.dumps({
        "CZ": {"9001": {"name": "Bank 9001 (CZ)", "bic": "TSTBCZPP", "kind": "bank"},
               "9002": {"name": "Bank 9002 (CZ)", "bic": "NOVPCZPP", "kind": "bank"},
               "9003": {"name": "Bank 9003 (CZ)", "bic": "PNDGCZPP", "kind": "bank"},
               "9004": {"name": "Bank 9004 (CZ)", "bic": "FUTRCZPP", "kind": "bank"},
               "9005": {"name": "Bank 9005 (CZ)", "bic": None, "national_id": "11223344", "kind": "bank"},
               "9006": {"name": "Bank 9006 (CZ)", "bic": "NONECZPP", "kind": "bank"},
               "9007": {"name": "Bank 9007 (CZ)", "bic": "LEFTCZPP", "kind": "bank"},
               "9008": {"name": "Bank 9008 (CZ)", "bic": "VLFTCZPP", "kind": "bank"},
               "9009": {"name": "Bank 9009 (CZ)", "bic": "SOONCZPP", "kind": "bank"},
               "9010": {"name": "Bank 9010 (CZ)", "bic": None, "national_id": "44556677", "kind": "bank"}},
        "LT": {"39990": {"name": "EMI Lithuania (fict.)", "bic": None, "kind": "emi"}},
    }))
    return p


def _rows(path: Path, sql: str) -> list[tuple]:
    with sqlite3.connect(path) as c:
        return c.execute(sql).fetchall()


# --- loader ---------------------------------------------------------------------------------------------------------

def test_loader_is_deterministic(tmp_path: Path, snap: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    sha_a = loader.load(str(FIXTURE), str(a))
    sha_b = loader.load(str(FIXTURE), str(b))
    assert sha_a == sha_b == hashlib.sha256((a / "snapshot.sqlite").read_bytes()).hexdigest()
    assert (a / "snapshot.sha256").read_text().split()[0] == sha_a
    assert mr.snapshot_sha(a / "snapshot.sqlite") == mr.sidecar_sha(a / "snapshot.sqlite") == sha_a
    meta = mr.meta(a / "snapshot.sqlite")
    assert meta["raw_csv_sha256"] == hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    assert meta["loader_version"] == loader.LOADER_VERSION
    assert not list(a.glob("*.tmp"))


def test_loader_decoding_repair_and_shifted_rows(snap: Path) -> None:
    rows = dict(_rows(snap, "SELECT record_id, name || '|' || src_encoding || '|' || record_ok || '|' || repaired "
                            "FROM records"))
    assert rows["e1" + "0" * 30] == "Šťastná Směnárna s.r.o.|cp1250|1|0"
    assert rows["d1" + "0" * 30] == "Žluťoučký Kůň s.r.o.|utf-8|1|0"
    assert rows["f1" + "0" * 30] == "Rozdel\neny Holding|ascii|1|1"
    assert rows["9f" + "0" * 30].endswith("|0|0")  # shifted fragment kept, not ok
    counts = json.loads(mr.meta(snap)["counts"])
    assert counts["rows_total"] == 20 and counts["rows_ok"] == 17 and counts["rows_repaired"] == 1
    assert counts["by_record_type"] == {"licence": 4, "payment_scheme": 7, "sanction": 3, "warning": 3}
    # truncated rows with a valid record_type are kept but never ok (see the ghost tests below)
    assert rows["b4" + "0" * 30] == "Ghost Warning Firm|ascii|0|0"
    assert rows["c3" + "0" * 30] == "Ghost Sanctioned Holding|ascii|0|0"
    assert mr.meta(snap)["as_of"] == "2026-10-18"
    doms = {d for (d,) in _rows(snap, "SELECT domain FROM domains")}
    assert {"fictiveinvest.test", "nepravda-capital.test", "gmail.com"} <= doms and "https" not in doms


def test_loader_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert loader.main(["load", "--src", str(FIXTURE), "--out", str(tmp_path)]) == 0
    sha = capsys.readouterr().out.strip()
    assert loader.main(["stats", "--out", str(tmp_path)]) == 0
    stats = json.loads(capsys.readouterr().out)
    assert stats["sha256"] == stats["sidecar_sha256"] == sha and stats["counts"]["rows_ok"] == 17


def test_loader_pins_sqlite_writer_version(tmp_path: Path) -> None:
    # the sqlite header records the library version of the last writer; it must not leak into the prov sha
    loader.load(str(FIXTURE), str(tmp_path))
    hdr = (tmp_path / "snapshot.sqlite").read_bytes()[:100]
    assert int.from_bytes(hdr[96:100], "big") == 3_000_000
    assert mr.meta(tmp_path / "snapshot.sqlite")["loader_version"] == loader.LOADER_VERSION


def test_loader_src_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(loader.ENV_SRC, str(FIXTURE))
    assert loader.resolve_src(None, tmp_path) == str(FIXTURE)
    assert loader.resolve_src("s3://bucket/x.csv", tmp_path) == "s3://bucket/x.csv"


def test_snapshot_opened_read_only(snap: Path) -> None:
    with pytest.raises(sqlite3.OperationalError):
        mr.connect(snap).execute("DELETE FROM meta")
    assert mr.connect(snap) is mr.connect(snap)


# --- normalisation ----------------------------------------------------------------------------------------------

def test_normalisation() -> None:
    assert mr.core_name("ACME s.r.o.") == "acme"
    assert mr.core_name("Beta Servis, a. s.") == "beta servis"
    assert mr.core_name("JSC Example Plant") == "example plant"
    assert mr.core_name("coinhouse.ltd") == "coinhouse ltd"  # a host name keeps its TLD
    assert mr.core_name("Komer\rní banka") == "komerni banka"  # control residue of a lost letter dropped
    assert mr.split_domains("a.test|https, WWW.B.Test/x") == ["a.test", "b.test"]
    assert mr.norm_national_id("00 001 350") == "1350"


# --- F-PSP ----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("code,line,sev", [
    ("9001", "PSP INST VOP OK", "INFO"),
    ("9002", "PSP NO VOP", "WARN"),  # SCT Inst only
    ("9003", "PSP NO VOP", "WARN"),  # VoP pending EDS registration
    ("9004", "PSP NO VOP", "WARN"),  # ready dates after the snapshot date
    ("9005", "PSP NO VOP", "WARN"),  # licence row via national_id, no scheme row
    ("9006", "PSP UNKNOWN", "WARN"),  # BIC not in the snapshot
    ("9007", "PSP NO VOP", "WARN"),  # left SCT Inst before the snapshot date
    ("9008", "PSP NO VOP", "WARN"),  # left VoP before the snapshot date
    ("9009", "PSP INST VOP OK", "INFO"),  # leaving date after the snapshot date: still in
    ("9010", "PSP NO VOP", "WARN"),  # licence row whose `until` has passed
])
def test_psp(snap: Path, bank_codes: Path, code: str, line: str, sev: str) -> None:
    f = psp_fact(_iban("CZ", code + "000000" + "1234567890"), mr_path=snap, bank_codes_path=bank_codes)
    assert (f["display_line"], f["severity"]) == (line, sev)
    assert f["prov"] == mr.snapshot_sha(snap)
    assert f["evidence"]["bank_code"] == code and f["evidence"]["country"] == "CZ"
    assert f["evidence"]["found"] is (line != "PSP UNKNOWN")
    if code in ("9005", "9010"):
        assert f["evidence"]["licensed"] is (code == "9005")


def test_psp_without_snapshot_date_dated_entries_do_not_count(tmp_path: Path, bank_codes: Path) -> None:
    # an undated source file -> meta as_of '' -> ready / leaving dates cannot be checked -> never INFO
    sha = loader.load(str(FIXTURE), str(tmp_path))
    assert mr.meta(tmp_path / "snapshot.sqlite")["as_of"] == ""
    f = psp_fact(_iban("CZ", "9001" + "000000" + "1234567890"), mr_path=tmp_path / "snapshot.sqlite",
                 bank_codes_path=bank_codes)
    assert (f["display_line"], f["severity"], f["prov"]) == ("PSP NO VOP", "WARN", sha)


def test_psp_lt_emi_unknown_and_missing_snapshot(snap: Path, bank_codes: Path, tmp_path: Path) -> None:
    f = psp_fact("LT483999000000001234", mr_path=snap, bank_codes_path=bank_codes)
    assert (f["display_line"], f["severity"]) == ("PSP UNKNOWN", "WARN")
    assert f["evidence"] == {**f["evidence"], "bank_code": "39990", "country": "LT", "found": False}
    g = psp_fact("LT483999000000001234", mr_path=tmp_path / "none.sqlite", bank_codes_path=bank_codes)
    assert (g["display_line"], g["severity"]) == ("PSP UNKNOWN", "WARN") and "prov" not in g


# --- F-WARNLIST -----------------------------------------------------------------------------------------------------

def test_warnlist_clear(snap: Path) -> None:
    f = warnlist_fact("Nepravda Trading s.r.o.", ["nepravda.test"], mr_path=snap)
    assert (f["display_line"], f["severity"], f["prov"]) == ("WARNLIST CLEAR", "INFO", mr.snapshot_sha(snap))


@pytest.mark.parametrize("name,domains,match", [
    ("Nepravda Capital s.r.o.", [], "name"),  # legal form ignored
    ("NEPRAVDA-CAPITAL", [], "name"),
    ("Some Vendor s.r.o.", ["fictiveinvest.test"], "domain"),
    ("Some Vendor s.r.o.", ["https://www.nepravda-capital.test/x"], "domain"),
    ("Some Vendor s.r.o.", ["mail.fictiveinvest.test"], "domain"),  # subdomain of a listed domain
])
def test_warnlist_hit(snap: Path, name: str, domains: list[str], match: str) -> None:
    f = warnlist_fact(name, domains, mr_path=snap)
    assert (f["display_line"], f["severity"]) == ("WARNLIST HIT", "BLOCK")
    assert f["evidence"]["hit"]["match"] == match


@pytest.mark.parametrize("name,domains", [
    ("Capital Nepravda Group", []),  # first token differs
    ("Some Vendor", ["gmail.com"]),  # shared mailbox provider never counts
    ("Ghost Warning Firm", []),  # only in truncated / shifted (record_ok = 0) rows
    ("Some Vendor", ["fictiveinvest.test.example"]),  # the listed domain is not a parent
])
def test_warnlist_no_false_positive(snap: Path, name: str, domains: list[str]) -> None:
    assert warnlist_fact(name, domains, mr_path=snap)["display_line"] == "WARNLIST CLEAR"


def test_warning_domain_hit_helper(snap: Path) -> None:
    hit = mr.warning_domain_hit("FictiveInvest.test", mr_path=snap)
    assert hit is not None and hit["domain"] == "fictiveinvest.test" and hit["kind"] == "website"
    assert mr.warning_domain_hit("acme.cz", mr_path=snap) is None
    assert mr.warning_domain_hit("", mr_path=snap) is None


# --- F-SANCTION -----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name,ico,match", [
    ("Fiktivni Zbrojovka Holding", "", "name"),
    ("Imaginary Arms Plant Co.", "", "name"),  # alias, legal form stripped
    ("Fiktivni Zbrojovka Holdings", "", "name"),  # near-exact
    ("Unrelated Name s.r.o.", "55667788", "national_id"),
    ("Rozdeleny Holding a.s.", "", "name"),  # record re-joined by the loader
])
def test_sanction_hit(snap: Path, name: str, ico: str, match: str) -> None:
    f = sanction_fact(name, ico, mr_path=snap)
    assert (f["display_line"], f["severity"], f["prov"]) == ("EU SANCTION HIT", "BLOCK", mr.snapshot_sha(snap))
    assert f["evidence"]["hit"]["match"] == match


def test_record_ok_zero_rows_are_indexed_but_never_match(snap: Path) -> None:
    # guards the ghost cases against passing vacuously: the names ARE in the index under a valid record_type
    got = _rows(snap, "SELECT r.record_type, r.record_ok FROM names n JOIN records r ON r.seq = n.seq "
                      "WHERE n.core IN ('ghost warning firm', 'ghost sanctioned holding') ORDER BY 1, 2")
    assert ("sanction", 0) in got and ("warning", 0) in got and all(ok == 0 for _, ok in got)
    assert sanction_fact("Ghost Sanctioned Holding", "", mr_path=snap)["display_line"] == "SANCTIONS CLEAR"
    assert warnlist_fact("Ghost Warning Firm", [], mr_path=snap)["display_line"] == "WARNLIST CLEAR"


@pytest.mark.parametrize("name", ["Orlo s.r.o.", "Fiktivni Zbrojovka", "Orel", "ACME s.r.o."])
def test_sanction_clear(snap: Path, name: str) -> None:
    # 'Orel' is listed but shorter than the 5-char floor; 'Fiktivni Zbrojovka' fails the length guard
    f = sanction_fact(name, "12345678", mr_path=snap)
    assert (f["display_line"], f["severity"]) == ("SANCTIONS CLEAR", "INFO")


def test_missing_snapshot_never_clear(tmp_path: Path) -> None:
    w = warnlist_fact("ACME s.r.o.", ["acme.cz"], mr_path=tmp_path / "none.sqlite")
    s = sanction_fact("ACME s.r.o.", "12345678", mr_path=None)
    assert (w["display_line"], w["severity"]) == ("WARNLIST N/A", "WARN") and "prov" not in w
    assert (s["display_line"], s["severity"]) == ("SANCTIONS N/A", "WARN") and "prov" not in s


# --- real snapshot (skipped unless built) ---------------------------------------------------------------------------

real = pytest.mark.skipif(not REAL.is_file(), reason="real MostlyRight snapshot not built")


@real
@pytest.mark.parametrize("name,ico,domain", [
    ("ACME s.r.o.", "12345678", "acme.cz"),
    ("Beta Servis a.s.", "87654321", "betaservis.cz"),
    ("Gamma Tisk s.r.o.", "99887762", "gammatisk.cz"),
])
def test_real_demo_vendors_clear(name: str, ico: str, domain: str) -> None:
    assert warnlist_fact(name, [domain], mr_path=REAL)["display_line"] == "WARNLIST CLEAR"
    assert sanction_fact(name, ico, mr_path=REAL)["display_line"] == "SANCTIONS CLEAR"


@real
@pytest.mark.parametrize("iban,line", [
    ("CZ7501000000001155443322", "PSP INST VOP OK"),  # 0100: SCT Inst + VoP ready
    ("CZ6508000000192000145399", "PSP NO VOP"),  # 0800: SCT Inst (ready date after the snapshot), not in VoP
    ("CZ6203000000000123456789", "PSP NO VOP"),  # 0300: not in the EPC register; licensed via national_id
    ("LT483999000000001234", "PSP UNKNOWN"),  # 39990: no BIC, absent
])
def test_real_psp(iban: str, line: str) -> None:
    assert psp_fact(iban, mr_path=REAL, bank_codes_path=REAL_BANK_CODES)["display_line"] == line


@real
def test_real_true_positives() -> None:
    firm = _rows(REAL, "SELECT name FROM records WHERE record_ok = 1 AND record_type = 'warning' "
                       "AND value_kind = 'firm' AND length(name) > 8 ORDER BY seq LIMIT 1")[0][0]
    site = _rows(REAL, "SELECT d.domain FROM domains d JOIN records r ON r.seq = d.seq WHERE r.record_ok = 1 "
                       "AND r.record_type = 'warning' AND d.kind = 'website' ORDER BY r.seq LIMIT 1")[0][0]
    sanctioned = _rows(REAL, "SELECT name FROM records WHERE record_ok = 1 AND record_type = 'sanction' "
                             "AND name GLOB '[A-Za-z]*' AND length(name) > 12 ORDER BY seq LIMIT 1")[0][0]
    assert warnlist_fact(firm, [], mr_path=REAL)["display_line"] == "WARNLIST HIT"
    assert warnlist_fact("Unrelated Vendor s.r.o.", [site], mr_path=REAL)["display_line"] == "WARNLIST HIT"
    assert sanction_fact(sanctioned, "", mr_path=REAL)["display_line"] == "EU SANCTION HIT"
    assert sanction_fact(sanctioned + " s.r.o.", "", mr_path=REAL)["display_line"] == "EU SANCTION HIT"


def test_ensure_builds_missing_snapshot_then_noop_then_refuses_mismatch(tmp_path):
    out = tmp_path / "mr"
    sha = loader.ensure(str(FIXTURE), str(out))
    side = (out / "snapshot.sha256").read_text().split()[0]
    assert sha == side == hashlib.sha256((out / "snapshot.sqlite").read_bytes()).hexdigest()
    mtime = (out / "snapshot.sqlite").stat().st_mtime_ns
    assert loader.ensure(str(FIXTURE), str(out)) == sha  # fresh: no rebuild
    assert (out / "snapshot.sqlite").stat().st_mtime_ns == mtime
    (out / "snapshot.sqlite").unlink()
    (out / "snapshot.sha256").write_text("0" * 64 + "  snapshot.sqlite\n")
    with pytest.raises(loader.SnapshotMismatch):
        loader.ensure(str(FIXTURE), str(out))
    assert (out / "snapshot.sha256").read_text().split()[0] == "0" * 64  # committed prov kept
