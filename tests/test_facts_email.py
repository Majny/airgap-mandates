"""F-DKIM / F-DOMAIN / F-DOMAIN-AGE over the fictitious email fixtures (data/emails). Owner: WS-D."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from executor.facts.dkim import dkim_fact, dkim_verdict
from executor.facts.domain import domain_fact, is_lookalike
from executor.facts.domain_age import domain_age_fact

DATA = Path(__file__).resolve().parents[1] / "data"
EMAILS = DATA / "emails"
DNS = json.loads((DATA / "dns_snapshot.json").read_text())
DNS_SHA = hashlib.sha256((DATA / "dns_snapshot.json").read_bytes()).hexdigest()
MANIFEST = json.loads((EMAILS / "manifest.json").read_text())
REGISTRY_DOMAIN = {"ven_12345678": "acme.cz", "ven_87654321": "betaservis.cz", "ven_99887762": "gammatisk.cz"}
NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)


def _raw(name: str) -> bytes:
    return (EMAILS / name).read_bytes()


def _facts(name: str, registry_domain: str) -> tuple[dict, dict]:
    row = next(r for r in MANIFEST if r["file"] == name)
    verdict = dkim_verdict(_raw(name), dns_snapshot=DNS)
    return dkim_fact(verdict, prov=DNS_SHA), domain_fact(row["from_domain"], registry_domain)


def test_manifest_ids_match_raw_bytes():
    assert len(MANIFEST) == 8
    for row in MANIFEST:
        assert row["email_id"] == "eml_" + hashlib.sha256(_raw(row["file"])).hexdigest()[:16]


@pytest.mark.parametrize("name", ["01_acme_invoice_legit.eml", "02_beta_invoice_legit.eml",
                                  "03_gamma_invoice_legit.eml", "08_acme_change_legit.eml"])
def test_legit_emails_pass(name):
    row = next(r for r in MANIFEST if r["file"] == name)
    dk, dom = _facts(name, REGISTRY_DOMAIN[row["vendor_id"]])
    assert (dk["severity"], dk["display_line"], dk["prov"]) == ("INFO", "DKIM PASS", DNS_SHA)
    assert (dom["severity"], dom["display_line"]) == ("INFO", "DOMAIN MATCH")


def test_bec_lookalike_blocks_on_domain():
    dk, dom = _facts("04_bec_lookalike_acme-cz.eml", "acme.cz")
    assert dk["display_line"] == "DKIM PASS"  # d=acme-cz.com signs its own lookalike domain
    assert dk["evidence"]["d"] == "acme-cz.com"
    assert (dom["severity"], dom["display_line"]) == ("BLOCK", "DOMAIN LOOKALIKE")
    assert "prov" not in dom


def test_takeover_passes_email_facts():
    dk, dom = _facts("05_takeover_acme_real_domain.eml", "acme.cz")
    assert dk["display_line"] == "DKIM PASS" and dom["display_line"] == "DOMAIN MATCH"


def test_expected_facts_in_manifest():
    for row in MANIFEST:
        verdict = dkim_verdict(_raw(row["file"]), dns_snapshot=DNS)
        got = {"F-DKIM": dkim_fact(verdict, prov=DNS_SHA)["display_line"]}
        if row["vendor_id"]:
            got["F-DOMAIN"] = domain_fact(row["from_domain"], REGISTRY_DOMAIN[row["vendor_id"]])["display_line"]
        assert {k: got[k] for k in row["expected_facts"]} == row["expected_facts"], row["file"]


def test_tampered_body_fails():
    raw = _raw("01_acme_invoice_legit.eml").replace(b"CZ6508000000192000145399", b"LT483999000000001234", 1)
    verdict = dkim_verdict(raw, dns_snapshot=DNS)
    assert verdict["result"] == "fail"
    f = dkim_fact(verdict, prov=DNS_SHA)
    assert (f["severity"], f["display_line"]) == ("BLOCK", "DKIM FAIL")


def test_missing_dns_record_fails():
    verdict = dkim_verdict(_raw("01_acme_invoice_legit.eml"), dns_snapshot={})
    assert verdict["result"] == "fail" and verdict["aligned"] is False


def test_unsigned_is_none_and_blocks():
    verdict = dkim_verdict(_raw("07_exfil_injection.eml"), dns_snapshot=DNS)
    assert verdict == {"result": "none", "d": None, "s": None, "aligned": False}
    assert dkim_fact(verdict, prov=DNS_SHA)["severity"] == "BLOCK"


def test_unaligned_pass_blocks():
    f = dkim_fact({"result": "pass", "d": "mailer.example", "s": "x", "aligned": False}, prov=DNS_SHA)
    assert (f["severity"], f["display_line"]) == ("BLOCK", "DKIM FAIL")


@pytest.mark.parametrize("cand,expected", [
    ("acme-cz.com", True), ("acme.cz.com", True), ("acrne.cz", True), ("acme.co", True),
    ("xn--cme-5cd.cz", True),  # Cyrillic a + "cme"
    ("ácme.cz", True),
    ("acme.cz", False), ("ACME.CZ", False), ("mail.acme.cz", False), ("betaservis.cz", False),
    ("gammatisk.cz", False), ("example.com", False),
])
def test_is_lookalike_table(cand, expected):
    assert is_lookalike(cand, "acme.cz") is expected


def test_domain_fact_unknown_and_subdomain():
    assert domain_fact("example.com", "acme.cz")["display_line"] == "DOMAIN UNKNOWN"
    assert domain_fact("example.com", "acme.cz")["severity"] == "WARN"
    sub = domain_fact("mail.acme.cz", "acme.cz")
    assert sub["display_line"] == "DOMAIN MATCH" and sub["evidence"]["match"] == "subdomain"


@pytest.mark.parametrize("days,sev,line", [
    (0, "WARN", "DOMAIN AGE 0D"), (12, "WARN", "DOMAIN AGE 12D"), (29, "WARN", "DOMAIN AGE 29D"),
    (30, "INFO", "DOMAIN AGE 30D"), (364, "INFO", "DOMAIN AGE 364D"), (400, "INFO", "DOMAIN AGE 1Y"),
    (3 * 365 + 10, "INFO", "DOMAIN AGE 3Y"),
])
def test_domain_age_thresholds(days, sev, line):
    first_seen = (NOW - timedelta(days=days)).isoformat().replace("+00:00", "Z")
    f = domain_age_fact("acme.cz", first_seen, NOW)
    assert (f["severity"], f["display_line"]) == (sev, line)
    assert "prov" not in f and f["evidence"]["first_seen"] == first_seen


def test_domain_age_first_time():
    f = domain_age_fact("acme-cz.com", None, NOW)
    assert (f["severity"], f["display_line"]) == ("WARN", "DOMAIN AGE 0D")


# --- adversarial-review regressions ---------------------------------------------------------------------------------

def _resign(raw: bytes, *, length: bool) -> bytes:
    """Re-sign an unsigned copy of a fixture with the DEMO acme.cz key (optionally with an l= body length tag)."""
    import dkim

    body_start = raw.index(b"From: ")
    unsigned = raw[body_start:]
    pem = (DATA / "dkim_keys" / "acme.cz.demo2026.pem").read_bytes()
    sig = dkim.sign(unsigned, b"demo2026", b"acme.cz", pem, include_headers=[b"From", b"To", b"Subject", b"Date"],
                    canonicalize=(b"relaxed", b"relaxed"), linesep=b"\n", length=length)
    return sig + unsigned


def test_resigned_without_length_tag_passes():
    raw = _resign(_raw("01_acme_invoice_legit.eml"), length=False)
    assert dkim_verdict(raw, dns_snapshot=DNS) == {"result": "pass", "d": "acme.cz", "s": "demo2026", "aligned": True}


def test_body_length_tag_is_refused():
    raw = _resign(_raw("01_acme_invoice_legit.eml"), length=True)
    assert dkim_verdict(raw, dns_snapshot=DNS)["result"] == "fail"
    appended = raw + b"\nUPDATE: please pay LT483999000000001234 instead.\n"
    verdict = dkim_verdict(appended, dns_snapshot=DNS)
    assert verdict["result"] == "fail" and verdict["aligned"] is False
    assert dkim_fact(verdict, prov=DNS_SHA)["severity"] == "BLOCK"


def test_prepended_second_from_is_unaligned():
    raw = _raw("01_acme_invoice_legit.eml")
    forged = b"From: Jana Novakova <jana.novakova@acme-cz.com>\n" + raw
    verdict = dkim_verdict(forged, dns_snapshot=DNS)
    assert verdict["aligned"] is False
    assert dkim_fact(verdict, prov=DNS_SHA)["display_line"] == "DKIM FAIL"


@pytest.mark.parametrize("verdict", [
    {"result": "pass", "d": "acme.cz", "s": "demo2026", "aligned": "false"},
    {"result": "pass", "d": "acme.cz", "s": "demo2026", "aligned": 1},
    {"result": "PASS", "d": "acme.cz", "s": "demo2026", "aligned": True},
    {"result": "pass", "d": "acme.cz", "s": "demo2026"},
    {},
])
def test_dkim_fact_strict_on_malformed_verdict(verdict):
    f = dkim_fact(verdict, prov=DNS_SHA)
    assert (f["severity"], f["display_line"], f["prov"]) == ("BLOCK", "DKIM FAIL", DNS_SHA)


def test_dkim_fact_evidence_is_json_safe():
    f = dkim_fact({"result": "fail", "d": 1.5, "s": ["x"], "aligned": False}, prov=DNS_SHA)
    assert f["evidence"] == {"result": "fail", "d": None, "s": None, "aligned": False}


@pytest.mark.parametrize("cand,ref", [
    ("ac​m​e.cz", "acme.cz"),  # zero-width spaces must not inflate the edit distance
    ("a­c­me.cz", "acme.cz"),  # soft hyphens
    ("Kovo.cz", "kovo.cz"),  # KELVIN SIGN lower-cases to ASCII k: never an exact match
    ("ａｃｍｅ.cz", "acme.cz"),  # full-width letters
])
def test_unicode_tricks_are_lookalikes(cand, ref):
    f = domain_fact(cand, ref)
    assert (f["severity"], f["display_line"]) == ("BLOCK", "DOMAIN LOOKALIKE")


def test_punycode_registry_domain_still_matches_itself():
    assert domain_fact("xn--cme-5cd.cz", "xn--cme-5cd.cz")["display_line"] == "DOMAIN MATCH"


def test_domain_age_unparseable_first_seen_warns():
    f = domain_age_fact("acme.cz", "not-a-date", NOW)
    assert (f["severity"], f["display_line"]) == ("WARN", "DOMAIN AGE 0D")
    assert f["evidence"]["first_seen"] == "not-a-date"


def test_domain_age_future_first_seen_warns():
    f = domain_age_fact("acme.cz", "2027-01-01T00:00:00Z", NOW)
    assert (f["severity"], f["display_line"]) == ("WARN", "DOMAIN AGE 0D")


def test_manifest_rows_are_not_vacuous():
    assert all(row["expected_facts"] for row in MANIFEST)
    attacks = {row["file"] for row in MANIFEST if row["attack"]}
    assert attacks == {"04_bec_lookalike_acme-cz.eml", "05_takeover_acme_real_domain.eml", "06_pdf_injection.eml",
                       "07_exfil_injection.eml"}
    for row in MANIFEST:
        marker = b"X-AirGap-Fixture: synthetic-attack" if row["attack"] else b"X-AirGap-Fixture: synthetic;"
        assert marker in _raw(row["file"]), row["file"]


def _no_floats(obj) -> bool:
    if isinstance(obj, float):
        return False
    if isinstance(obj, dict):
        return all(_no_floats(v) for v in obj.values())
    if isinstance(obj, list):
        return all(_no_floats(v) for v in obj)
    return True


def test_fixture_json_has_no_floats():
    paths = [EMAILS / "manifest.json", DATA / "dns_snapshot.json", *sorted((DATA / "invoices").glob("*.json"))]
    for p in paths:
        assert _no_floats(json.loads(p.read_text())), p


def test_generator_reproduces_committed_fixtures(tmp_path):
    import shutil

    from tools.gen_emails import generate

    shutil.copytree(DATA / "dkim_keys", tmp_path / "dkim_keys")
    generate(tmp_path)
    for name in [*(r["file"] for r in MANIFEST), "manifest.json"]:
        assert (tmp_path / "emails" / name).read_bytes() == (EMAILS / name).read_bytes(), name
    assert (tmp_path / "dns_snapshot.json").read_bytes() == (DATA / "dns_snapshot.json").read_bytes()
    for p in (tmp_path / "invoices").glob("*.json"):
        assert p.read_bytes() == (DATA / "invoices" / p.name).read_bytes(), p.name
