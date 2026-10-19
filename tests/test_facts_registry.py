"""WS-D fact modules: F-VOP, F-VAT, F-BANK, F-FIRSTSEEN, F-ANOM, F-CALLBACK, F-ATTEST (CONTRACTS.md v2 §2.1)."""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from executor.facts import _util, anom, attest_fact, callback, firstseen, iban_bank, vat, vop

DATA = Path(__file__).resolve().parents[1] / "data"
VOP = DATA / "vop_mock.json"
ADIS = DATA / "adis_cache" / "adis.json"
BANKS = DATA / "bank_codes.json"
VENDORS = DATA / "vendors.json"

ACME_IBAN = "CZ6508000000192000145399"
ACME_NEW = "CZ2003000000002001234567"
BETA_IBAN = "CZ6203000000000123456789"
GAMMA_IBAN = "CZ7501000000001155443322"
FRAUD = "LT483999000000001234"
MULE = "LT493999000000005678"
NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)  # 14:00 Europe/Prague

ALL_FACTS: list[dict] = []


def keep(f: dict) -> dict:
    ALL_FACTS.append(f)
    return f


def sha(p: Path) -> str:
    return _util.sha256_hex(p.read_bytes())


def no_floats(obj: object) -> bool:
    if isinstance(obj, float):
        return False
    if isinstance(obj, dict):
        return all(no_floats(v) for v in obj.values())
    if isinstance(obj, list):
        return all(no_floats(v) for v in obj)
    return True


# --- F-VOP (simulated)

@pytest.mark.parametrize("iban,name,code,sev", [
    (ACME_IBAN, "ACME s.r.o.", "MTCH", "INFO"),
    (ACME_NEW, "Acme, s. r. o.", "MTCH", "INFO"),
    (MULE, "ACME s.r.o.", "CMTC", "WARN"),
    (FRAUD, "ACME s.r.o.", "NMTC", "BLOCK"),
    ("CZ5855000000001265098001", "ACME s.r.o.", "NOAP", "WARN"),  # bank 5500 not a participant
    ("CZ0901000000009999999999", "ACME s.r.o.", "NOAP", "WARN"),  # participant, account unknown
    ("DE89370400440532013000", "ACME s.r.o.", "NOAP", "WARN"),  # country not in the mock
])
def test_vop_codes(iban, name, code, sev):
    f = keep(vop.vop_fact(iban, name, vop_path=VOP))
    assert (f["id"], f["severity"], f["display_line"]) == ("F-VOP", sev, f"VOP {code}")
    assert f["evidence"]["code"] == code
    assert f["prov"] == sha(VOP)
    assert "simulated" in f["label"].lower()


def test_vop_cmtc_label_shows_registered_holder():
    f = vop.vop_fact(MULE, "ACME s.r.o.", vop_path=VOP)
    assert "ACME SRO Trading" in f["label"]
    assert f["evidence"]["holder"] == "ACME SRO Trading"


def test_vop_name_normalization():
    assert vop.normalize_name("ACME s.r.o.") == vop.normalize_name("Acme SRO") == "acme"
    assert vop.normalize_name("Beta Servis a.s.") == vop.normalize_name("BETA SERVIS, AS") == "beta servis"
    assert vop.normalize_name("Žluťoučký kůň spol. s r.o.") == "zlutoucky kun"
    assert vop.match_code("Beta Servis a.s.", "Beta Servise a.s.")[0] == "CMTC"  # token_sort_ratio >= 85


# --- F-VAT (ADIS cache)

def test_vat_published_yes():
    f = keep(vat.vat_fact("12345678", ACME_NEW, adis_path=ADIS))
    assert (f["severity"], f["display_line"]) == ("INFO", "ADIS ACCT YES")
    assert f["prov"] == sha(ADIS) and f["evidence"]["dic"] == "CZ12345678"


@pytest.mark.parametrize("ico,iban", [("12345678", FRAUD), ("12345678", BETA_IBAN), ("11111111", ACME_IBAN)])
def test_vat_not_published_or_unknown_is_warn(ico, iban):
    f = keep(vat.vat_fact(ico, iban, adis_path=ADIS))
    assert (f["severity"], f["display_line"]) == ("WARN", "ADIS ACCT NO")
    assert f["evidence"]["account_published"] is False


def test_vat_unreliable_blocks(tmp_path):
    p = tmp_path / "adis.json"
    p.write_text(json.dumps({"as_of": "2026-10-19", "payers": {"CZ12345678": {"unreliable": True,
                                                                              "accounts": [ACME_IBAN]}}}))
    f = keep(vat.vat_fact("CZ12345678", ACME_IBAN, adis_path=p))
    assert (f["severity"], f["display_line"]) == ("BLOCK", "VAT UNRELIABLE")
    assert f["prov"] == sha(p)


def test_vat_bad_mode_and_cz_iban():
    with pytest.raises(ValueError):
        vat.vat_fact("12345678", ACME_IBAN, adis_path=ADIS, mode="other")
    assert vat.cz_iban("0800", "2000145399", "19") == ACME_IBAN


def test_vat_live_mode_parsing_without_network(monkeypatch):
    monkeypatch.setattr(vat, "_live_lookup", lambda d: {"found": True, "unreliable": False, "accounts": [ACME_IBAN]})
    f = vat.vat_fact("12345678", ACME_IBAN, adis_path=ADIS, mode="live")
    assert f["display_line"] == "ADIS ACCT YES" and f["evidence"]["source"] == "adis-live" and len(f["prov"]) == 64


# --- F-BANK

@pytest.mark.parametrize("iban,country,sev,line", [
    (ACME_IBAN, "CZ", "INFO", "BANK DOMESTIC"),
    (GAMMA_IBAN, "CZ", "INFO", "BANK DOMESTIC"),
    (FRAUD, "CZ", "WARN", "BANK FOREIGN EMI"),
    (MULE, "CZ", "WARN", "BANK FOREIGN EMI"),
    (FRAUD, "LT", "WARN", "BANK FOREIGN EMI"),  # EMI is WARN even when domestic
])
def test_bank(iban, country, sev, line):
    f = keep(iban_bank.bank_fact(iban, country, bank_codes_path=BANKS))
    assert (f["id"], f["severity"], f["display_line"]) == ("F-BANK", sev, line)
    assert f["prov"] == sha(BANKS)


def test_bank_evidence_lt_emi():
    f = iban_bank.bank_fact(FRAUD, "CZ", bank_codes_path=BANKS)
    assert f["evidence"]["bank_code"] == "39990" and f["evidence"]["kind"] == "emi"


# --- F-FIRSTSEEN

HISTORY = [{"iban": ACME_IBAN, "from": "2024-03-01", "to": "2026-10-19T07:00:00Z", "change_id": None},
           {"iban": ACME_NEW, "from": "2026-10-19T07:00:00Z", "to": None, "change_id": "chg_8"}]


def test_firstseen_new():
    f = keep(firstseen.firstseen_fact(FRAUD, HISTORY, NOW))
    assert (f["severity"], f["display_line"]) == ("WARN", "IBAN NEW 0H")
    assert f["prov"] == _util.digest(HISTORY)


def test_firstseen_5h():
    f = keep(firstseen.firstseen_fact(ACME_NEW, HISTORY, NOW))
    assert (f["severity"], f["display_line"]) == ("WARN", "IBAN NEW 5H")
    assert f["evidence"]["hours"] == 5


def test_firstseen_400d():
    hist = [{"iban": ACME_IBAN, "from": (NOW - timedelta(days=400)).date().isoformat(), "to": None,
             "change_id": None}]
    f = keep(firstseen.firstseen_fact(ACME_IBAN, hist, NOW))
    assert (f["severity"], f["display_line"]) == ("INFO", "IBAN SEEN 400D")


def test_firstseen_boundary_72h():
    hist = [{"iban": ACME_NEW, "from": "2026-10-16T12:00:00Z", "to": None, "change_id": "chg_1"}]
    assert firstseen.firstseen_fact(ACME_NEW, hist, NOW)["display_line"] == "IBAN SEEN 3D"
    hist[0]["from"] = "2026-10-16T12:00:01Z"
    assert firstseen.firstseen_fact(ACME_NEW, hist, NOW)["display_line"] == "IBAN NEW 71H"


# --- F-ANOM

def call(step, tool, untrusted=False, ts=None, session="s1"):
    row = {"session_id": session, "step": step, "tool": tool, "args_sha256": "0" * 64, "result": "ok",
           "untrusted_read": untrusted}
    if ts:
        row["ts"] = ts
    return row


PAYEE = {"vendor_id": "ven_12345678"}
MANDATE = {"max_per_payment_minor": 5_000_000}


def test_anom_quiet_is_info():
    f = keep(anom.anom_fact({"kind": "proposal", "invoice": {"amount_minor": 1_450_123}},
                            [call(1, "inbox.list"), call(2, "payment.propose")], payee=PAYEE, mandate=MANDATE,
                            now=NOW))
    assert (f["severity"], f["display_line"], f["evidence"]["score"]) == ("INFO", "ANOM 0/100", 0)
    assert f["prov"] == _util.digest([call(1, "inbox.list"), call(2, "payment.propose")])


def test_anom_untrusted_read_before_change_warns_at_40():
    log = [call(1, "inbox.list"), call(2, "inbox.read", untrusted=True), call(4, "payee.request_change")]
    f = keep(anom.anom_fact({"kind": "change", "new_iban": FRAUD}, log, payee=PAYEE, mandate=None, now=NOW))
    assert (f["severity"], f["display_line"]) == ("WARN", "ANOM 40/100")
    assert f["evidence"]["features"] == "untrusted_read_before_action"


def test_anom_untrusted_read_too_far_back_or_other_session():
    log = [call(1, "inbox.read", untrusted=True), call(5, "payee.request_change"),
           call(4, "inbox.read", untrusted=True, session="s2")]
    f = anom.anom_fact({"kind": "change"}, log, payee=PAYEE, mandate=None, now=NOW)
    assert f["evidence"]["score"] == 0


def test_anom_all_features():
    ts = [f"2026-10-19T21:00:{s:02d}Z" for s in range(0, 60, 10)]  # 6 proposals in 50 s
    log = [call(1, "inbox.read", untrusted=True)] + [call(2 + i, "payment.propose", ts=t) for i, t in enumerate(ts)]
    night = datetime(2026, 10, 19, 21, 30, tzinfo=timezone.utc)  # 23:30 Prague
    f = keep(anom.anom_fact({"kind": "proposal", "amount_minor": 4_900_000}, log, payee=PAYEE, mandate=MANDATE,
                            now=night))
    assert f["evidence"]["features"] == "untrusted_read_before_action,proposal_burst,just_below_cap,round_amount," \
                                        "off_hours"
    assert (f["severity"], f["display_line"]) == ("WARN", "ANOM 100/100")


@pytest.mark.parametrize("amount,mandate,expected", [
    (4_900_000, MANDATE, {"just_below_cap", "round_amount"}),
    (4_899_999, MANDATE, set()),
    (5_000_001, MANDATE, set()),
    (300_000, None, {"round_amount"}),
])
def test_anom_amount_features(amount, mandate, expected):
    got = anom.features({"amount_minor": amount}, [], mandate=mandate, now=NOW)
    assert set(got) == expected


def test_anom_burst_needs_more_than_five_in_60s():
    five = [call(i, "payment.propose", ts=f"2026-10-19T10:00:{i * 10:02d}Z") for i in range(5)]
    assert "proposal_burst" not in anom.features({}, five, mandate=None, now=NOW)
    spread = [call(i, "payment.propose", ts=f"2026-10-19T10:0{i}:00Z") for i in range(8)]
    assert "proposal_burst" not in anom.features({}, spread, mandate=None, now=NOW)


def test_anom_off_hours_boundaries():
    def hour(h):  # Prague is UTC+2 on 2026-10-19
        return datetime(2026, 10, 19, h, 0, tzinfo=timezone.utc) - timedelta(hours=2)
    assert "off_hours" in anom.features({}, [], mandate=None, now=hour(22))
    assert "off_hours" in anom.features({}, [], mandate=None, now=hour(5))
    assert "off_hours" not in anom.features({}, [], mandate=None, now=hour(6))


def test_anom_score_never_lowers_severity():
    """The score can only add WARN: never BLOCK, never below INFO; severity is monotone in the score."""
    sevs = []
    for amount in (1_234_567, 300_000, 4_900_000):
        for log in ([], [call(1, "inbox.read", untrusted=True), call(2, "payment.propose")]):
            f = anom.anom_fact({"amount_minor": amount}, log, payee=PAYEE, mandate=MANDATE, now=NOW)
            assert f["severity"] in ("INFO", "WARN")
            assert (f["severity"] == "WARN") == (f["evidence"]["score"] >= anom.WARN_AT)
            sevs.append((f["evidence"]["score"], f["severity"]))
    ranks = [s for _, s in sorted(sevs)]
    assert ranks == sorted(ranks, key=["INFO", "WARN"].index)


# --- F-CALLBACK

@pytest.mark.parametrize("cb,sev,line", [
    ({"status": "confirmed"}, "INFO", "CALLBACK OK"),
    ({"status": "pending"}, "BLOCK", "CALLBACK MISSING"),
    ({"status": "denied"}, "BLOCK", "CALLBACK MISSING"),
    (None, "BLOCK", "CALLBACK MISSING"),
])
def test_callback(cb, sev, line):
    f = keep(callback.callback_fact({"callback": cb} if cb is not None else {}))
    assert (f["id"], f["severity"], f["display_line"]) == ("F-CALLBACK", sev, line)


# --- F-ATTEST

def res(cls, ok=True):
    return {"ok": ok, "issuer_class": cls, "iss": f"https://{cls}.example", "error": None if ok else "kb_jwt_invalid",
            "disclosed": {}, "vc_sha256": "0" * 64}


IN_NET = {"in_network": True, "break_glass": False}


@pytest.mark.parametrize("results,sev,line,k", [
    ([], "BLOCK", "ATT 0/3", 0),
    ([res("supplier-erp")], "BLOCK", "ATT 1/3 ERP", 1),
    ([res("supplier-erp"), res("supplier-erp")], "BLOCK", "ATT 1/3 ERP", 1),  # same class twice is still 1
    ([res("supplier-bank"), res("registry", ok=False)], "BLOCK", "ATT 1/3 BANK", 1),
    ([res("supplier-bank"), res("supplier-erp")], "INFO", "ATT 2/3 ERP BANK", 2),
    ([res("registry"), res("supplier-erp")], "INFO", "ATT 2/3 ERP REG", 2),
    ([res("registry"), res("supplier-bank"), res("supplier-erp")], "INFO", "ATT 3/3 ALL", 3),
])
def test_attest_k(results, sev, line, k):
    f = keep(attest_fact.attest_fact(IN_NET, results))
    assert (f["id"], f["severity"], f["display_line"], f["evidence"]["k"]) == ("F-ATTEST", sev, line, k)


def test_attest_break_glass_and_off_network():
    f = keep(attest_fact.attest_fact({"in_network": True, "break_glass": True}, []))
    assert (f["severity"], f["display_line"], f["evidence"]["break_glass"]) == ("INFO", "ATT BREAK-GLASS", True)
    f = keep(attest_fact.attest_fact({"in_network": False, "break_glass": False}, []))
    assert (f["severity"], f["display_line"]) == ("INFO", "ATT OFF-NETWORK")
    f = keep(attest_fact.attest_fact({"in_network": False, "break_glass": True}, []))
    assert f["display_line"] == "ATT BREAK-GLASS"


# --- adversarial regressions

def write_vop(tmp_path, holder):
    p = tmp_path / "vop.json"
    p.write_text(json.dumps({"participants": {"CZ": ["0100"]}, "accounts": {GAMMA_IBAN: {"holder": holder}}}))
    return p


@pytest.mark.parametrize("holder", ["Tisk", "Tisk s.r.o.", "Gamma"])
def test_vop_holder_fragment_of_name_is_nmtc(tmp_path, holder):
    """A holder that is only a fragment of the registered name must not be a close match (was CMTC via subset)."""
    f = vop.vop_fact(GAMMA_IBAN, "Gamma Tisk s.r.o.", vop_path=write_vop(tmp_path, holder))
    assert (f["severity"], f["display_line"]) == ("BLOCK", "VOP NMTC")


@pytest.mark.parametrize("holder", ["ACME \u0414\u0414\u0414 s.r.o.", "ACME \u03a9\u03c9\u03c9", "\u0410\u0421\u041c\u0415 s.r.o."])
def test_vop_non_latin_letters_never_mtch(tmp_path, holder):
    """Letters without an ASCII decomposition used to be dropped, turning 'ACME <cyrillic>' into an exact MTCH."""
    f = vop.vop_fact(GAMMA_IBAN, "ACME s.r.o.", vop_path=write_vop(tmp_path, holder))
    assert f["evidence"]["code"] != "MTCH" and f["severity"] != "INFO"


def test_bank_unknown_code_is_warn():
    """A CZ bank code missing from the snapshot cannot be ruled out as an EMI (was INFO 'BANK DOMESTIC')."""
    f = keep(iban_bank.bank_fact("CZ5855000000001265098001", "CZ", bank_codes_path=BANKS))
    assert (f["severity"], f["display_line"]) == ("WARN", "BANK FOREIGN EMI")
    assert f["evidence"]["found"] is False and f["prov"] == sha(BANKS)


@pytest.mark.parametrize("change", [{}, {"in_network": None}, {"in_network": "false"},
                                    {"in_network": True, "break_glass": "false"}, {"break_glass": 1}])
def test_attest_malformed_flags_fail_closed(change):
    """Only literal in_network=False / break_glass=True leave the k-of-3 path (missing key used to give INFO)."""
    f = keep(attest_fact.attest_fact(change, [res("supplier-erp")]))
    assert (f["severity"], f["display_line"]) == ("BLOCK", "ATT 1/3 ERP")


@pytest.fixture
def new_york_tz():
    old = os.environ.get("TZ")
    os.environ["TZ"] = "America/New_York"
    time.tzset()
    yield
    if old is None:
        os.environ.pop("TZ", None)
    else:
        os.environ["TZ"] = old
    time.tzset()


def test_naive_now_is_utc_not_host_local(new_york_tz):
    """Naive `now` must not depend on the host zone (astimezone() on a naive datetime uses local time)."""
    naive = datetime(2026, 10, 19, 3, 0)  # 03:00 UTC = 05:00 Prague (off-hours); 03:00 New York = 09:00 Prague
    assert "off_hours" in anom.features({}, [], mandate=None, now=naive)
    hist = [{"iban": ACME_NEW, "from": "2026-10-19T00:00:00Z", "to": None, "change_id": "chg_1"}]
    assert firstseen.firstseen_fact(ACME_NEW, hist, naive)["display_line"] == "IBAN NEW 3H"


def test_anom_burst_mixed_naive_and_aware_ts():
    log = [call(i, "payment.propose", ts=f"2026-10-19T10:00:{i * 5:02d}" + ("Z" if i % 2 else ""))
           for i in range(6)]
    assert "proposal_burst" in anom.features({}, log, mandate=None, now=NOW)


def test_vat_parse_live_response():
    def std(bank, number, prefix=None, ended=None):
        return NS(standardniUcet=NS(kodBanky=bank, cislo=number, predcisli=prefix), nestandardniUcet=None,
                  datumZverejneniUkonceni=ended)
    ucty = [std("0800", "2000145399", "19"), std("0300", "2001234567", ended="2025-01-01"),
            NS(standardniUcet=None, nestandardniUcet=NS(cislo="LT48 3999 0000 0000 1234"),
               datumZverejneniUkonceni=None)]
    row = NS(nespolehlivyPlatce="NE", zverejneneUcty=NS(ucet=ucty))
    got = vat.parse_live(NS(statusPlatceDPH=[row]))
    assert got == {"found": True, "unreliable": False, "accounts": [ACME_IBAN, FRAUD]}
    assert vat.parse_live(NS(statusPlatceDPH=[NS(nespolehlivyPlatce="ANO", zverejneneUcty=None)]))["unreliable"]
    assert vat.parse_live(NS(statusPlatceDPH=[]))["found"] is False
    assert vat.parse_live(NS(statusPlatceDPH=[NS(nespolehlivyPlatce="NENALEZEN")]))["found"] is False


def test_vat_live_unknown_dic_is_warn(monkeypatch):
    monkeypatch.setattr(vat, "_live_lookup", lambda d: {"found": False, "unreliable": False, "accounts": []})
    f = vat.vat_fact("12345678", ACME_IBAN, adis_path=ADIS, mode="live")
    assert (f["severity"], f["display_line"], f["evidence"]["payer_found"]) == ("WARN", "ADIS ACCT NO", False)


def sample_facts() -> list[dict]:
    """One fact per branch of every module, so the contract check below never depends on test order."""
    out = [vop.vop_fact(i, "ACME s.r.o.", vop_path=VOP) for i in (ACME_IBAN, MULE, FRAUD, "DE89370400440532013000")]
    out += [vat.vat_fact("12345678", i, adis_path=ADIS) for i in (ACME_NEW, FRAUD)]
    out += [iban_bank.bank_fact(i, "CZ", bank_codes_path=BANKS) for i in (ACME_IBAN, FRAUD)]
    out += [firstseen.firstseen_fact(i, HISTORY, NOW) for i in (ACME_IBAN, ACME_NEW, FRAUD)]
    out.append(anom.anom_fact({"amount_minor": 4_900_000}, [], payee=PAYEE, mandate=MANDATE, now=NOW))
    out += [callback.callback_fact({"callback": {"status": s}}) for s in ("confirmed", "none")]
    out += [attest_fact.attest_fact(c, [res("supplier-erp"), res("supplier-bank"), res("registry")])
            for c in (IN_NET, {"in_network": False}, {"break_glass": True})]
    return out


# --- data files

def test_vendors_rows():
    rows = json.loads(VENDORS.read_text())
    by_ico = {r["ico"]: r for r in rows}
    assert set(by_ico) == {"12345678", "87654321", "99887762", "77665546"}
    delta = by_ico["77665546"]
    assert (delta["iban"], delta["in_network"], delta["domain"]) == ("CZ5201000000007788990011", True, "deltastavby.cz")
    acme, beta, gamma = by_ico["12345678"], by_ico["87654321"], by_ico["99887762"]
    assert (acme["iban"], acme["domain"], acme["in_network"]) == (ACME_IBAN, "acme.cz", True)
    assert (beta["iban"], beta["in_network"]) == (BETA_IBAN, False)
    assert (gamma["iban"], gamma["in_network"], gamma["domain"]) == (GAMMA_IBAN, True, "gammatisk.cz")
    required = {"vendor_id", "ico", "name", "domain", "iban", "country", "phone", "contact_email", "registered_since",
                "in_network", "issuer_pins", "iban_history"}
    for r in rows:
        assert required <= set(r) and r["issuer_pins"] == [] and r["vendor_id"] == f"ven_{r['ico']}"
        assert r["iban_history"] == [{"iban": r["iban"], "from": r["registered_since"], "to": None,
                                      "change_id": None}]
        assert vat.vat_fact(r["ico"], r["iban"], adis_path=ADIS)["display_line"] == "ADIS ACCT YES"
        assert vop.vop_fact(r["iban"], r["name"], vop_path=VOP)["display_line"] == "VOP MTCH"


def test_pinned_ibans_valid_mod97():
    for iban in (ACME_IBAN, ACME_NEW, BETA_IBAN, GAMMA_IBAN, FRAUD, MULE):
        t = iban[4:] + iban[:4]
        assert int("".join(str(int(c, 36)) for c in t)) % 97 == 1, iban


# --- cross-cutting (runs last in this module)

def test_zz_all_facts_contract():
    facts = ALL_FACTS + sample_facts()
    assert len(facts) >= 19
    snapshot_ids = {"F-VOP", "F-VAT", "F-BANK", "F-FIRSTSEEN", "F-ANOM"}
    for f in facts:
        line = f["display_line"]
        assert len(line) <= 18 and all(0x20 <= ord(c) <= 0x7E for c in line), line
        assert f["kind"] == "F" and f["severity"] in ("INFO", "WARN", "BLOCK")
        assert no_floats(f), f
        if f["id"] in snapshot_ids:
            assert len(f.get("prov", "")) == 64, f
