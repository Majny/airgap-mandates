"""Tests for executor/render.py, profile safe5-mono-18x7 (non-default since H0; CONTRACTS §5).

The four goldens below are the v2 Safe 5 screens. The default profile safe3-mono-16x4 is tested in
tests/test_render_safe3.py. Every kwargs helper here pins profile=safe5-mono-18x7.
Emulator screenshot goldens live in tests/device/ (WS-C, needs trezor-user-env).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from executor import render as R

ACME_IBAN = "CZ6508000000192000145399"
NEW_IBAN = "CZ6203000000000123456789"
FRAUD_IBAN = "LT483999000000001234"  # fictitious Lithuanian EMI
LONG_IBAN = "LC14BOSL12345678901234567890123456"  # 34 chars, format-valid, synthetic


def h64(prefix16: str) -> str:
    return prefix16 + "0" * 48


def fact(id: str, severity: str = "INFO", line: str = "X", kind: str = "F") -> dict[str, str]:
    return {"id": id, "kind": kind, "severity": severity, "label": id, "display_line": line}


PAY_FACTS = [fact("F-VAT", line="ADIS ACCT YES"), fact("F-VOP", line="VOP MTCH"),
             fact("F-MANDATE", "WARN", "OVER MANDATE CAP")]
CHG_FACTS = [fact("F-VOP", "WARN", "VOP CMTC"), fact("F-ATTEST", line="ATT 2/3 ERP BANK")]


def pay_kwargs(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = dict(
        proposal_no=42, nonce="0C55A1E7", exp="2026-10-19T13:20:00Z", payee_name="Beta Servis a.s.",
        iban=ACME_IBAN, amount_minor=12500_50, currency="CZK", vs="2026101901", facts=PAY_FACTS,
        subject_hash=h64("9b1e44c07a2d1f30"),
    )
    base.setdefault("profile", R.PROFILE_SAFE5)
    base.update(kw)
    return base


def mandate_kwargs(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = dict(
        mandate_no=3, nonce="91BC02E1", max_per_payment_minor=80000_00, max_total_minor=250000_00, max_count=20,
        payee_scope="existing_only", valid_from="2026-10-19T10:00:00Z", valid_until="2026-10-20T16:00:00Z",
        currency="CZK", require_vop=["MTCH"], payee_count=12, payee_registry_version=31,
        policy_hash=h64("1f3a9c0e7d2b4a61"), subject_hash=h64("3e0d9a1c55b2e7f0"), role="clerk", sig_index=1,
        sig_total=2,
    )
    base.setdefault("profile", R.PROFILE_SAFE5)
    base.update(kw)
    return base


def chg_kwargs(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = dict(
        change_no=7, nonce="7C11A0E2", vendor_name="ACME s.r.o.", vendor_ico="12345678", old_iban=ACME_IBAN,
        old_since="2024-03-01", new_iban=NEW_IBAN, facts=CHG_FACTS, subject_hash=h64("4f2a9c1e0b7d3a55"),
        role="treasury", sig_index=2, sig_total=2,
    )
    base.setdefault("profile", R.PROFILE_SAFE5)
    base.update(kw)
    return base


def attest_kwargs(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = dict(
        change_no=7, nonce="7D11E0A2", vendor_name="ACME s.r.o.", ico="12345678", iban=NEW_IBAN,
        valid_from="2026-10-20", signer_role="director", role_basis="OR", threshold=2, signer_count=3, version=5,
        subject_hash=h64("5a0c7e19d3b4f286"),
    )
    base.setdefault("profile", R.PROFILE_SAFE5)
    base.update(kw)
    return base


def assert_s11(text: str) -> list[list[str]]:
    """S11: ASCII + LF, <=18 cols, page 1 exactly 7 lines, <=2 pages, line 1 starts AG1/, break lines <=15."""
    ls = text.split("\n")
    assert not text.endswith("\n")
    assert all(" " <= c <= "~" or c == "\n" for c in text)
    assert all(1 <= len(line) <= 18 for line in ls), ls
    assert ls[0].startswith("AG1/")
    assert len(ls) <= 14
    if len(ls) > 7:
        brk = R.PROFILES[R.PROFILE_SAFE5].break_line_max
        assert len(ls[6]) <= brk and len(ls[7]) <= brk
    return R.render_pages(text, R.PROFILE_SAFE5)


# ----------------------------------------------------------------- goldens (ARCHITECTURE §3.4)

PAY_GOLDEN = (
    "AG1/DEMO PAY 42\n"
    "12500.50 CZK\n"
    "CZ65 0800 0000\n"
    "1920 0014 5399\n"
    "BETA SERVIS A.S.\n"
    "VS 2026101901\n"
    "EXP 10-19 15:20\n"
    "0 BLOCK 1 WARN\n"
    "OVER MANDATE CAP\n"
    "VOP MTCH\n"
    "ADIS ACCT YES\n"
    "ROLE CLERK 1/1\n"
    "N 0C55A1E7\n"
    "H 9b1e44c07a2d1f30"
)

MANDATE_GOLDEN = (
    "AG1/DEMO MANDATE\n"
    "NO 3 CZK\n"
    "PER PAY 80000\n"
    "TOTAL 250000\n"
    "MAX 20 PAYMENTS\n"
    "EXISTING PAYEES\n"
    "TO 10-20 18:00\n"
    "ROLE CLERK 1/2\n"
    "FROM 10-19 12:00\n"
    "REQ VOP MTCH\n"
    "PAYEES 12 REG V31\n"
    "N 91BC02E1\n"
    "P 1f3a9c0e7d2b4a61\n"
    "H 3e0d9a1c55b2e7f0"
)

CHG_GOLDEN = (
    "AG1/DEMO CHG 7\n"
    "ACME S.R.O.\n"
    "ICO 12345678\n"
    "OLD ..5399 2024-03\n"
    "NEW CZ62 0300 0000\n"
    "    0001 2345 6789\n"
    "BANK 0300 CZ\n"
    "0 BLOCK 1 WARN\n"
    "ATT 2/3 ERP BANK\n"
    "VOP CMTC\n"
    "COOLOFF DONE\n"
    "ROLE TREASURY 2/2\n"
    "N 7C11A0E2\n"
    "H 4f2a9c1e0b7d3a55"
)

ATTEST_GOLDEN = (
    "AG1/DEMO ATTEST\n"
    "ACME S.R.O.\n"
    "ICO 12345678\n"
    "PAY TO ACCOUNT\n"
    "CZ62 0300 0000\n"
    "0001 2345 6789\n"
    "FROM 2026-10-20\n"
    "SIGNER DIR (OR)\n"
    "QUORUM 2/3 V5\n"
    "CHANGE 7\n"
    "N 7D11E0A2\n"
    "H 5a0c7e19d3b4f286"
)


def test_pay_golden():
    text = R.render_pay(**pay_kwargs())
    assert text == PAY_GOLDEN
    assert [len(p) for p in assert_s11(text)] == [7, 7]


def test_mandate_golden():
    text = R.render_mandate(**mandate_kwargs())
    assert text == MANDATE_GOLDEN
    assert [len(p) for p in assert_s11(text)] == [7, 7]


def test_chg_golden():
    text = R.render_change(**chg_kwargs())
    assert text == CHG_GOLDEN
    assert [len(p) for p in assert_s11(text)] == [7, 7]


def test_attest_golden():
    text = R.render_vendor_attest(**attest_kwargs())
    assert text == ATTEST_GOLDEN
    assert [len(p) for p in assert_s11(text)] == [7, 5]


@pytest.mark.parametrize("template,kw,golden", [
    ("PAY", pay_kwargs(), PAY_GOLDEN),
    ("MANDATE", mandate_kwargs(), MANDATE_GOLDEN),
    ("CHG", chg_kwargs(), CHG_GOLDEN),
    ("VENDOR_ATTEST", attest_kwargs(), ATTEST_GOLDEN),
])
def test_rerender_from_params(template, kw, golden):
    assert R.render(template, kw) == golden
    assert R.render(template, {k: v for k, v in kw.items() if k != "profile"}, profile=R.PROFILE_SAFE5,
                    deployment="DEMO") == golden


def test_profile_constants():
    p = R.PROFILES["safe5-mono-18x7"]
    assert (p.width, p.lines_per_page, p.max_pages, p.break_line_max) == (18, 7, 2, 15)
    assert R.MIN_WIDTH["safe5-mono-18x7"] == 18 and p.hash_hex == 16


# ----------------------------------------------------------------- general rules


def test_deployment_tag_in_title():
    text = R.render_pay(**pay_kwargs(deployment="PROD1"))
    assert text.split("\n")[0] == "AG1/PROD1 PAY 42"
    with pytest.raises(R.RenderError):
        R.render_pay(**pay_kwargs(deployment="demo"))
    with pytest.raises(R.RenderError):
        R.render_pay(**pay_kwargs(deployment="TOOLONG"))


def test_title_never_dropped():
    with pytest.raises(R.RenderError) as e:
        R.render_pay(**pay_kwargs(deployment="ABCDE", proposal_no=12345))  # 'AG1/ABCDE PAY 12345' = 19
    assert e.value.code == "WIDTH"


@pytest.mark.parametrize("nonce", ["0C55A1", "0c55a1e7", "0C55A1E7F", "GGGGGGGG"])
def test_nonce_is_8_uppercase_hex(nonce):
    with pytest.raises(R.RenderError):
        R.render_pay(**pay_kwargs(nonce=nonce))


def test_hints_never_on_device():
    hint = fact("H-AGENT", line="agent: CFO approved", kind="H")
    text = R.render_pay(**pay_kwargs(facts=PAY_FACTS + [hint]))
    assert text == PAY_GOLDEN
    assert "[H]" not in text and "[F]" not in text and "AGENT" not in text


def test_r0_block_fact_cannot_render():
    with pytest.raises(R.RenderError) as e:
        R.render_pay(**pay_kwargs(facts=PAY_FACTS + [fact("F-DOMAIN", "BLOCK", "LOOKALIKE DOMAIN")]))
    assert e.value.code == "R0_BLOCK"
    with pytest.raises(R.RenderError):
        R.render_change(**chg_kwargs(facts=[fact("F-ATTEST", "BLOCK", "ATT 0/3")]))


def test_fact_lines_uppercased_and_truncated():
    long = fact("F-PSP", "WARN", "psp unknown in any list")
    text = R.render_pay(**pay_kwargs(facts=[long]))
    assert "PSP UNKNOWN IN AN~" in text.split("\n")


def test_fact_display_line_must_be_ascii():
    with pytest.raises(R.RenderError) as e:
        R.render_pay(**pay_kwargs(facts=[fact("F-VAT", line="ÚČET ZVEŘEJNĚN")]))
    assert e.value.code == "NON_ASCII"


def test_fact_order_v2():
    ids = [f.id for f in R.order_facts([fact("F-BANK"), fact("F-VAT"), fact("F-PSP"), fact("F-VOP"),
                                        fact("F-SANCTION"), fact("F-WARNLIST"), fact("F-ATTEST"),
                                        fact("F-ZZZ"), fact("H-AGENT", kind="H")])]
    assert ids == ["F-ATTEST", "F-WARNLIST", "F-SANCTION", "F-VOP", "F-PSP", "F-VAT", "F-BANK", "F-ZZZ"]


def test_fact_overflow_keeps_warns_and_counts():
    facts = [fact("F-BANK", line="BANK INFO"), fact("F-VAT", line="ADIS ACCT YES"), fact("F-VOP", line="VOP MTCH"),
             fact("F-PSP", "WARN", "PSP UNKNOWN"), fact("F-FIRSTSEEN", "WARN", "FIRST SEEN 2H")]
    text = R.render_pay(**pay_kwargs(facts=facts))
    page2 = assert_s11(text)[1]
    assert page2 == ["0 BLOCK 2 WARN", "PSP UNKNOWN", "FIRST SEEN 2H", "+3 MORE 0 BLOCK", "ROLE CLERK 1/1",
                     "N 0C55A1E7", "H 9b1e44c07a2d1f30"]


def test_no_facts_page2_is_short():
    text = R.render_pay(**pay_kwargs(facts=[]))
    assert assert_s11(text)[1] == ["0 BLOCK 0 WARN", "ROLE CLERK 1/1", "N 0C55A1E7", "H 9b1e44c07a2d1f30"]


def test_amount_whole_major_units():
    text = R.render_pay(**pay_kwargs(amount_minor=12500000))
    assert text.split("\n")[1] == "125000 CZK"


@pytest.mark.parametrize("bad", [1.5, -1, True, "100"])
def test_amount_must_be_int_minor(bad):
    with pytest.raises(R.RenderError):
        R.render_pay(**pay_kwargs(amount_minor=bad))


def test_times_are_prague_mmdd_hhmm():
    winter = R.render_pay(**pay_kwargs(exp="2026-12-01T13:20:00Z"))
    assert "EXP 12-01 14:20" in winter.split("\n")
    dt = datetime(2026, 10, 19, 13, 20, tzinfo=timezone.utc)
    assert R.render_pay(**pay_kwargs(exp=dt)) == PAY_GOLDEN
    with pytest.raises(R.RenderError):
        R.render_pay(**pay_kwargs(exp="2026-10-19T13:20:00"))  # naive


# ----------------------------------------------------------------- page-1 fill and overflow


def test_pay_without_vs_fills_page1_with_bank():
    text = R.render_pay(**pay_kwargs(vs=None))
    p1 = assert_s11(text)[0]
    assert p1[-2:] == ["EXP 10-19 15:20", "BANK 0800 CZ"]


def test_pay_lt_iban():
    text = R.render_pay(**pay_kwargs(iban=FRAUD_IBAN))
    p1 = assert_s11(text)[0]
    assert p1[2:4] == ["LT48 3999 0000", "0000 1234"]


def test_pay_34_char_iban_moves_exp_to_page2():
    text = R.render_pay(**pay_kwargs(iban=LONG_IBAN))
    p1, p2 = assert_s11(text)
    assert p1 == ["AG1/DEMO PAY 42", "12500.50 CZK", "LC14 BOSL 1234", "5678 9012 3456", "7890 1234 56",
                  "BETA SERVIS A.S.", "VS 2026101901"]
    assert p2[:2] == ["0 BLOCK 1 WARN", "EXP 10-19 15:20"]
    assert p2[-3:] == ["ROLE CLERK 1/1", "N 0C55A1E7", "H 9b1e44c07a2d1f30"]
    assert "".join(p1[2:5]).replace(" ", "") == LONG_IBAN  # IBAN in full


def test_chg_34_char_iban_keeps_break_rule():
    text = R.render_change(**chg_kwargs(new_iban=LONG_IBAN))
    p1, p2 = assert_s11(text)
    assert p1[3:] == ["NEW LC14 BOSL 1234", "    5678 9012 3456", "    7890 1234 56", "BANK BOSL LC"]
    # The carried OLD line yields its slot so the pinned ATT fact is never folded into "+N MORE".
    assert p2[1:3] == ["ATT 2/3 ERP BANK", "VOP CMTC"] and "OLD ..5399 2024-03" not in p2


def test_chg_lt_iban():
    p1 = assert_s11(R.render_change(**chg_kwargs(new_iban=FRAUD_IBAN)))[0]
    assert p1[4:] == ["NEW LT48 3999 0000", "    0000 1234", "BANK 39990 LT"]


def test_attest_34_char_iban_moves_from_to_page2():
    p1, p2 = assert_s11(R.render_vendor_attest(**attest_kwargs(iban=LONG_IBAN)))
    assert p1[-1] == "7890 1234 56"
    assert "FROM 2026-10-20" in p2


@pytest.mark.parametrize("name,line", [
    ("Dodavatel Servis s", "DODAVATEL SERVIS S"),          # 18 chars, fits
    ("Dodavatel Servis sro", "DODAVATEL SERVIS ~"),        # truncated with ~
    ("Řemeslná dílna Žďár", "REMESLNA DILNA ZD~"),         # transliterated, then truncated
    ("Straße & Søn", "STRASSE & SON"),
])
def test_names_uppercase_translit_truncate(name, line):
    text = R.render_pay(**pay_kwargs(payee_name=name))
    assert assert_s11(text)[0][4] == line


def test_name_that_cannot_be_transliterated_fails_closed():
    with pytest.raises(R.RenderError) as e:
        R.render_pay(**pay_kwargs(payee_name="ООО Ромашка"))
    assert e.value.code == "NON_ASCII"


def test_mandate_treasury_role_line_respects_page_break():
    p2 = assert_s11(R.render_mandate(**mandate_kwargs(role="treasury", sig_index=2)))[1]
    assert p2[0] == "REQ VOP MTCH"
    assert set(p2) >= {"ROLE TREASURY 2/2", "FROM 10-19 12:00", "PAYEES 12 REG V31"}


def test_attest_long_signer_line_respects_page_break():
    p2 = assert_s11(R.render_vendor_attest(**attest_kwargs(signer_role="accountant", role_basis="POA")))[1]
    assert p2[0] == "QUORUM 2/3 V5" and "SIGNER ACCT (POA)" in p2


def test_mandate_single_payment_noun():
    assert "MAX 1 PAYMENT" in R.render_mandate(**mandate_kwargs(max_count=1)).split("\n")


def test_enroll_and_reject_single_page():
    e = R.render_enroll(role="clerk", nonce="0C55A1E7")
    assert e == "AG1/DEMO ENROLL\nROLE CLERK\nN 0C55A1E7"
    r = R.render_chg_reject(change_no=7, nonce="1A2B3C4D", vendor_name="ACME s.r.o.", vendor_ico="12345678",
                            new_iban=FRAUD_IBAN, subject_hash=h64("0123456789abcdef"), profile=R.PROFILE_SAFE5)
    assert r == ("AG1/DEMO REJECT 7\nACME S.R.O.\nICO 12345678\nNEW ..1234\nROLE CLERK\nN 1A2B3C4D\n"
                 "H 0123456789abcdef")
    assert len(assert_s11(r)) == 1


# ----------------------------------------------------------------- negative goldens (S11 validator)


def test_negative_diacritics_rejected():
    with pytest.raises(R.RenderError) as e:
        R.check_text("AG1/DEMO PAY 1\nDODAVATEL ŘEMESLA", R.PROFILE_SAFE5)
    assert e.value.code == "NON_ASCII"


def test_negative_19_char_line_rejected():
    with pytest.raises(R.RenderError) as e:
        R.check_text("AG1/DEMO PAY 1\n" + "X" * 19, R.PROFILE_SAFE5)
    assert e.value.code == "WIDTH"


def test_negative_three_pages_rejected():
    with pytest.raises(R.RenderError) as e:
        R.check_text("\n".join(["AG1/DEMO PAY 1"] + ["LINE"] * 14), R.PROFILE_SAFE5)
    assert e.value.code == "PAGES"


def test_negative_long_line_at_page_break_rejected():
    text = "\n".join(["AG1/DEMO PAY 1"] + ["L"] * 5 + ["X" * 16] + ["N 0C55A1E7"])
    with pytest.raises(R.RenderError) as e:
        R.check_text(text, R.PROFILE_SAFE5)
    assert e.value.code == "PAGE_BREAK"


def test_negative_missing_tag_and_trailing_newline():
    with pytest.raises(R.RenderError):
        R.check_text("PAY 1\nX")
    with pytest.raises(R.RenderError):
        R.check_text("AG1/DEMO PAY 1\n")


# ----------------------------------------------------------------- profiles, width, hashes


def test_ui_preview_profile_is_wider_and_not_for_device():
    text = R.render_pay(**pay_kwargs(profile=R.PROFILE_UI))
    ls = text.split("\n")
    assert ls[2] == "CZ65 0800 0000 1920 0014 5399" and all(len(x) <= 32 for x in ls)
    with pytest.raises(R.RenderError):
        R.check_text(text)  # does not fit the device profile


def test_width_parameter():
    text = R.render_pay(**pay_kwargs(width=20))
    assert all(len(x) <= 20 for x in text.split("\n"))
    with pytest.raises(R.RenderError):
        R.render_pay(**pay_kwargs(width=17))
    with pytest.raises(R.RenderError):
        R.render_pay(**pay_kwargs(profile="nope"))


def test_subject_hash_deterministic_and_drives_h_line():
    params = {k: v for k, v in pay_kwargs().items() if k != "subject_hash"}
    subj = R.subject_object(deployment="DEMO", purpose="PAY", role="clerk", subject_id="prp_42",
                            nonce="0C55A1E7", params=params, facts_digest="ab" * 32, policy_hash="cd" * 32)
    sh = R.subject_hash(subj)
    assert len(sh) == 64 and sh == R.subject_hash(dict(subj))
    assert "nonce" not in subj["params"] and "subject_hash" not in subj["params"]
    text = R.render_pay(**pay_kwargs(subject_hash=sh))
    assert text.split("\n")[-1] == f"H {sh[:16]}"


def test_translit_table_hash_stable():
    assert len(R.translit_table_hash()) == 64
    assert R.display_name("ACME s.r.o.") == "ACME S.R.O."


def test_deterministic():
    assert R.render_pay(**pay_kwargs()) == R.render_pay(**pay_kwargs())
    assert R.text_sha256(PAY_GOLDEN) == R.text_sha256(R.render_pay(**pay_kwargs()))


# ----------------------------------------------------------------- S11 property test


_hex = st.text(alphabet="0123456789ABCDEF", min_size=8, max_size=8)
_name = st.text(alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x17F), min_size=1, max_size=40).filter(
    lambda s: s.strip() != "")
_line = st.text(alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E), min_size=1, max_size=30).filter(
    lambda s: s.strip() != "")
_fact = st.builds(lambda i, s, ln: fact(i, s, ln), st.sampled_from(R.FACT_ORDER), st.sampled_from(["INFO", "WARN"]),
                  _line)
_iban = st.sampled_from([ACME_IBAN, NEW_IBAN, FRAUD_IBAN, LONG_IBAN, "DE89370400440532013000",
                         "SK3112000000198742637541"])


@settings(max_examples=300, deadline=None)
@given(no=st.integers(1, 99999), nonce=_hex, name=_name, iban=_iban, amount=st.integers(0, 10**12),
       vs=st.one_of(st.none(), st.from_regex(r"^[0-9]{1,10}$", fullmatch=True)),
       facts=st.lists(_fact, max_size=8))
def test_s11_grid(no, nonce, name, iban, amount, vs, facts):
    """S11: every PAY/CHG the renderer accepts obeys the 18x7 grid; anything else raises RenderError."""
    try:
        text = R.render_pay(**pay_kwargs(proposal_no=no, nonce=nonce, payee_name=name, iban=iban,
                                         amount_minor=amount, vs=vs, facts=facts))
    except R.RenderError:
        return
    pages = assert_s11(text)
    assert len(pages[0]) == 7
    assert pages[1][0].startswith("0 BLOCK ")
    try:
        text = R.render_change(**chg_kwargs(change_no=no, nonce=nonce, vendor_name=name, new_iban=iban,
                                            facts=facts))
    except R.RenderError:
        return
    assert len(assert_s11(text)[0]) == 7
