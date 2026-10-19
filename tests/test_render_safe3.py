"""Tests for executor/render.py, default profile safe3-mono-16x4 (Trezor Safe 3; CONTRACTS §5, ARCHITECTURE §3.4).

The Safe 3 draws 18 mono columns x 4 lines per page, but its page-break glyphs take 2 columns on the last line of
a page and the first line of the next (H0, docs/device/measurements.md). Width 16 therefore makes reflow
impossible; only the title (line 1, never next to a break) may use 18. Byte goldens below = the CONTRACTS §5.2 screens.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import tests.test_render as T
from executor import render as R


def _d(helper, kw: dict[str, Any]) -> dict[str, Any]:
    """The safe5 kwargs helper minus its pinned profile (i.e. the default profile) unless one is passed."""
    base = helper(**kw)
    if "profile" not in kw:
        del base["profile"]
    return base


def pay_kwargs(**kw: Any) -> dict[str, Any]:
    return _d(T.pay_kwargs, kw)


def mandate_kwargs(**kw: Any) -> dict[str, Any]:
    return _d(T.mandate_kwargs, kw)


def chg_kwargs(**kw: Any) -> dict[str, Any]:
    return _d(T.chg_kwargs, kw)


def attest_kwargs(**kw: Any) -> dict[str, Any]:
    return _d(T.attest_kwargs, kw)


def assert_s11(text: str) -> list[list[str]]:
    """S11 on the Safe 3: ASCII + LF, title <= 18, every other line <= 16, <= 14 lines, pages of 4."""
    ls = text.split("\n")
    assert not text.endswith("\n")
    assert all(" " <= c <= "~" or c == "\n" for c in text)
    assert ls[0].startswith("AG1/") and len(ls[0]) <= 18
    assert all(1 <= len(line) <= 16 for line in ls[1:]), ls
    assert len(ls) <= 14
    pages = R.render_pages(text)
    assert pages == [ls[i : i + 4] for i in range(0, len(ls), 4)]
    return pages


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
    "H 9b1e44c07a2d1f"
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
    "PAYEES 12 V31\n"
    "N 91BC02E1\n"
    "P 1f3a9c0e7d2b4a\n"
    "H 3e0d9a1c55b2e7"
)
CHG_GOLDEN = (
    "AG1/DEMO CHG 7\n"
    "ACME S.R.O.\n"
    "ICO 12345678\n"
    "OLD ..5399 24-03\n"
    "NEW CZ62 0300\n"
    "    0000 0001\n"
    "    2345 6789\n"
    "0 BLOCK 1 WARN\n"
    "ATT 2/3 ERP BANK\n"
    "VOP CMTC\n"
    "COOLOFF DONE\n"
    "ROLE TREAS 2/2\n"
    "N 7C11A0E2\n"
    "H 4f2a9c1e0b7d3a"
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
    "H 5a0c7e19d3b4f2"
)


@pytest.mark.parametrize("fn,kw,golden,pages", [
    (R.render_pay, pay_kwargs(), PAY_GOLDEN, [4, 4, 4, 2]),
    (R.render_mandate, mandate_kwargs(), MANDATE_GOLDEN, [4, 4, 4, 2]),
    (R.render_change, chg_kwargs(), CHG_GOLDEN, [4, 4, 4, 2]),
    (R.render_vendor_attest, attest_kwargs(), ATTEST_GOLDEN, [4, 4, 4]),
])
def test_goldens(fn, kw, golden, pages):
    text = fn(**kw)
    assert text == golden
    assert [len(p) for p in assert_s11(text)] == pages


@pytest.mark.parametrize("template,kw,golden", [
    ("PAY", pay_kwargs(), PAY_GOLDEN),
    ("MANDATE", mandate_kwargs(), MANDATE_GOLDEN),
    ("CHG", chg_kwargs(), CHG_GOLDEN),
    ("VENDOR_ATTEST", attest_kwargs(), ATTEST_GOLDEN),
])
def test_rerender_from_params(template, kw, golden):
    assert R.render(template, kw) == golden
    assert R.render(template, kw, profile=R.PROFILE_SAFE3, deployment="DEMO") == golden


def test_profile_constants():
    p = R.PROFILES[R.PROFILE_SAFE3]
    assert R.DEFAULT_PROFILE == R.PROFILE_SAFE3 == "safe3-mono-16x4"
    assert (p.width, p.lines_per_page, p.max_pages, p.max_lines, p.break_line_max) == (16, 4, 4, 14, 16)
    assert (p.hash_hex, p.title_max, p.block_lines) == (14, 18, 7)
    assert (R.DEFAULT_WIDTH, R.LINES_PER_PAGE, R.MAX_PAGES, R.MAX_LINES, R.BREAK_LINE_MAX) == (16, 4, 4, 14, 16)
    assert R.MIN_WIDTH[R.PROFILE_SAFE3] == 16


def test_page1_is_what_the_money_does():
    """Device page 1 of a PAY: title, amount and the full payee IBAN."""
    assert R.render_pages(PAY_GOLDEN)[0] == ["AG1/DEMO PAY 42", "12500.50 CZK", "CZ65 0800 0000", "1920 0014 5399"]


def test_short_forms_only_when_needed():
    m = R.render_mandate(**mandate_kwargs(role="treasury", sig_index=2)).split("\n")
    assert "ROLE TREAS 2/2" in m and "PAYEES 12 V31" in m
    assert "ROLE TREASURY 2/2" in R.render_mandate(**mandate_kwargs(role="treasury", sig_index=2,
                                                                     profile=R.PROFILE_SAFE5)).split("\n")
    assert R.render_enroll(role="treasury", nonce="0C55A1E7") == "AG1/DEMO ENROLL\nROLE TREASURY\nN 0C55A1E7"
    a = R.render_vendor_attest(**attest_kwargs(signer_role="accountant", role_basis="POA")).split("\n")
    assert "SIGNER ACCT POA" in a


def test_title_may_use_18_columns():
    r = R.render_chg_reject(change_no=7, nonce="1A2B3C4D", vendor_name="ACME s.r.o.", vendor_ico="12345678",
                            new_iban=T.FRAUD_IBAN, subject_hash=T.h64("0123456789abcdef"))
    assert r == "AG1/DEMO REJECT 7\nACME S.R.O.\nICO 12345678\nNEW ..1234\nROLE CLERK\nN 1A2B3C4D\nH 0123456789abcd"
    assert R.render_pay(**pay_kwargs(proposal_no=12345)).split("\n")[0] == "AG1/DEMO PAY 12345"
    with pytest.raises(R.RenderError) as e:
        R.render_pay(**pay_kwargs(deployment="ABCDE", proposal_no=12345))  # 19
    assert e.value.code == "WIDTH"


def test_long_new_iban_gets_label_line():
    text = R.render_change(**chg_kwargs(new_iban=T.LONG_IBAN))
    pages = assert_s11(text)
    assert pages[0][-1] == "NEW IBAN"
    assert pages[1][:3] == ["LC14 BOSL 1234", "5678 9012 3456", "7890 1234 56"]


def test_long_payee_iban_carries_exp():
    pages = assert_s11(R.render_pay(**pay_kwargs(iban=T.LONG_IBAN)))
    assert pages[0][2:] == ["LC14 BOSL 1234", "5678 9012 3456"] and pages[1][0] == "7890 1234 56"


@pytest.mark.parametrize("name,line", [
    ("Dodavatel Servis s", "DODAVATEL SERVI~"),
    ("Beta Servis a.s.", "BETA SERVIS A.S."),
    ("Řemeslná dílna", "REMESLNA DILNA"),
])
def test_names_truncated_at_16(name, line):
    assert R.render_pay(**pay_kwargs(payee_name=name)).split("\n")[4] == line


def test_hash_lines_14_hex():
    sh = "ab" * 32
    text = R.render_pay(**pay_kwargs(subject_hash=sh))
    assert text.split("\n")[-1] == "H " + sh[:14]
    assert R.render_pay(**pay_kwargs(subject_hash=sh, profile=R.PROFILE_SAFE5)).split("\n")[-1] == "H " + sh[:16]


def test_hints_never_on_device():
    hint = T.fact("H-AGENT", line="agent: CFO approved", kind="H")
    assert R.render_pay(**pay_kwargs(facts=T.PAY_FACTS + [hint])) == PAY_GOLDEN


def test_amount_doc_fact_orders_after_dup():
    i = R.FACT_ORDER.index("F-DUP")
    assert R.FACT_ORDER[i + 1] == "F-AMOUNT-DOC"
    facts = [T.fact("F-SPLIT", "WARN", "SPLIT 24H"), T.fact("F-AMOUNT-DOC", line="AMOUNT OK DOC")]
    ls = R.render_pay(**pay_kwargs(facts=facts)).split("\n")
    assert ls.index("AMOUNT OK DOC") < ls.index("SPLIT 24H")
    with pytest.raises(R.RenderError) as e:
        R.render_pay(**pay_kwargs(facts=[T.fact("F-AMOUNT-DOC", "BLOCK", "AMOUNT != DOC")]))
    assert e.value.code == "R0_BLOCK"


_MANY = [T.fact("F-VOP", "WARN", "VOP CMTC"), T.fact("F-ATTEST", line="ATT 2/3 ERP BANK"),
         T.fact("F-PSP", "WARN", "PSP NO VOP"), T.fact("F-BANK", "WARN", "BANK FOREIGN EMI"),
         T.fact("F-FIRSTSEEN", "WARN", "IBAN NEW 5H")]


@pytest.mark.parametrize("iban", [T.NEW_IBAN, T.LONG_IBAN, T.FRAUD_IBAN])
@pytest.mark.parametrize("profile", [R.PROFILE_SAFE3, R.PROFILE_SAFE5])
def test_chg_attestation_is_pinned(iban, profile):
    """ATT k/3 is what the human confirms on a CHG: never folded into +N MORE, even behind 4 WARNs."""
    ls = R.render_change(**chg_kwargs(facts=_MANY, new_iban=iban, profile=profile)).split("\n")
    assert "ATT 2/3 ERP BANK" in ls and "+4 MORE 0 BLOCK" in ls and "0 BLOCK 4 WARN" in ls
    cb = [T.fact("F-CALLBACK", line="CALLBACK OK"), T.fact("F-ATTEST", line="ATT BREAK-GLASS")] + _MANY[2:]
    ls = R.render_change(**chg_kwargs(facts=cb, new_iban=iban, profile=profile)).split("\n")
    assert "ATT BREAK-GLASS" in ls and "0 BLOCK 3 WARN" in ls
    ls = R.render_change(**chg_kwargs(facts=cb[:2], new_iban=T.NEW_IBAN, profile=profile)).split("\n")
    assert "CALLBACK OK" in ls and "ATT BREAK-GLASS" in ls  # break-glass path, no overflow: both shown


def test_pay_overflow_unchanged_by_pinning():
    ls = R.render_pay(**pay_kwargs(facts=_MANY)).split("\n")
    assert "ATT 2/3 ERP BANK" not in ls and "+3 MORE 0 BLOCK" in ls


# ----------------------------------------------------------------- negative goldens (S11 validator, default profile)


def test_negative_17_char_body_line_rejected():
    with pytest.raises(R.RenderError) as e:
        R.check_text("AG1/DEMO PAY 1\n" + "X" * 17)
    assert e.value.code == "WIDTH"


def test_negative_19_char_title_rejected():
    with pytest.raises(R.RenderError) as e:
        R.check_text("AG1/DEMO PAY 12345" + "6")
    assert e.value.code == "WIDTH"


def test_negative_15_lines_rejected():
    with pytest.raises(R.RenderError) as e:
        R.check_text("\n".join(["AG1/DEMO PAY 1"] + ["LINE"] * 14))
    assert e.value.code == "PAGES"


def test_negative_diacritics_rejected():
    with pytest.raises(R.RenderError) as e:
        R.check_text("AG1/DEMO PAY 1\nDODAVATEL ŘEMESLA")
    assert e.value.code == "NON_ASCII"


def test_safe5_text_is_not_a_safe3_text():
    """An 18-col v2 golden must not pass the Safe 3 validator (it would reflow on the device)."""
    with pytest.raises(R.RenderError):
        R.check_text(T.CHG_GOLDEN)


# ----------------------------------------------------------------- S11 property test


@settings(max_examples=300, deadline=None)
@given(no=st.integers(1, 99999), nonce=T._hex, name=T._name, iban=T._iban, amount=st.integers(0, 10**12),
       vs=st.one_of(st.none(), st.from_regex(r"^[0-9]{1,10}$", fullmatch=True)),
       facts=st.lists(T._fact, max_size=8))
def test_s11_grid(no, nonce, name, iban, amount, vs, facts):
    """S11: every PAY/CHG the renderer accepts obeys the Safe 3 grid; anything else raises RenderError."""
    try:
        text = R.render_pay(**pay_kwargs(proposal_no=no, nonce=nonce, payee_name=name, iban=iban,
                                         amount_minor=amount, vs=vs, facts=facts))
    except R.RenderError:
        return
    ls = text.split("\n")
    assert_s11(text)
    assert ls[7].startswith("0 BLOCK ")
    try:
        text = R.render_change(**chg_kwargs(change_no=no, nonce=nonce, vendor_name=name, new_iban=iban,
                                            facts=facts))
    except R.RenderError:
        return
    assert_s11(text)
