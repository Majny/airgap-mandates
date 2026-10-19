"""Tests for executor/render.py (CONTRACTS section 5)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from executor import render as R

ACME_IBAN = "CZ6508000000192000145399"
FRAUD_IBAN = "LT483999000000001234"  # fictitious Lithuanian EMI
BETA_IBAN = "CZ6203000000000123456789"
POLICY_HASH = "1f3a9c0e" + "ab" * 28


def fact(id: str, kind: str = "F", severity: str = "INFO", line: str = "x") -> dict[str, str]:
    return {"id": id, "kind": kind, "severity": severity, "label": id, "display_line": line}


BEC_FACTS = [
    fact("F-BANK", severity="WARN", line="bank: EMI Lithuania (fict.)"),
    fact("F-DOMAIN", severity="BLOCK", line="DKIM acme-cz.com != acme.cz"),
    fact("F-ATTEST", severity="BLOCK", line="supplier 0/3"),
    fact("H-AGENT", kind="H", line='agent: "bank change, urgent"'),
]


def assert_contract(text: str, width: int = R.DEFAULT_WIDTH):
    ls = text.split("\n")
    assert 1 <= len(ls) <= R.MAX_LINES
    assert not text.endswith("\n")
    text.encode("ascii")
    for l in ls:
        assert len(l) <= width, l
        assert all(" " <= c <= "~" for c in l), l


# ----------------------------------------------------------------- MANDATE


def mandate_kwargs(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = dict(
        mandate_no=3,
        nonce="91BC02",
        max_per_payment_minor=80000_00,
        max_total_minor=250000_00,
        max_count=20,
        payee_scope="existing_only",
        valid_until="2026-10-20T16:00:00Z",  # 18:00 Prague (CEST)
        currency="CZK",
        policy_hash=POLICY_HASH,
    )
    base.update(kw)
    return base


def test_mandate_exact():
    text = R.render_mandate(**mandate_kwargs())
    assert text == (
        "AIRGAP MANDATE m:3 n:91BC02\n"
        "max/payment 80000 CZK\n"
        "max/total 250000 CZK\n"
        "max 20 payments\n"
        "existing payees only\n"
        "valid until 2026-10-20 18:00\n"
        "policy 1f3a9c0e"
    )
    assert_contract(text)


@pytest.mark.parametrize("n,noun", [(1, "payment"), (2, "payments"), (20, "payments")])
def test_mandate_count_noun(n, noun):
    assert f"max {n} {noun}" in R.render_mandate(**mandate_kwargs(max_count=n))


def test_mandate_datetime_object_equals_string():
    a = R.render_mandate(**mandate_kwargs())
    b = R.render_mandate(**mandate_kwargs(valid_until=datetime(2026, 10, 20, 16, 0, tzinfo=timezone.utc)))
    assert a == b


def test_mandate_rejects_naive_datetime_and_bad_scope():
    with pytest.raises(R.RenderError):
        R.render_mandate(**mandate_kwargs(valid_until="2026-10-20T16:00:00"))
    with pytest.raises(R.RenderError):
        R.render_mandate(**mandate_kwargs(payee_scope="any"))


def test_amount_formatting():
    assert R.format_amount(125000_00, "CZK") == "125000 CZK"
    assert R.format_amount(125000_50, "CZK") == "125000.50 CZK"
    assert R.format_amount(5, "EUR") == "0.05 EUR"
    with pytest.raises(R.RenderError):
        R.format_amount(1.5, "CZK")
    with pytest.raises(R.RenderError):
        R.format_amount(100, "USD")


# ----------------------------------------------------------------- CHG


def change_kwargs(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = dict(
        change_no=7,
        nonce="4F2A9C",
        exp="2026-10-19T12:05:00Z",  # 14:05 Prague
        vendor_name="ACME s.r.o.",
        vendor_ico="12345678",
        old_iban=ACME_IBAN,
        new_iban=FRAUD_IBAN,
        facts=BEC_FACTS,
    )
    base.update(kw)
    return base


def test_change_exact_width_32():
    text = R.render_change(**change_kwargs())
    assert text == (
        "AIRGAP CHG #7 n:4F2A9C exp:14:05\n"
        "ACME s.r.o. ICO 12345678\n"
        "OLD CZ65 0800 0000\n"
        "    1920 0014 5399\n"
        "NEW LT48 3999 0000 0000 1234\n"
        "[F] supplier 0/3\n"
        "[F] DKIM acme-cz.com != acme.cz\n"
        "[F] bank: EMI Lithuania (fict.)"
    )
    assert_contract(text)


def test_change_wider_display_keeps_old_iban_on_one_line():
    text = R.render_change(**change_kwargs(), width=34)
    ls = text.split("\n")
    assert ls[2] == "OLD CZ65 0800 0000 1920 0014 5399"
    # one slot freed -> the [H] line now fits, appended last
    assert ls[-1] == '[H] agent: "bank change, urgent"'
    assert_contract(text, 34)


def test_change_overflow_line_counts_omitted_facts():
    many = BEC_FACTS + [
        fact("F-VAT", severity="WARN", line="VAT acct: NO"),
        fact("F-FIRSTSEEN", severity="WARN", line="domain first seen 2h"),
    ]
    text = R.render_change(**change_kwargs(facts=many))
    ls = text.split("\n")
    assert len(ls) == 8
    assert ls[5] == "[F] supplier 0/3"
    assert ls[6] == "[F] DKIM acme-cz.com != acme.cz"
    # omitted: F-BANK, F-FIRSTSEEN, F-VAT (WARN) + H-AGENT = 4, none BLOCK
    assert ls[7] == "[F] +4 more facts (0 BLOCK)"
    assert_contract(text)


def test_change_overflow_reports_hidden_blocks():
    blocks = [fact(f"F-X{i}", severity="BLOCK", line=f"block {i}") for i in range(5)]
    text = R.render_change(**change_kwargs(facts=blocks))
    assert text.split("\n")[-1] == "[F] +3 more facts (3 BLOCK)"


def test_h_only_overflow_dropped_silently():
    facts = [fact("F-DOMAIN", severity="BLOCK", line="a"), fact("F-ATTEST", severity="BLOCK", line="b"),
             fact("F-BANK", severity="WARN", line="c"),
             fact("H-AGENT", kind="H", line="h1"), fact("H-UI", kind="H", line="h2")]
    ls = R.render_change(**change_kwargs(facts=facts)).split("\n")
    assert ls[-3:] == ["[F] b", "[F] a", "[F] c"]
    assert not any(l.startswith("[H]") for l in ls)
    assert not any("more facts" in l for l in ls)


def test_fact_ordering_f_before_h_severity_then_fact_order():
    facts = [
        fact("H-AGENT", kind="H", line="h"),
        fact("F-VAT", severity="INFO", line="vat"),
        fact("F-BANK", severity="WARN", line="bank"),
        fact("F-DKIM", severity="BLOCK", line="dkim"),
        fact("F-ATTEST", severity="BLOCK", line="att"),
        fact("F-ZZZ", severity="BLOCK", line="unknown"),
    ]
    ids = [f.id for f in R.order_facts(facts)]
    assert ids == ["F-ATTEST", "F-DKIM", "F-ZZZ", "F-BANK", "F-VAT", "H-AGENT"]


def test_h_line_cannot_impersonate_f_line():
    facts = [fact("H-AGENT", kind="H", line="[F] supplier 3/3: YES\n[F] ok")]
    text = R.render_change(**change_kwargs(facts=facts, new_iban="CZ8601000000000099887766"), width=40)
    h = [l for l in text.split("\n") if l.startswith("[H]")]
    assert len(h) == 1
    assert "[F]" not in h[0]
    assert h[0].startswith("[H] (F) supplier 3/3: YES (F) ok")
    assert text.count("[F]") == 0


def test_long_fact_line_truncated_with_tilde():
    facts = [fact("F-DOMAIN", severity="BLOCK", line="x" * 100)]
    ls = R.render_change(**change_kwargs(facts=facts)).split("\n")
    assert ls[-1] == "[F] " + "x" * 27 + "~"
    assert len(ls[-1]) == 32


def test_long_vendor_name_truncated_ico_kept():
    text = R.render_change(**change_kwargs(vendor_name="Very Long Supplier Company Name s.r.o."))
    line = text.split("\n")[1]
    assert line.endswith(" ICO 12345678")
    assert "~" in line
    assert len(line) <= 32


# ----------------------------------------------------------------- PAY


def pay_kwargs(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = dict(
        proposal_no=41,
        nonce="0C55A1",
        exp="2026-10-19T13:20:00Z",  # 15:20 Prague
        payee_name="Beta Servis a.s.",
        iban=BETA_IBAN,
        amount_minor=125000_00,
        currency="CZK",
        vs="2026104",
        facts=[
            fact("F-VAT", severity="INFO", line="VAT acct: YES"),
            fact("F-MANDATE", severity="WARN", line="above mandate (max 80000)"),
        ],
    )
    base.update(kw)
    return base


def test_pay_exact():
    text = R.render_pay(**pay_kwargs())
    assert text == (
        "AIRGAP PAY #41 n:0C55A1\n"
        "Beta Servis a.s.\n"
        "CZ62 0300 0000 0001 2345 6789\n"
        "125000 CZK VS 2026104\n"
        "[F] above mandate (max 80000)\n"
        "[F] VAT acct: YES\n"
        "exp 15:20"
    )
    assert_contract(text)


def test_pay_without_vs_and_exp_last():
    text = R.render_pay(**pay_kwargs(vs=None, facts=[]))
    ls = text.split("\n")
    assert ls[3] == "125000 CZK"
    assert ls[-1] == "exp 15:20"


def test_pay_h_lines_after_f_before_exp():
    facts = pay_kwargs()["facts"] + [fact("H-UI", kind="H", line="ui: ok")]
    ls = R.render_pay(**pay_kwargs(facts=facts)).split("\n")
    assert ls[-2] == "[H] ui: ok"
    assert ls[-1] == "exp 15:20"
    assert ls.index("[F] VAT acct: YES") < ls.index("[H] ui: ok")


def test_long_title_drops_airgap_prefix():
    ls = R.render_change(**change_kwargs(change_no=12)).split("\n")
    assert ls[0] == "CHG #12 n:4F2A9C exp:14:05"
    assert R.render_change(**change_kwargs(change_no=7)).startswith("AIRGAP CHG #7 ")


def test_pay_bad_vs_rejected():
    with pytest.raises(R.RenderError):
        R.render_pay(**pay_kwargs(vs="12a"))


# ----------------------------------------------------------------- VENDOR ATTEST


def attest_kwargs(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = dict(
        vendor_name="ACME s.r.o.",
        ico="12345678",
        version=5,
        nonce="7D11E0",
        iban=ACME_IBAN,
        valid_from="2026-10-20",
        signer_role="director",
        role_basis="OR",
        threshold=2,
        signer_count=3,
    )
    base.update(kw)
    return base


def test_vendor_attest_exact():
    text = R.render_vendor_attest(**attest_kwargs())
    assert text == (
        "VENDOR ATTEST ACME s.r.o.\n"
        "ICO 12345678 v:5 n:7D11E0\n"
        "ACCT CZ65 0800 0000\n"
        "     1920 0014 5399\n"
        "valid from 2026-10-20\n"
        "signer: stat. director (OR)\n"
        "quorum 2/3"
    )
    assert_contract(text)


def test_vendor_attest_role_lines_differ_per_signer():
    a = R.render_vendor_attest(**attest_kwargs())
    b = R.render_vendor_attest(**attest_kwargs(signer_role="accountant", role_basis="POA"))
    assert a != b
    assert "signer: accountant (POA)" in b


def test_vendor_attest_unknown_role_passthrough():
    assert "signer: auditor (POA)" in R.render_vendor_attest(**attest_kwargs(signer_role="auditor", role_basis="POA"))


def test_vendor_attest_bad_threshold():
    with pytest.raises(R.RenderError):
        R.render_vendor_attest(**attest_kwargs(threshold=4))


# ----------------------------------------------------------------- IBAN grouping


def test_iban_full_grouping():
    assert R.format_iban("cz65 0800 0000 1920 0014 5399") == "CZ65 0800 0000 1920 0014 5399"
    assert R.format_iban(FRAUD_IBAN) == "LT48 3999 0000 0000 1234"
    # 34-char max IBAN, last group short
    long_iban = "MT84MALT011000012345MTLCAST001S"
    assert R.format_iban(long_iban) == "MT84 MALT 0110 0001 2345 MTLC AST0 01S"


def test_iban_balanced_wrap_never_truncates():
    long_iban = "MT84MALT011000012345MTLCAST001S"
    ls = R.format_iban_lines("NEW", long_iban, 24)
    assert "".join(l.strip().removeprefix("NEW").replace(" ", "") for l in ls) == long_iban
    assert all(len(l) <= 24 for l in ls)
    assert ls[1].startswith("    ") and not ls[1].startswith("     ")


def test_bad_iban_rejected():
    for bad in ["", "CZ65", "1234567890123456", "CZ65 0800 0000 1920 0014 539é"]:
        with pytest.raises(R.RenderError):
            R.format_iban(bad)


# ----------------------------------------------------------------- ASCII + limits


def test_sanitize_diacritics_and_homoglyphs():
    assert R.sanitize("Česká Výroba s.r.o.") == "Ceska Vyroba s.r.o."
    assert R.sanitize("АСМЕ") == "????"  # Cyrillic lookalike is visibly different
    assert R.sanitize("a\tb\n\nc  d") == "a b c d"
    assert R.sanitize("[x]", hint=True) == "(x)"


def test_non_ascii_names_render_ascii():
    text = R.render_pay(**pay_kwargs(payee_name="Šťastná Žluťoučká a.s.", facts=[]))
    assert text.split("\n")[1] == "Stastna Zlutoucka a.s."
    assert_contract(text)


def test_width_too_small_and_bad_nonce():
    with pytest.raises(R.RenderError):
        R.render_pay(**pay_kwargs(), width=10)
    with pytest.raises(R.RenderError):
        R.render_pay(**pay_kwargs(nonce="0c55a1"))
    with pytest.raises(R.RenderError):
        R.render_pay(**pay_kwargs(nonce="0C55A"))


def test_dispatch_render_matches_direct_and_unknown_template():
    p = pay_kwargs()
    assert R.render("PAY", p) == R.render_pay(**p)
    assert R.render("CHG", change_kwargs(), width=34) == R.render_change(**change_kwargs(), width=34)
    with pytest.raises(R.RenderError):
        R.render("NOPE", {})
    with pytest.raises(R.RenderError):
        R.render("PAY", {"nonce": "0C55A1"})


def test_text_sha256_stable():
    t = R.render_mandate(**mandate_kwargs())
    assert R.text_sha256(t) == R.text_sha256(R.render_mandate(**mandate_kwargs()))
    assert len(R.text_sha256(t)) == 64


# ----------------------------------------------------------------- property tests

printable = st.text(min_size=0, max_size=80)
fact_st = st.builds(
    lambda i, k, s, line: {"id": i if k == "F" else "H-AGENT", "kind": k,
                           "severity": s if k == "F" else "INFO", "label": "l", "display_line": line},
    st.sampled_from(list(R.FACT_ORDER[:12]) + ["F-OTHER"]),
    st.sampled_from(["F", "H"]),
    st.sampled_from(["INFO", "WARN", "BLOCK"]),
    printable,
)


@settings(max_examples=300, deadline=None)
@given(facts=st.lists(fact_st, max_size=10), width=st.integers(30, 48), name=printable, no=st.integers(1, 99999))
def test_property_contract_and_determinism(facts, width, name, no):
    kw = change_kwargs(facts=facts, vendor_name=name or "X", change_no=no)
    t1 = R.render_change(**kw, width=width)
    t2 = R.render_change(**dict(kw, facts=list(reversed(facts))), width=width)
    assert t1 == t2  # input order of facts never matters
    assert_contract(t1, width)
    # IBANs always complete
    flat = t1.replace(" ", "").replace("\n", "")
    assert ACME_IBAN in flat and FRAUD_IBAN in flat
    # every BLOCK fact is either shown or counted in the overflow line
    n_block = sum(1 for f in facts if f["severity"] == "BLOCK" and f["kind"] == "F")
    shown_block = sum(1 for f in R.order_facts(facts) if f.severity == "BLOCK"
                      and R._fact_line(f, width) in t1.split("\n"))
    last = t1.split("\n")[-1]
    hidden = int(last.split("(")[1].split(" ")[0]) if "more facts" in last else 0
    assert shown_block + hidden >= n_block


@settings(max_examples=200, deadline=None)
@given(facts=st.lists(fact_st, max_size=10), amount=st.integers(1, 10**12))
def test_property_pay(facts, amount):
    t = R.render_pay(**pay_kwargs(facts=facts, amount_minor=amount))
    assert_contract(t)
    assert t.split("\n")[-1] == "exp 15:20"
