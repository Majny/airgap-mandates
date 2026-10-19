"""Red-team findings (in-memory DemoEnv). Each test asserts the invariant that SHOULD hold; they failed on main@97668a6 and pass after the fixes (I-DUP by document, FX outside the mandate, strict pattern anchoring)."""
from executor import scenes
from executor.docs import extract


def _cited(env, no, amount, currency="CZK"):
    return scenes.cited(env, {"vendor_id": scenes.ACME, "invoice_no": no, "issue_date": "2026-10-10",
                              "amount_minor": amount, "currency": currency, "vs": "7777", "reason_code": "DUE"})


def test_f1_mandate_cap_ignores_invoice_currency():
    """A CZK mandate must not autopay an EUR invoice as if EUR minor units were CZK minor units."""
    env = scenes.DemoEnv()
    env.active_mandate()  # CZK, max_per_payment 80 000.00 CZK
    inv = _cited(env, "FV-2026-8888", 7_900_000, "EUR")  # 79 000.00 EUR
    st, r = env.call("POST", "/proposals", {"invoice": inv, "hints": []}, "tools")
    assert st == 201
    assert r["decision"]["decision"] != "allow", "EUR invoice autopaid under a CZK-denominated mandate"


def test_f2_same_document_paid_twice_via_invoice_no_reference():
    """I-DUP: one source document (same invoice_ref) must not execute twice under the mandate."""
    env = scenes.DemoEnv()
    env.active_mandate()
    no = "ACME-2026-7777"  # non-plain number: the document matcher also accepts its inv_ reference
    inv = _cited(env, no, 1_450_000)
    st, r = env.call("POST", "/proposals", {"invoice": inv, "hints": []}, "tools")
    assert r["decision"]["decision"] == "allow"
    again = {**inv, "invoice_no": extract.invoice_no_ref(no), "issue_date": "2026-10-01"}
    st, r = env.call("POST", "/proposals", {"invoice": again, "hints": []}, "tools")
    assert r["decision"]["decision"] != "allow", "same document executed a second time"
    assert len(env.store.scan("ledger")) == 1


def test_f3_change_iban_with_trailing_newline_is_rejected():
    """CONTRACTS conventions: IBAN is uppercase electronic format; a trailing newline must be a 400."""
    env = scenes.DemoEnv()
    current = env.store.get("registry", {"vendor_id": scenes.ACME})["iban"]
    st, r = env.call("POST", "/changes", {"vendor_id": scenes.ACME, "new_iban": current + "\n",
                                          "email_id": scenes.LEGIT_CHANGE_EMAIL, "hints": []}, "tools")
    assert st == 400, f"non-canonical IBAN accepted ({st}); bypasses the 'already the active IBAN' guard"
