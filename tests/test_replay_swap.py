"""Security invariant tests (CONTRACTS.md v2 §8.2). Owner: WS-A."""
from tests.wsa_helpers import Harness


def _pay_challenge(h: Harness) -> dict:
    h.mandate()
    st, r = h.propose(12_500_050, vendor="ven_87654321")
    assert st == 201 and r["decision"]["decision"] == "challenge", r
    return r["decision"]["challenge"]


def test_s1_no_sig_403():
    h = Harness()
    ch = _pay_challenge(h)
    for sig in ("", "0x", "0x" + "00" * 65, "not-a-sig"):
        st, r = h.call("POST", "/signatures", {"nonce": ch["nonce"], "role": "clerk", "sig": sig}, "host")
        assert st in (400, 403), (sig, r)
    st, r = h.submit(ch, h.stranger)  # well-formed but not enrolled
    assert (st, r["error"]) == (403, "unknown_signer")
    st, r = h.submit(ch, h.treasury, role="clerk")  # enrolled, wrong role
    assert (st, r["error"]) == (403, "unknown_signer")
    assert h.store.scan("ledger") == []  # 0 money moved; the mandate was never used
    assert h.call("GET", f"/proposals/{ch['subject_id']}")[1]["status"] == "PENDING_SIG"


def test_s2_render_mismatch():
    h = Harness()
    ch = _pay_challenge(h)
    lie = "AG1/DEMO PAY 42\n125.00 CZK\nACME OK\nVOP OK"
    st, r = h.submit(ch, h.clerk, text=lie, displayed_text=lie)
    assert (st, r["error"]) == (403, "render_mismatch")
    assert r["details"]["expected_sha256"] == ch["text_sha256"]
    assert h.store.get("nonces", {"nonce": ch["nonce"]})["used"] is False  # not consumed
    # signing the host's lie without claiming it: recovery over the executor text yields a different address
    st, r = h.submit(ch, h.clerk, text=lie)
    assert (st, r["error"]) == (403, "unknown_signer")
    rejected = [e for e in h.leaves() if e["type"] == "signature" and not e["data"]["accepted"]]
    assert [e["data"]["error"] for e in rejected] == ["render_mismatch", "unknown_signer"]
    st, r = h.submit(ch, h.clerk)  # the real text still works
    assert st == 200 and r["effect"]["type"] == "payment_executed"


def test_s5_replay():
    h = Harness()
    ch = _pay_challenge(h)
    assert h.submit(ch, h.clerk)[0] == 200
    st, r = h.submit(ch, h.clerk)
    assert (st, r["error"]) == (403, "nonce_reused")
    txs = h.store.scan("ledger")
    assert len(txs) == 1 and txs[0]["authorization"]["kind"] == "stepup"


def test_s5_expired():
    h = Harness()
    ch = _pay_challenge(h)
    h2 = Harness(fake_now="2026-10-19T12:05:00Z")  # exp = created + 300 s
    h2.store, h2.ctx.store = h.store, h.store
    st, r = h2.submit(ch, h.clerk)
    assert (st, r["error"]) == (403, "expired")
    assert h.store.scan("ledger") == []


def test_s5_swap():
    h = Harness()
    h.mandate()
    _, a = h.propose(12_500_050, vendor="ven_87654321", no="A-1")
    _, b = h.propose(9_000_000, vendor="ven_12345678", no="B-1")
    ca, cb = a["decision"]["challenge"], b["decision"]["challenge"]
    st, r = h.submit(cb, h.clerk, text=ca["text"])  # signature over A presented with B's nonce
    assert (st, r["error"]) == (403, "unknown_signer")
    st, r = h.submit(ca, h.clerk, nonce=cb["nonce"], text=ca["text"])
    assert (st, r["error"]) == (403, "unknown_signer")
    assert h.store.scan("ledger") == []
    # nonce binds deployment/purpose/subject: the subject hash differs per challenge
    assert ca["subject_hash"] != cb["subject_hash"] and ca["nonce"] != cb["nonce"]


def test_signer_without_enroll_leaf_is_refused():
    """Online "enrolled before used": a row written without its enroll leaf (or pointing at another leaf) is not an
    enrolled signer, even if active for the role."""
    from eth_account import Account

    h = Harness()
    ch = _pay_challenge(h)
    ghost = Account.create()
    h.store.put("enrolled_signers", {"address": ghost.address.lower(), "role": "clerk", "device": "GENUINE",
                                     "active": True})  # no enroll_seq, no leaf
    st, r = h.submit(ch, ghost)
    assert (st, r["error"]) == (403, "unknown_signer")
    other_seq = h.store.get("enrolled_signers", {"address": h.clerk.address.lower()})["enroll_seq"]
    h.store.put("enrolled_signers", {"address": ghost.address.lower(), "role": "clerk", "device": "GENUINE",
                                     "active": True, "enroll_seq": other_seq})  # borrows the clerk's leaf
    st, r = h.submit(ch, ghost)
    assert (st, r["error"]) == (403, "unknown_signer")
    assert h.store.scan("ledger") == []
    st, r = h.submit(ch, h.clerk)  # properly enrolled (row + leaf in one transaction)
    assert st == 200 and r["effect"]["type"] == "payment_executed"


def test_deactivated_signer_is_refused_and_can_be_reenrolled():
    """Deactivation = a new enroll leaf with active=false; the online check reads the row's enroll_seq leaf."""
    import json

    from executor.store import seed, signers

    h = Harness()
    ch = _pay_challenge(h)
    leaves = [e for e in h.leaves() if e["type"] == "enroll"]
    assert leaves and all(e["data"]["active"] is True for e in leaves)
    seq = signers.deactivate(h.store, h.clerk.address, settings=h.settings)
    leaf = json.loads(h.store.get("audit", {"log_id": "audit", "seq": seq})["event"])
    assert leaf["type"] == "enroll" and leaf["data"]["active"] is False
    st, r = h.submit(ch, h.clerk)
    assert (st, r["error"]) == (403, "unknown_signer")
    # a row claiming active=true but pointing at the active=false leaf is still refused (the leaf is authoritative)
    row = h.store.get("enrolled_signers", {"address": h.clerk.address.lower()})
    h.store.put("enrolled_signers", {**row, "active": True})
    assert h.submit(ch, h.clerk)[1]["error"] == "unknown_signer"
    seed.enroll_signer(h.store, h.clerk.address, "clerk", device="GENUINE", settings=h.settings)  # re-enrol
    st, r = h.submit(ch, h.clerk)
    assert st == 200 and r["effect"]["type"] == "payment_executed"
