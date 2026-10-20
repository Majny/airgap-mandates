"""executor.audit.explain: every audit event type explains; every attack is named as an ATTACK of the right kind; a
benign day is not; IBANs are masked and no secret material reaches a rendered line. Owner: orchestrator."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from attacker import attacks
from executor import e2e, scenes
from executor.audit import explain as X
from executor.models import AuditEventType
from tests.log_helpers import ATTACK_KINDS, leaves, run_attack, seeded

FIXTURES = Path(__file__).resolve().parents[1] / "contracts" / "fixtures" / "audit_events"


@pytest.fixture(autouse=True)
def _isolate_implant(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRGAP_IMPLANT_DIR", str(tmp_path / "implant"))
    yield


def _attack_explanations(env: scenes.DemoEnv, res: attacks.AttackResult, from_seq: int) -> list[X.Explained]:
    """What the ops log says about one attack: its new leaves, its refused requests, its telling responses."""
    out = [X.explain(le["event"], le["seq"]) for le in leaves(env, from_seq)]
    for r in res.requests:
        body = r.response if isinstance(r.response, dict) else {}
        if r.status >= 400:
            out.append(X.refusal(r.method, r.path, r.principal, r.status, body.get("error"), body.get("message")))
        else:
            out.append(X.response(r.method, r.path, r.principal, r.status, body))
    return [x for x in out if x is not None]


def test_every_fixture_and_event_type_explains():
    seen = set()
    for p in sorted(FIXTURES.glob("*.json")):
        ev = json.loads(p.read_text())
        for known in (None, X.known_from([{"vendor_id": "ven_12345678", "name": "ACME", "domain": "acme.cz",
                                          "iban": "CZ6508000000192000145399"}])):
            x = X.explain(ev, known=known)
            assert x is not None and x.level in X.LEVELS and x.title and x.kind, p.name
            assert x.seq == ev["seq"] and x.type == ev["type"]
        seen.add(ev["type"])
    assert seen == {t.value for t in AuditEventType}, "a fixture per event type"
    assert X.explain({"type": "witness_refusal", "data": {"status": 422}}).level == X.ATTACK
    assert X.explain({"type": "checkpoint", "data": {"size": 3}}).level == X.NOISE
    assert X.explain({"type": "nonsense", "data": "not a dict"}).level == X.INFO
    assert X.explain({"type": "decision", "data": {"inputs": "garbage", "decision": "deny"}}) is not None
    assert X.explain("not an event") is None  # type: ignore[arg-type]


@pytest.mark.parametrize("key", list(attacks.ATTACKS))
def test_each_attack_is_named(key: str):
    env, pending = seeded(with_scenes=False)
    start = len(leaves(env))
    res = run_attack(key, env, pending)
    xs = _attack_explanations(env, res, start)
    kinds = {x.kind for x in xs if x.level == X.ATTACK}
    assert ATTACK_KINDS[key] in kinds, (key, kinds, [x.text for x in xs])
    assert not [x for x in xs if x.level == X.ERROR], [x.text for x in xs if x.level == X.ERROR]


def test_incidents_for_the_console():
    env, pending = seeded()
    for key in attacks.ATTACKS:
        run_attack(key, env, pending)
    get = lambda path, k: env.call("GET", path, None, "host")[1][k]  # noqa: E731
    incs = X.incidents(leaves(env), get("/vendors", "vendors"), get("/changes", "changes"), get("/proposals", "proposals"))
    kinds = {i.kind for i in incs}
    for want in ("lookalike domain (BEC)", "mailbox takeover", "mailbox takeover?", "prompt injection",
                 "replayed approval", "forged approval", "fake attestation", "tampered approval (PC malware)",
                 "data exfiltration", "hijacked agent"):
        assert want in kinds, (want, kinds)
    seqs = [i.last_seq for i in incs if i.last_seq is not None]
    assert seqs == sorted(seqs, reverse=True)  # newest first
    bec = next(i for i in incs if i.kind == "lookalike domain (BEC)" and str(i.subject).startswith("prp_"))
    assert bec.who.get("sender_domain") == "acme-cz.com" and bec.how_stopped
    assert all(i.level == X.ATTACK for i in incs), "no money reached an attacker"
    d = incs[0].as_dict()
    assert d["steps"] and d["title"] and "how_stopped" in d


def test_benign_day_is_not_an_attack():
    env = scenes.DemoEnv()
    e2e.run(env.call, env.clerk, env.treasury, now=env.now, log=lambda s: None)
    xs = [X.explain(le["event"], le["seq"]) for le in leaves(env)]
    attacks_ = [x for x in xs if x.level == X.ATTACK]
    # the S1 beat ends with a deliberate replay of the step-up signature: that, and only that, is an attack
    assert [x.kind for x in attacks_] == ["replayed approval"], [x.text for x in attacks_]
    assert attacks_[0].seq == max(x.seq for x in xs if x.type == "signature")
    levels = {x.level for x in xs}
    assert {X.PAID, X.HUMAN, X.OK} <= levels and X.ERROR not in levels
    paid = [x for x in xs if x.level == X.PAID]
    assert len(paid) == 4 and all("…" in x.title for x in paid)


def test_iban_masking():
    assert X.mask_iban("CZ6508000000192000145399") == "CZ65 …5399"
    assert X.mask_iban("CZ65 0800 0000 1920 0014 5399") == "CZ65 …5399"
    assert X.mask_ibans("pay to LT483999000000001234 now") == "pay to LT48 …1234 now"
    ev = json.loads((FIXTURES / "execution.json").read_text())
    masked, full = X.explain(ev), X.explain(ev, full_iban=True)
    assert "CZ65 …5399" in masked.text and "CZ6508000000192000145399" not in json.dumps(masked.as_dict())
    assert "CZ65 0800 0000 1920 0014 5399" in full.text
    assert X.clean("a\x1b[31mred\nline‮") == "a [31mred line"


def test_no_secret_material_in_any_line():
    from vendor import portal

    env, pending = seeded()
    for key in attacks.ATTACKS:
        run_attack(key, env, pending)
    rows = leaves(env)
    get = lambda path, k: env.call("GET", path, None, "host")[1][k]  # noqa: E731
    xs = X.explain_all(rows, get("/vendors", "vendors"), get("/changes", "changes"), get("/proposals", "proposals"))
    text = "\n".join(json.dumps(x.as_dict(), ensure_ascii=False) for x in xs)
    plain = "\n".join(json.dumps(X.explain(le["event"], le["seq"]).as_dict(), ensure_ascii=False) for le in rows)
    secrets = set()
    for le in rows:
        d = le["event"].get("data") or {}
        for k in ("sig", "enroll_sig", "nonce_secret_sha256", "text_sha256", "commitment", "args_sha256"):
            if isinstance(d.get(k), str) and len(d[k]) > 20:
                secrets.add(d[k][2:30] if d[k].startswith("0x") else d[k][:28])
    secrets |= {m for msg in getattr(portal, "SMS_OUTBOX", []) for m in re.findall(r"Code (\d{6})", str(msg))}
    secrets.add("ZXlGb3JnZWQ.cGF5bG9hZA.c2ln")  # the forged VC body of the fake-portal attack
    assert secrets
    for s in secrets:
        assert s not in text and s not in plain, s
    assert attacks.FRAUD_IBAN not in plain and attacks.TAKEOVER_IBAN not in plain  # ops-log view: masked
    assert "LT48 …1234" in plain
    assert "\x1b" not in text


def test_resent_approval_after_expiry_is_a_replay():
    acc = {"type": "signature", "seq": 5, "data": {"nonce": "AB12CD34", "purpose": "PAY", "role": "clerk",
                                                   "accepted": True, "error": None, "sig": "0x" + "ab" * 65}}
    late = {"type": "signature", "seq": 9, "data": {**acc["data"], "accepted": False, "error": "expired"}}
    assert X.explain(late).level == X.BLOCKED  # alone: maybe just a slow clerk
    known = X.Known()
    X.explain(acc, known=known)
    x = X.explain(late, known=known)
    assert (x.level, x.kind, x.title) == (X.ATTACK, "replayed approval", "Replay of an old Trezor approval")
    assert x.rule_ids == ("expired",)


ODD_ROWS = [{"seq": 1, "event": "str"}, {"seq": 2, "event": {"type": "proposal", "data": ["x"]}},
            {"seq": 3, "event": {"type": "proposal", "data": {"invoice": "notadict", "hints": "x"}}},
            {"seq": "4", "event": {"type": "checkpoint"}}, {"seq": 9, "event": {"type": "anchor", "data": {}}},
            {"event": {"type": "decision", "data": {"inputs": {"facts": {"facts": ["s"]}}, "decision": "deny"}}},
            {"seq": True, "event": {"type": "signature", "data": {"error": 7}}}, "not a row", None]


def test_odd_and_partial_rows_never_raise():
    """incidents() runs for every console page (global banner): one odd leaf or change row must not take it down."""
    xs = X.explain_all(ODD_ROWS)
    assert xs and all(x.level in X.LEVELS for x in xs)
    assert X.incidents(ODD_ROWS) == []
    odd_changes = [{"change_id": "c", "state": "PENDING_ATTEST", "facts": ["x", None, {"id": "F-VOP"}]},
                   {"change_id": "d", "state": "PENDING_ATTEST", "facts": "nope"}, "row"]
    assert X.incidents([], changes=odd_changes) == []  # type: ignore[arg-type]
    assert X.change_risk(odd_changes[0]) is None and X.change_risk(odd_changes[1]) is None
    from host import story

    assert story.security({"leaves": ODD_ROWS})["n"] == 0
    assert story.event_log({"leaves": ODD_ROWS}, show="Everything")
    story.build({"leaves": ODD_ROWS}, [], [], [])


def test_bank_rejection_is_an_error_not_a_breach():
    """RJCT: the bank refused the order, no money moved. An ops-log ERROR, never a breach card or breach alert."""
    from host import alerts, story

    rows = [{"seq": 5, "event": {"type": "rail_submitted", "subject_id": "tx_1", "ts": "2026-10-20T09:00:00Z",
                                 "data": {"tx_id": "tx_1", "status": "RJCT"}}}]
    x = X.explain(rows[0]["event"], 5)
    assert x.level == X.ERROR and not X.is_breach(x) and "no money moved" in x.why
    assert X.incidents(rows) == []
    sec = story.security({"leaves": rows})
    assert sec["n"] == 0 and sec["attacker_minor"] == 0
    assert story.event_log({"leaves": rows}, show="Attacks only") == []
    assert alerts.alert_items(rows, [], [], []) == []


def test_non_hostile_block_on_a_change_is_not_an_attack():
    """F-VAT (unreliable VAT payer) rejects a change on arrival, but nobody lied to us: BLOCKED, no card, no alert."""
    from host import alerts, story

    rows = [{"seq": 7, "event": {"type": "state_transition", "subject_id": "chg_9", "ts": "2026-10-20T09:00:00Z",
                                 "data": {"change_id": "chg_9", "event": "CREATE", "from": None, "to": "REJECTED",
                                          "reason": "BLOCK at create: F-VAT"}}}]
    x = X.explain(rows[0]["event"], 7)
    assert (x.level, x.kind) == (X.BLOCKED, "account change refused") and "refused on arrival" in x.title
    hostile = X.explain({**rows[0]["event"], "data": {**rows[0]["event"]["data"],
                                                      "reason": "BLOCK at create: F-DOMAIN F-VAT"}})
    assert (hostile.level, hostile.kind) == (X.ATTACK, "lookalike domain (BEC)")
    assert story.security({"leaves": rows})["n"] == 0 and alerts.alert_items(rows, [], [], []) == []
    _, cards = story.build({"leaves": rows}, [], [], [])
    assert cards and cards[0]["tone"] == "info"


def test_warn_facts_in_rule_ids_do_not_make_an_attack():
    """rule_ids also carry WARN facts: an honest duplicate from a supplier whose VoP answer is a WARN (close match,
    scheme down) or with an F-ANOM WARN is bookkeeping, BLOCKED 'duplicate invoice', never an attack."""
    from host import alerts, story

    for warn in ("F-VOP", "F-ANOM"):
        ev = {"type": "decision", "subject_id": "prp_9", "ts": "2026-10-20T09:00:00Z",
              "data": {"decision": "deny", "rule_ids": ["F-DUP", warn, "I-BLOCK", "I-DUP"],
                       "inputs": {"subject": {"invoice": {"vendor_id": "ven_1", "amount_minor": 100}},
                                  "facts": {"facts": [{"id": "F-DUP", "kind": "F", "severity": "BLOCK",
                                                       "label": "Duplicate invoice"},
                                                      {"id": warn, "kind": "F", "severity": "WARN",
                                                       "label": "close match"}]}}}}
        x = X.explain(ev, 5)
        assert (x.level, x.kind) == (X.BLOCKED, "duplicate invoice"), warn
        rows = [{"seq": 5, "event": ev}]
        assert story.security({"leaves": rows})["n"] == 0 and alerts.alert_items(rows, [], [], []) == []
    nmtc = {**ev, "data": {**ev["data"], "rule_ids": ["F-VOP", "I-BLOCK"], "inputs": {"facts": {"facts": [
        {"id": "F-VOP", "kind": "F", "severity": "BLOCK", "label": "VoP no match"}]}}}}
    assert (X.explain(nmtc).level, X.explain(nmtc).kind) == (X.ATTACK, "payee name mismatch")


def test_lone_expired_approval_is_not_alerted():
    """Console and alerts agree: an expired approval alone (maybe a slow clerk) is not an attack."""
    from host import alerts, story

    rows = [{"seq": 6, "event": {"type": "signature", "subject_id": "prp_1", "ts": "2026-10-20T09:00:00Z",
                                 "data": {"accepted": False, "error": "expired", "role": "clerk", "purpose": "PAY",
                                          "nonce": "AB", "signer_address": "0x" + "1" * 40}}}]
    assert X.explain(rows[0]["event"]).level == X.BLOCKED
    assert alerts.alert_items(rows, [], [], []) == [] and story.security({"leaves": rows})["n"] == 0
    _, cards = story.build({"leaves": rows}, [], [], [])
    assert all(c["tone"] != "attack" for c in cards)


def test_every_error_code_reads_in_words():
    from executor.errors import ERROR_CODES

    for code in ERROR_CODES:
        for who in ("host", "agent"):
            x = X.refusal("POST", "/changes/chg_1/attestations", who, 500 if code == "internal_error" else 400,
                          code, "detail")
            assert x.level in X.LEVELS and x.title and x.kind, code
            if code != "internal_error":
                assert not re.search(r"\b[a-z]+_[a-z_]+\b", x.title.replace("chg_1", "")), (code, x.title)


def test_validation_messages_never_echo_values():
    """A jsonschema message repeats the offending value (a callback code, a signature, a VC): only the field path
    and the kind of error reach the line."""
    sig, vc = "0x" + "ab" * 65, "eyJhbGciOiJFUzI1NiJ9.eyJpYmFuIjoiQ1oyMCJ9.c2ln~WyJzYWx0Il0~"
    cases = [("code: 739215 is not of type 'string'", "code: wrong type"),
             ("code: '739215 ' does not match '^[0-9]{6}$'", "code: bad format"),
             (f"sig: ['{sig}'] is not of type 'string'", "sig: wrong type"),
             (f"vc: '{vc}\\n' does not match '^[A-Za-z0-9_.~-]+$'", "vc: bad format"),
             ("body: Additional properties are not allowed ('iban' was unexpected)", "body: unknown field 'iban'")]
    for raw, want in cases:
        x = X.refusal("POST", "/callbacks/chg_1", "vendor_portal", 400, "invalid_request", raw)
        assert want in x.text, (raw, x.text)
        assert "739215" not in x.text and "abab" not in x.text and "eyJ" not in x.text
    assert X.refusal("POST", "/proposals", "tools", 400, "invalid_request",
                     "invoice: Additional properties are not allowed ('iban' was unexpected)").kind == "IBAN injection"
    # an executor sentence that merely mentions an IBAN is not IBAN smuggling
    assert X.refusal("POST", "/changes", "tools", 400, "invalid_request",
                     "new_iban is already the active IBAN").level == X.BLOCKED
    assert "eyJ" not in X.clean(f"x {vc} y") and "abab" not in X.clean(f"sig {sig}")


@pytest.mark.parametrize("level", ["H2", "H3", "H4", "H5"])
def test_bench_hardware_attacks_are_named(level: str, caplog):
    """Bench H2-H5 (PC malware, moved / forged approvals, stolen agent credentials) each give an ATTACK line."""
    import logging

    from bench import scripted
    from executor import oplog

    caplog.set_level(logging.INFO, logger="airgap")
    try:
        r = scripted._a3(level, 0, "diligent")
    finally:
        oplog.LOGGER.propagate = True
    assert not r["attack_success"] and r["money_moved_minor"] == 0
    kinds = {getattr(rec, "airgap", {}).get("kind") for rec in caplog.records
             if getattr(rec, "airgap", {}).get("level") == "ATTACK"}
    assert kinds & {"tampered approval (PC malware)", "forged approval", "stolen agent credentials"}, (level, kinds)


def test_names_and_targets_from_data_in_hand():
    """Without the console's GET /vendors, the explainer names the supplier from the decision facts and the payment
    an approval attack went for from its challenge."""
    env, pending = seeded()
    run_attack("forged_approval", env, pending)
    known = X.Known()
    xs = [X.explain(le["event"], le["seq"], known=known) for le in leaves(env)]
    blocked = next(x for x in xs if x.type == "decision" and x.level == X.ATTACK)
    assert blocked.title.startswith("Payment blocked: ACME s.r.o. · ") and "ven_" not in blocked.title
    forged = [x for x in xs if x.kind == "forged approval"]
    assert forged and all(" · " in x.title and x.money_minor for x in forged), [x.title for x in forged]
    paid = next(x for x in xs if x.level == X.PAID)
    assert "ven_" not in paid.title


def test_payment_from_an_attack_is_flagged_while_it_waits():
    env, pending = seeded()
    run_attack("invoice_injection", env, pending)
    known = X.Known()
    xs = [X.explain(le["event"], le["seq"], known=known) for le in leaves(env)]
    inj = next(x for x in xs if x.kind == "prompt injection")
    linked = [x for x in xs if x.level == X.HUMAN and x.subject == inj.subject]
    assert linked and all(x.title.startswith("⚠ Linked to an attack (prompt injection") for x in linked)
    assert all("check it with the supplier" in x.why for x in linked)


def test_plain_words_not_codes():
    assert "does not match the supplier" in X.plain_fact({"id": "F-VOP", "label": "Verification of Payee: NMTC"})
    assert "absent != safe" not in X.plain_fact({"id": "F-PSP", "label": "bank code 39990 LT not listed "
                                                                       "(absent != safe)"})
    x = X.explain({"type": "change_event", "subject_id": "chg_1",
                   "data": {"change_id": "chg_1", "event": "vc_rejected", "detail": {"error": "vc_invalid"}}})
    assert "digital signature is not valid" in x.why
    s = X.clean("pay this invoice to LT483999000000001234 now please " * 3, 60, full_iban=True)
    assert "LT48 3999 0000 0000 1234" in s and s.endswith("…")
    assert X.clean("aaaa LT483999000000001234 bbbb", 12) == "aaaa…"  # never cut inside an IBAN


def test_every_attack_has_threat_layer_and_evidence():
    """Track 3: every attack in attacker/attacks.py reads back from the bank's log (attacks.bank_log: audit export,
    explain, the request-level ring) with the expected threat class and defence layer, concrete evidence, and 0 CZK
    moved. Attack h's lines arrive when the clerk signs the swapped payment."""
    from tests.log_helpers import ATTACK_THREATS

    env, pending = seeded()
    for key, (threat, layer) in ATTACK_THREATS.items():
        res = run_attack(key, env, pending)
        lines = res.bank_log if key != "clerk_pc_malware" else attacks.bank_log(env.call, res.bank_mark)
        hits = [d for d in lines if d["level"] == X.ATTACK and d["threat"] == threat and d["layer"] == layer]
        assert hits, (key, [(d["level"], d["threat"], d["layer"]) for d in lines])
        assert all(d["evidence"] and d["threat"] in X.THREATS and d["layer"] in X.LAYERS
                   for d in lines if d["level"] == X.ATTACK), key
        assert all("0 CZK moved" in d["headline"] for d in lines if d["level"] == X.ATTACK), key
        assert all(d["headline"].startswith(d["threat"] + " · ") for d in lines if d["level"] == X.ATTACK), key


def test_brief_vocabulary_for_tools_egress_and_iam():
    """Decoy / taint -> PROMPT INJECTION, mail rules and egress -> DATA EXFILTRATION, IAM and caller allowlist ->
    PRIVILEGE ESCALATION, each with its layer and evidence (fixtures and request refusals)."""
    def tool(rules, tool="mandate.write"):
        return X.explain({"type": "tool_call", "subject_id": "ses_1", "data": {"tool": tool, "result": "forbidden",
                                                                              "rule_ids": rules}}, 66)

    x = tool(["T-DECOY"])
    assert (x.threat, x.layer) == (X.PI, X.L_PERM) and x.evidence.startswith("T-DECOY:") and "mandate.write" in x.evidence
    assert x.headline.startswith("PROMPT INJECTION · Hijacked agent tried to raise its own spending limit → stopped "
                                 "by permission scoping: T-DECOY") and x.headline.endswith("· 0 CZK moved")
    assert (tool(["T-TAINT"]).threat, tool(["T-TAINT"]).layer) == (X.PI, X.L_ANOM)
    assert tool(["T-MAIL-ALLOWLIST"], "mail.send_template").threat == X.DE
    eg = X.explain(json.loads((FIXTURES / "egress_block.json").read_text()))
    assert (eg.threat, eg.layer) == (X.DE, X.L_EGRESS) and "exfil@evil.example" in eg.evidence
    iam = X.explain({**json.loads((FIXTURES / "iam_deny_mirror.json").read_text()),
                     "data": {**json.loads((FIXTURES / "iam_deny_mirror.json").read_text())["data"], "source": "boto3"}})
    assert (iam.threat, iam.layer) == (X.PE, X.L_PERM) and iam.evidence.startswith("IAM explicitDeny")
    w = X.explain(json.loads((FIXTURES / "witness_refusal.json").read_text()))
    assert (w.threat, w.layer) == (X.LT, X.L_TLOG)
    r = X.refusal("POST", "/signatures", "agent", 403, "caller_not_allowed", "no")
    assert (r.threat, r.layer) == (X.PE, X.L_PERM) and "POST /signatures" in r.evidence
    b = X.refusal("POST", "/signatures", "host", 403, "sigs_insufficient", "x")
    assert b.level == X.BLOCKED and not b.threat and b.layer == X.L_HW and "→ stopped by" in b.headline
    op = X.refusal("POST", "/proposals", "tools", 409, "state_conflict", "x")  # operational, no defence layer
    assert op.level == X.BLOCKED and not op.layer and "stopped by" not in op.headline


def test_deny_without_facts_never_calls_a_warn_fact_an_attack():
    """Issue 1: a decision leaf without its facts: F-VOP / F-ANOM in rule_ids may be a mere WARN, so an honest
    duplicate stays BLOCKED; a fact that is BLOCK whenever present (F-DOMAIN) is still an attack."""
    assert X._deny_kind(["F-DUP", "F-VOP", "I-BLOCK", "I-DUP"], []) == (X.BLOCKED, "duplicate invoice")
    assert X._deny_kind(["F-DUP", "F-ANOM", "I-BLOCK", "I-DUP"], []) == (X.BLOCKED, "duplicate invoice")
    assert X._deny_kind(["F-DOMAIN", "F-AMOUNT-DOC", "I-BLOCK"], []) == (X.ATTACK, "lookalike domain (BEC)")
