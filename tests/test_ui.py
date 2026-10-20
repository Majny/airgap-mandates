"""Host UI smoke tests (headless Streamlit AppTest). Owner: WS-F."""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

from host import ui  # noqa: E402

UI_PATH = str(Path(ui.__file__).resolve())


def _run(monkeypatch: pytest.MonkeyPatch, trezor_path: str = "") -> AppTest:
    monkeypatch.setenv("AIRGAP_EXECUTOR_URL", "http://127.0.0.1:9")  # unreachable: every tab must degrade, not crash
    monkeypatch.setenv("AIRGAP_TREZOR_PATH", trezor_path)
    return AppTest.from_file(UI_PATH, default_timeout=30).run()


def test_ui_renders_without_executor(monkeypatch: pytest.MonkeyPatch):
    at = _run(monkeypatch)
    assert not at.exception
    assert any("LOCAL" in m.value for m in at.markdown)
    assert not any("FALLBACK: EMULATOR CLERK" in m.value for m in at.markdown)


def test_ui_emulator_fallback_banner(monkeypatch: pytest.MonkeyPatch):
    at = _run(monkeypatch, "udp:127.0.0.1:21324")
    assert any("FALLBACK: EMULATOR CLERK" in m.value for m in at.markdown)


def test_device_labels_from_enroll_leaves():
    bundle = {"leaves": [{"seq": 0, "event": {"type": "enroll", "data": {"address": "0xAbC", "device": "GENUINE"}}},
                         {"seq": 1, "event": {"type": "enroll", "data": {"address": "0xdef", "device": "EMULATOR"}}}]}
    assert ui.device_labels(bundle) == {"0xabc": "GENUINE", "0xdef": "EMULATOR"}


def test_story_of_the_scenes_in_plain_words():
    """The Overview feed over a normal day, the lookalike BEC with agent escalation and the mailbox takeover."""
    from executor import e2e, scenes
    from host import story

    env = scenes.DemoEnv()
    e2e.run(env.call, env.clerk, env.treasury, now=env.now, log=lambda s: None)
    scenes.scene_s2(env, log=lambda s: None)
    scenes.scene_s3(env, log=lambda s: None)
    get = lambda path, key, who="host": env.call("GET", path, None, who)[1][key]  # noqa: E731
    bundle = env.call("GET", "/audit/export?log_id=audit&from_seq=0", None, "auditor")[1]
    kpis, cards = story.build(bundle, get("/vendors", "vendors"), get("/changes", "changes"),
                              get("/proposals", "proposals"))
    titles = " | ".join(c["title"] for c in cards)
    assert kpis["attacker_minor"] == 0 and kpis["paid_n"] == 5 and kpis["auto_n"] == 3
    for t in ("Paid automatically", "Needs a human", "Account-change attack stopped", "Mailbox takeover stopped",
              "Replay attack stopped", "Forged approval stopped", "Hijacked agent", "New account active"):
        assert t in titles, t
    assert kpis["attacks"] == sum(c["tone"] == "attack" for c in cards)
    assert cards[0]["seq"] > cards[-1]["seq"]  # newest first
    assert "embedded_reference" not in " ".join(c["body"] for c in cards)


def test_ui_renders_on_seeded_memory_executor(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AIRGAP_EXECUTOR_URL", "memory:")
    monkeypatch.setenv("AIRGAP_UI_REFRESH_S", "0")
    at = AppTest.from_file(UI_PATH, default_timeout=60).run()
    assert not at.exception
    assert [m.value for m in at.metric][1] == "0.00 CZK"  # paid to unregistered accounts
    assert [t.label for t in at.tabs][:2] == ["Overview", "Security"]
    page = " ".join(m.value for m in at.markdown)
    # freshly seeded: every attack is the replayed demo backdrop, so no "Under attack" banner and 0 attacks stopped
    assert "Under attack:" not in page and [m.value for m in at.metric][2] == "0"
    assert "No live attacks" in page and "Demo backdrop:" in page and "not counted above" in page
    assert "DEMO BACKDROP (seeded scene)" in page and "ATTACK STOPPED" not in page
    assert "Who / from where" in page and "How it was stopped" in page
    assert "Event log" in page and '<table class="evlog">' in page


def test_expired_sign_in_is_named_not_shown_as_unreachable():
    assert ui._login_expired({"message": "The security token included in the request is expired"})
    assert ui._login_expired({"error": "unreachable",
                              "message": "TokenRetrievalError: Error when retrieving token from sso: Token has expired"})
    assert not ui._login_expired({"error": "unreachable", "message": "ConnectError: connection refused"})
    assert not ui._login_expired("text")


def test_assumed_role_credentials_are_reassumed_before_expiry(monkeypatch: pytest.MonkeyPatch):
    """A console left open longer than the 1 h STS session must not start failing with 'token expired'."""
    from datetime import datetime, timedelta, timezone

    from infra import aws_e2e

    issued: list[datetime] = []

    class Sts:
        def get_caller_identity(self):
            return {"Account": "503002144042"}

        def assume_role(self, **kw):
            exp = datetime.now(timezone.utc) + (timedelta(minutes=2) if not issued else timedelta(hours=1))
            issued.append(exp)
            return {"Credentials": {"AccessKeyId": f"AK{len(issued)}", "SecretAccessKey": "s", "SessionToken": "t",
                                    "Expiration": exp}}

    monkeypatch.setattr(aws_e2e.boto3, "client", lambda *a, **k: Sts())
    monkeypatch.setattr(aws_e2e, "_creds", {})
    assert aws_e2e.role_creds("host").access_key == "AK1"  # expires in 2 min: inside the 5 min margin
    assert aws_e2e.role_creds("host").access_key == "AK2"  # so it is re-assumed
    assert aws_e2e.role_creds("host").access_key == "AK2"  # and the fresh one is reused


def test_challenge_countdown(monkeypatch: pytest.MonkeyPatch):
    from datetime import datetime, timedelta, timezone

    monkeypatch.setattr(ui, "EXECUTOR", "https://example.execute-api.eu-central-1.amazonaws.com/prod")
    soon = (datetime.now(timezone.utc) + timedelta(seconds=130)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert 125 <= ui.expires_in({"exp": soon}) <= 130
    assert ui.expires_in({"exp": "2026-01-01T00:00:00Z"}) == 0
    assert ui.expires_in({}) is None
    monkeypatch.setattr(ui, "EXECUTOR", "memory:")  # seeded executor: fixed past clock, no countdown
    assert ui.expires_in({"exp": soon}) is None
    monkeypatch.setattr(ui, "EXECUTOR", "http://127.0.0.1:8000")  # tools/local_stack: same fixed clock
    assert ui.expires_in({"exp": "2026-01-01T00:00:00Z"}) is None


@pytest.fixture(scope="module")
def attacked() -> dict:
    """Seeded executor (S2, S3, a waiting Delta payment) after every attack in attacker/attacks.py."""
    from tests import log_helpers

    from tools.local_stack import audit_next_seq

    env, pending = log_helpers.seeded()
    seed = audit_next_seq(env.call)
    log_helpers.run_all(env, pending)
    get = lambda path, key: env.call("GET", path, None, "host")[1][key]  # noqa: E731
    return {"seed_seq": seed, "bundle": env.call("GET", "/audit/export?log_id=audit&from_seq=0", None, "auditor")[1],
            "vendors": get("/vendors", "vendors"), "changes": get("/changes", "changes"),
            "proposals": get("/proposals?limit=200", "proposals")}


def test_security_cards_tell_a_bank_person_what_happened(attacked: dict):
    """One card per attack: the kind in plain words, who / from where, what they tried, how it was stopped, money
    moved and the audit seq. Every attack that leaves an audit entry has its card (stolen agent credentials is
    refused at the door: only the ops log has it)."""
    from host import story
    from tests.log_helpers import ATTACK_KINDS

    sec = story.security(attacked["bundle"], attacked["vendors"], attacked["changes"], attacked["proposals"])
    cards = sec["incidents"]
    assert sec["n"] == len(cards) >= 10 and sec["attacker_minor"] == 0
    kinds = {c["kind"] for c in cards}
    for key, kind in ATTACK_KINDS.items():
        if key != "stolen_agent_creds":
            assert kind in kinds, (key, kind)
    for c in cards:
        assert c["headline"].startswith(("Attack stopped: ", "Suspected attack, on hold: ",
                                         "Attack blocked, payment still waiting: ")), c["headline"]
        assert not c["breach"]
        assert c["what"] and c["who"] and c["tried"] and c["stopped"] and c["seqs"], c
        assert c["moved_minor"] == 0
    maxes = [max(c["seqs"]) for c in cards]
    assert maxes == sorted(maxes, reverse=True)  # newest first
    assert sec["latest"] is cards[0]
    bec = next(c for c in cards if c["kind"] == "lookalike domain (BEC)" and str(c["subject"]).startswith("prp_"))
    assert "acme-cz.com" in bec["who"][0] and "lookalike of the real supplier domain acme.cz" in bec["who"][0]
    assert ("Amount", "48 900.00 CZK") in bec["facts"] and "F-DOMAIN" in bec["stopped"][-1][1]
    malware = next(c for c in cards if c["kind"] == "tampered approval (PC malware)")
    assert "Delta Stavby" in malware["tried"] and "render_mismatch" in malware["stopped"][0][1]
    held = next(c for c in cards if c["kind"] == "mailbox takeover?")
    assert held["held"] and any(k == "Account they wanted" for k, _ in held["facts"])
    inj = next(c for c in cards if c["kind"] == "prompt injection")
    assert any(k == "Account they wanted" and v.startswith("LT48") for k, v in inj["facts"])
    # the injected invoice is still waiting for a clerk: the card says so, and the Payments row is tagged
    assert inj["waiting"] and "still waits in Payments" in inj["next"] and "Beta Servis" in inj["next"]
    assert inj["headline"].startswith("Attack blocked, payment still waiting")
    assert story.linked(sec)[inj["subject"]] is inj
    page = ui.incident_html(inj)
    assert "Your next step" in page and "PAYMENT STILL WAITING" in page


def test_demo_backdrop_is_marked_and_not_counted(attacked: dict):
    """The seeded S2/S3 attacks (the ops log's [demo replay]) are grey DEMO BACKDROP cards, left out of the banner,
    the "Attacks stopped" KPI and the kind chips; the live attacks stay red. Advice never calls a payment genuine."""
    from host import story

    args = (attacked["bundle"], attacked["vendors"], attacked["changes"], attacked["proposals"])
    seed = attacked["seed_seq"]
    every, sec = story.security(*args), story.security(*args, seed_seq=seed)
    demo = [c for c in sec["incidents"] if c["backdrop"]]
    assert demo and sec["backdrop_n"] == len(demo) and sec["n"] + len(demo) == every["n"]
    assert all(max(c["seqs"]) < seed for c in demo) and sec["latest"] and not sec["latest"]["backdrop"]
    assert sum(sec["kinds"].values()) == sec["n"] and "mailbox takeover" not in sec["kinds"]  # S3's: seeded only
    page = ui.incident_html(demo[0])
    assert "DEMO BACKDROP (seeded scene)" in page and "ATTACK STOPPED" not in page
    assert "DEMO BACKDROP" not in ui.incident_html(next(c for c in sec["incidents"] if not c["backdrop"]))
    assert "[demo replay]" in ui.event_log_html(story.event_log(attacked["bundle"], show="Everything"), seed)
    for c in sec["incidents"]:
        assert "genuine" not in c["next"], c["next"]
    malware = next(c for c in sec["incidents"] if c["kind"] == "tampered approval (PC malware)")
    if malware["next"]:
        assert "off the network" in malware["next"] and "Trezor" in malware["next"]


def test_local_stack_serves_the_seed_boundary():
    from fastapi.testclient import TestClient

    from tools import local_stack

    env, _ = __import__("tests.log_helpers", fromlist=["seeded"]).seeded(with_scenes=False)
    app = local_stack.build_app(env.settings, env.store, seed={"seed_seq": 7, "scene": "S2+S3"})
    r = TestClient(app).get(local_stack.SEED_PATH)
    assert r.status_code == 200 and r.json() == {"seed_seq": 7, "scene": "S2+S3"}


def test_incident_card_html_escapes_attacker_text():
    """Sender domains, invoice numbers and agent hints are attacker-controlled: the card must not render them as HTML."""
    from host import story

    vendors = [{"vendor_id": "ven_1", "name": "ACME s.r.o.", "domain": "acme.cz", "iban": "CZ6508000000192000145399"}]
    evil = "acme-cz.com<img src=x onerror=alert(1)>"
    leaves = [
        {"seq": 0, "event": {"type": "ingest", "subject_id": "eml_1", "ts": "2026-10-20T09:00:00Z",
                             "data": {"email_id": "eml_1", "from_domain": evil}}},
        {"seq": 1, "event": {"type": "proposal", "subject_id": "prp_1", "ts": "2026-10-20T09:00:01Z",
                             "data": {"invoice": {"vendor_id": "ven_1", "invoice_no": "<b>X</b>", "amount_minor": 100,
                                                  "email_id": "eml_1"}, "hints": []}}},
        {"seq": 2, "event": {"type": "decision", "subject_id": "prp_1", "ts": "2026-10-20T09:00:02Z",
                             "data": {"subject_id": "prp_1", "decision": "deny", "rule_ids": ["I-BLOCK"],
                                      "inputs": {"invoice": {"vendor_id": "ven_1", "amount_minor": 100,
                                                             "invoice_no": "<b>X</b>"},
                                                 "facts": {"facts": [{"id": "F-DOMAIN", "kind": "F", "severity":
                                                                      "BLOCK", "label": "lookalike"}]}}}}}]
    sec = story.security({"leaves": leaves}, vendors, [], [])
    assert sec["n"] == 1
    page = ui.incident_html(sec["incidents"][0])
    assert "<img" not in page and "<b>X</b>" not in page and "&lt;img" in page


def test_event_log_filters_and_order(attacked: dict):
    from host import story

    args = (attacked["bundle"], attacked["vendors"], attacked["changes"], attacked["proposals"])
    attacks = story.event_log(*args, show="Attacks only")
    normal = story.event_log(*args)
    everything = story.event_log(*args, show="Everything")
    assert attacks and {x.level for x in attacks} <= {"ATTACK", "ERROR"}
    assert "NOISE" not in {x.level for x in normal} and "NOISE" in {x.level for x in everything}
    assert len(attacks) < len(normal) < len(everything) == len(attacked["bundle"]["leaves"])
    assert [x.seq for x in everything] == sorted((x.seq for x in everything), reverse=True)  # newest first
    titles = " | ".join(x.title for x in attacks)
    for t in ("Tampered approval for the payment", "Forged approval for the payment", "Replay of an old Trezor approval",
              "Fake supplier attestation"):
        assert t in titles, t
    html = ui.event_log_html(attacks)
    assert html.count("<tr") == len(attacks) and "🛑 ATTACK" in html


def test_auditor_security_view_reads_the_log_alone(attacked: dict):
    """Auditors get no vendor master or proposals: the Security tab still finds the attacks in the leaves."""
    from host import story

    sec = story.security(attacked["bundle"])
    kinds = {c["kind"] for c in sec["incidents"]}
    assert {"forged approval", "replayed approval", "tampered approval (PC malware)", "fake attestation",
            "data exfiltration", "prompt injection"} <= kinds


def test_security_tab_projector_layout_and_request_level_cards():
    """Issue 3/5/6: request-level attacks (no audit leaf) become live cards; the summary row counts per threat group;
    the newest card names threat, layer, evidence and the proof; older ones are one-liners; advice never vouches for
    a payment and always sends the operator to the registered contact and the Trezor screen."""
    from executor import oplog
    from host import story
    from tests import log_helpers
    from tools.local_stack import audit_next_seq

    env, pending = log_helpers.seeded()
    seed, n0 = audit_next_seq(env.call), max((d["n"] for d in oplog.recent()), default=0)
    log_helpers.run_all(env, pending)
    get = lambda path, key: env.call("GET", path, None, "host")[1][key]  # noqa: E731
    bundle = env.call("GET", "/audit/export?log_id=audit&from_seq=0", None, "auditor")[1]
    sec = story.security(bundle, get("/vendors", "vendors"), get("/changes", "changes"),
                         get("/proposals?limit=200", "proposals"), seed_seq=seed, refusals=oplog.recent(n0))
    live = [c for c in sec["incidents"] if not c["backdrop"]]
    door = [c for c in live if c["request_level"]]
    assert {c["kind"] for c in door} >= {"stolen agent credentials", "IBAN injection"}
    assert sum(sec["groups"].values()) == sec["n"] == len(live) and sec["groups"]["privilege escalation"] >= 3
    assert all(c["threat"] and c["layer"] and c["evidence"] for c in live), [c["kind"] for c in live]
    orders = [c["order"] for c in sec["incidents"]]
    assert orders == sorted(orders, reverse=True)
    top = ui.incident_html(live[0], steps=1)
    assert live[0]["kind"] == "tampered approval (PC malware)" and "HOST TAMPERING" in top
    assert "hardware signature" in top and "render_mismatch" in top and "Deterministic" in top
    assert "tools.verify_audit" in top  # signature card: re-verified offline (policy hash only on decision cards)
    line = ui.incident_line_html(door[0])
    assert line.startswith('<details class="incl"') and "PRIVILEGE ESCALATION" in line and "no audit entry" in line
    summary = ui.security_summary_html(sec)
    assert "prompt injection" in summary and "moved to attackers" in summary and "0.00 CZK" in summary
    for c in sec["incidents"]:
        assert "genuine" not in c["next"] and "passed every check" not in c["next"], c["next"]
        if c["next"]:
            assert "vendor master" in c["next"], c["next"]
        if c["next"] and c["kind"] in ("tampered approval (PC malware)", "forged approval", "replayed approval"):
            assert "Trezor screen" in c["next"] and "only truth" in c["next"], c["next"]
