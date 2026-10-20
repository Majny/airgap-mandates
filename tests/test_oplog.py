"""executor.oplog: the ops log over scenes S2/S3 and every attack names each attack in one readable ATTACK line; a 500
logs its traceback under the error_id the response carries; a logging failure never breaks dispatch; JSON lines
parse; unconfigured (tests, libraries) it prints nothing. Owner: orchestrator."""
from __future__ import annotations

import io
import json
import logging

import pytest

from attacker import attacks
from executor import oplog
from executor.audit import explain as X
from tests.log_helpers import ATTACK_KINDS, run_attack, seeded


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("AIRGAP_IMPLANT_DIR", str(tmp_path / "implant"))
    monkeypatch.delenv("AIRGAP_LOG_FORMAT", raising=False)
    monkeypatch.delenv("AIRGAP_LOG_LEVEL", raising=False)
    yield
    for h in list(oplog.LOGGER.handlers):  # undo configure(): back to the quiet library default
        if getattr(h, oplog._MARK, False):
            oplog.LOGGER.removeHandler(h)
    oplog.LOGGER.propagate = True
    oplog.LOGGER.setLevel(logging.NOTSET)


def _lines(recs: list[logging.LogRecord], level: str | None = None) -> list[dict]:
    out = [getattr(r, "airgap", {}) for r in recs if r.name == "airgap"]
    return [a for a in out if level is None or a.get("level") == level]


def test_every_attack_has_a_readable_attack_line(caplog):
    caplog.set_level(logging.DEBUG, logger="airgap")
    env, pending = seeded()
    scene = _lines(caplog.records, "ATTACK")
    kinds = {a["kind"] for a in scene}
    assert {"lookalike domain (BEC)", "mailbox takeover", "replayed approval", "forged approval",
            "hijacked agent", "data exfiltration"} <= kinds, kinds
    fmt = oplog.TextFormatter()
    for key in attacks.ATTACKS:
        caplog.clear()
        res = run_attack(key, env, pending)
        assert res.blocked and res.money_to_attacker_minor == 0
        recs = [r for r in caplog.records if getattr(r, "airgap", {}).get("level") == "ATTACK"]
        assert ATTACK_KINDS[key] in {r.airgap["kind"] for r in recs}, (key, [r.getMessage() for r in recs])
        for r in recs:
            line = fmt.format(r)
            assert line.split(" ", 1)[1].startswith("🛑 ATTACK  ") and " — " in line and "| " in line, line
            assert "\n" not in line and r.levelno == logging.WARNING
            assert attacks.FRAUD_IBAN not in line and attacks.TAKEOVER_IBAN not in line
        if key == "stolen_agent_creds":  # request-only refusals: no audit leaf, still an ATTACK line
            ref = [r.airgap for r in recs if r.airgap.get("status") == 403 and r.airgap.get("seq") is None]
            assert ref and all(a["principal"] in ("agent", "tools") for a in ref), [r.airgap for r in recs]
    # every line of the run carried a request id; refusals already told by a leaf line are not repeated at INFO+
    assert all(a.get("req") for a in _lines(caplog.records))


def test_benign_requests_are_quiet_at_info(caplog):
    caplog.set_level(logging.INFO, logger="airgap")
    env, _ = seeded(with_scenes=False)
    levels = {a["level"] for a in _lines(caplog.records)}
    assert "ATTACK" not in levels and "ERROR" not in levels
    assert {"HUMAN", "OK"} <= levels
    assert not [r for r in caplog.records if r.levelno < logging.INFO]


def test_500_logs_traceback_with_the_error_id(caplog, monkeypatch):
    caplog.set_level(logging.INFO, logger="airgap")
    env, _ = seeded(with_scenes=False)

    def boom(table):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(env.store, "scan", boom)
    st, body = env.call("GET", "/vendors", None, "host")
    assert st == 500 and body["error"] == "internal_error" and body["message"] == "RuntimeError"
    eid = body["details"]["error_id"]
    assert eid.startswith("err_")
    errs = [r for r in caplog.records if getattr(r, "airgap", {}).get("level") == "ERROR"]
    assert len(errs) == 1 and errs[0].airgap["error_id"] == eid and errs[0].exc_info
    text = oplog.TextFormatter().format(errs[0])
    assert "Traceback" in text and "disk on fire" in text and f"error_id={eid}" in text and "GET /vendors" in text


def test_logging_failure_never_breaks_dispatch(monkeypatch):
    env, _ = seeded(with_scenes=False)

    def broken(*a, **k):
        raise ValueError("explainer broken")

    oplog.configure(stream=io.StringIO())
    monkeypatch.setattr(X, "explain", broken)
    monkeypatch.setattr(X, "refusal", broken)
    monkeypatch.setattr(X, "response", broken)
    monkeypatch.setattr(oplog.LOGGER, "log", broken)
    st, r = env.call("POST", "/signatures", {"nonce": "00000000", "role": "clerk", "sig": "0x" + "00" * 65}, "agent")
    assert (st, r["error"]) == (403, "caller_not_allowed")
    st, r = env.call("GET", "/vendors", None, "host")
    assert st == 200 and r["vendors"]
    res = run_attack("replay_approval", env, None)
    assert res.blocked


def test_json_format_parses(monkeypatch):
    buf = io.StringIO()
    monkeypatch.setenv("AIRGAP_LOG_FORMAT", "json")
    oplog.configure(stream=buf)
    oplog.configure(stream=buf)  # idempotent: one handler, one line per event
    env, pending = seeded(with_scenes=False)
    run_attack("forged_approval", env, pending)
    run_attack("stolen_agent_creds", env, pending)
    rows = [json.loads(ln) for ln in buf.getvalue().splitlines() if ln.strip()]
    assert rows and all({"ts", "level", "title", "logger"} <= set(r) for r in rows)
    assert len([h for h in oplog.LOGGER.handlers if getattr(h, oplog._MARK, False)]) == 1
    forged = [r for r in rows if r.get("kind") == "forged approval"]
    assert forged and forged[0]["level"] == "ATTACK" and isinstance(forged[0]["seq"], int) and forged[0]["req"]
    assert any(r.get("kind") == "stolen agent credentials" and r.get("status") == 403 for r in rows)
    # Track 3 fields for CloudWatch Logs Insights: threat, layer, evidence, money moved
    assert forged[0]["threat"] == "REPLAY / FORGERY" and forged[0]["layer"] == "hardware signature"
    assert forged[0]["evidence"].startswith("unknown_signer:") and forged[0]["money_moved_minor"] == 0
    assert forged[0]["title"].startswith("REPLAY / FORGERY · Forged approval for the payment")


def test_text_format_and_levels(monkeypatch):
    buf = io.StringIO()
    oplog.configure(fmt="text", level="WARNING", stream=buf)
    env, pending = seeded(with_scenes=False)
    run_attack("replay_approval", env, pending)
    out = buf.getvalue().splitlines()
    assert out and all(" 🛑 ATTACK  " in ln or " 💥 ERROR  " in ln for ln in out), out  # WARNING: attacks only
    assert "\x1b[" not in buf.getvalue()  # not a TTY: no colour
    line = next(ln for ln in out if "replayed approval" in ln)
    assert "seq=" in line and "subject=mnd_1" in line and "rule=nonce_reused" in line and "principal=host" in line


def test_unconfigured_is_silent(capsys):
    env, _ = seeded(with_scenes=False)
    env.call("POST", "/mandates", {}, "tools")  # an ATTACK-level refusal
    out = capsys.readouterr()
    assert "ATTACK" not in out.err and "ATTACK" not in out.out


def test_malformed_requests_never_log_the_secret_they_carry(caplog):
    """A slightly malformed callback code, signature or VC is refused; its value never reaches the ops log."""
    caplog.set_level(logging.DEBUG, logger="airgap")
    env, _ = seeded(with_scenes=False)
    sig = "0x" + "ab" * 65
    vc = ("eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK3NkLWp3dCJ9.eyJpYmFuIjoiQ1oyMDAzMDAwMDAwMDAyMDAxMjM0NTY3In0.c2lnbmF0dXJl"
          "~WyJzYWx0IiwiaWJhbiJd~\n")
    for m, p, b, who in [("POST", "/callbacks/chg_1", {"code": 739215, "outcome": "confirm"}, "vendor_portal"),
                         ("POST", "/callbacks/chg_1", {"code": "739215 ", "outcome": "confirm"}, "vendor_portal"),
                         ("POST", "/signatures", {"nonce": "ABCDEF12", "role": "clerk", "sig": [sig]}, "host"),
                         ("POST", "/changes/chg_1/attestations", {"vc": vc}, "vendor_portal")]:
        st, _ = env.call(m, p, b, who)
        assert st == 400
    fmt = oplog.TextFormatter()
    text = "\n".join(fmt.format(r) for r in caplog.records if r.name == "airgap")
    assert "malformed request" in text
    for secret in ("739215", "ab" * 20, "eyJhbGciOiJFUzI1Ni", "WyJzYWx0Ii"):
        assert secret not in text, secret


def test_nested_tool_dispatch_is_told_once(caplog):
    """An agent tool call re-enters dispatch as `tools`: one story (the tool_call leaf), no second refusal line for a
    request the operator never sent."""
    from executor.tools.manifest import manifest_sha256

    caplog.set_level(logging.INFO, logger="airgap")
    env, _ = seeded(with_scenes=False)
    caplog.clear()
    body = {"session_id": "ses_probe", "step": 1, "args": {"vendor_id": "ven_00000000"},
            "manifest_sha256": manifest_sha256()}
    st, _ = env.call("POST", "/tools/vendor.lookup", body, "agent")
    lines = _lines(caplog.records)
    assert lines and not [a for a in lines if a.get("principal") == "tools"], lines
    assert len({a["req"] for a in lines}) == 1


def test_supplier_names_and_json_fields(monkeypatch):
    """Lines name the supplier (from data already in hand, no store reads) and JSON carries money and who."""
    buf = io.StringIO()
    oplog.configure(fmt="json", stream=buf)
    env, pending = seeded(with_scenes=False)
    run_attack("bec_lookalike", env, pending)
    run_attack("forged_approval", env, pending)
    rows = [json.loads(ln) for ln in buf.getvalue().splitlines() if ln.strip()]
    atk = [r for r in rows if r["level"] == "ATTACK"]
    change = next(r for r in atk if str(r.get("subject", "")).startswith("chg_") and r.get("seq") is not None)
    assert "ACME s.r.o." in change["title"] and "LT48 …1234" in change["title"] and change["new_iban"] == "LT48 …1234"
    pay = next(r for r in atk if r.get("subject", "").startswith("prp_") and r["kind"] == "lookalike domain (BEC)")
    assert "ACME s.r.o." in pay["title"] and pay["money_minor"] == 4890000 and pay["vendor_id"] and pay["sender_domain"]
    forged = next(r for r in atk if r["kind"] == "forged approval")
    assert " · " in forged["title"] and isinstance(forged["money_minor"], int) and forged["signer"]
    assert not [r for r in rows if "ven_" in r["title"] and r["level"] in ("ATTACK", "PAID", "HUMAN")]


def test_demo_replay_lines_are_marked():
    buf = io.StringIO()
    oplog.configure(fmt="text", stream=buf)
    with oplog.replay("S2"):
        seeded(with_scenes=True)
    oplog.emit("INFO", "live")
    out = buf.getvalue().splitlines()
    atk = [ln for ln in out if " 🛑 ATTACK  " in ln]
    assert atk and all("[demo replay] " in ln and "scene=S2" in ln for ln in atk)
    assert "scene=" not in out[-1] and "[demo replay]" not in out[-1]


def test_rail_failure_is_logged_after_the_payment(caplog, monkeypatch):
    from executor.rail import submit

    caplog.set_level(logging.INFO, logger="airgap")

    def down(*a, **k):
        raise ConnectionError("bank API down: TLS handshake timeout")

    monkeypatch.setattr(submit, "submit", down)
    from executor import scenes

    scenes.scene_s2(scenes.DemoEnv(), log=lambda s: None)
    lines = _lines(caplog.records)
    i = next(i for i, a in enumerate(lines) if a["level"] == "ERROR")
    assert "not delivered to the bank" in lines[i]["title"] and "ConnectionError" in lines[i]["why"]
    assert lines[i - 1]["level"] == "PAID"  # the committed payment first, then why its order did not reach the bank


def test_witness_relay_errors(caplog):
    caplog.set_level(logging.INFO, logger="airgap")
    oplog.witness_error("W2", "stored leaves do not reproduce the checkpoint root at size 12")
    oplog.witness_error("W2", "W2 422 at size 12: not an extension")
    oplog.witness_error("W2", "URLError: timed out")
    got = [(a["level"], a.get("kind")) for a in _lines(caplog.records)]
    assert got == [("ATTACK", "log fork / witness refusal")] * 2 + [("ERROR", "witness relay")]


def test_request_level_attacks_go_to_the_ring_and_the_local_route():
    """Attack d writes no audit leaf: its refusals land in oplog.recent() (ordered after the last leaf, stamped with
    the log clock) and the loopback stack serves them read-only at RECENT_PATH; a fresh log forgets them; the seeded
    demo replay is marked (scene)."""
    from fastapi.testclient import TestClient

    from tools import local_stack

    env, pending = seeded(with_scenes=False)
    with oplog.replay("S2+S3"):
        env.call("POST", "/mandates", {}, "tools")
    before = max((d["n"] for d in oplog.recent()), default=0)
    assert oplog.recent()[-1]["scene"] == "S2+S3"
    run_attack("stolen_agent_creds", env, pending)
    new = oplog.recent(before)
    kinds = {d["kind"] for d in new}
    assert {"stolen agent credentials", "IBAN injection"} <= kinds, kinds
    for d in new:
        assert d["threat"] == "PRIVILEGE ESCALATION" and d["layer"] == "permission scoping" and d["evidence"]
        assert isinstance(d["after_seq"], int) and d["log_ts"] and d["req"] and not d["scene"]
        assert attacks.FRAUD_IBAN not in json.dumps(d)  # masked like every ops-log line
    app = local_stack.build_app(env.settings, env.store, seed={"seed_seq": 0, "scene": None})
    r = TestClient(app).get(oplog.RECENT_PATH, params={"after": before})
    assert r.status_code == 200 and [d["n"] for d in r.json()["attacks"]] == [d["n"] for d in new]
    assert oplog.fetch_recent(env.call, before) == new  # in-process executor: no route, the process ring
    seeded(with_scenes=False)  # a brand-new store (audit seq 0): the old refusals are not about it
    assert not [d for d in oplog.recent() if d["n"] in {x["n"] for x in new}]


def test_ring_is_per_executor_store():
    """Two in-process executors in one process (a console on memory:, tests): each sees only its own refusals."""
    a, _ = seeded(with_scenes=False)
    b, _ = seeded(with_scenes=False)
    a.call("POST", "/mandates", {}, "tools")
    b.call("POST", "/signatures", {"nonce": "00000000", "role": "clerk", "sig": "0x00"}, "agent")
    assert {d["path"] for d in oplog.recent(scope=a.store)} == {"/mandates"}
    assert {d["path"] for d in oplog.recent(scope=b.store)} == {"/signatures"}
    assert all("_scope" not in d for d in oplog.recent())
