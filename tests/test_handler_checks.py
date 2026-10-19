"""Handler checks: I-REGISTRY snapshot input (CHG-3) and audit of malformed tool calls. Owner: WS-A."""
from executor import handler
from executor.config import Settings
from executor.store import seed
from executor.store.memory import MemoryStore

MANDATE = {"payee_registry_hash": "0" * 64, "created_at": "2026-10-19T12:00:00Z"}  # registry has moved since


def _payee(frm: str, change_id: str | None = "chg_7") -> dict:
    return {"vendor_id": "ven_12345678", "iban": "CZ2003000000002001234567",
            "iban_history": [{"iban": "CZ6508000000192000145399", "from": "2024-03-01", "to": frm, "change_id": None},
                             {"iban": "CZ2003000000002001234567", "from": frm, "to": None, "change_id": change_id}]}


def _ctx() -> handler.Context:
    s = Settings(backend="memory")
    st = MemoryStore(s)
    seed.seed_registry(st)
    return handler.Context(s, st)


def test_iban_activated_later_the_same_day_is_outside_the_snapshot():
    ctx = _ctx()
    assert handler._reg_hit(ctx, _payee("2026-10-19T15:30:00Z"), MANDATE) is False
    assert handler._reg_hit(ctx, _payee("2026-10-19T12:00:00Z"), MANDATE) is False  # not strictly before
    assert handler._reg_hit(ctx, _payee("2026-10-19T11:59:59Z"), MANDATE) is True
    assert handler._reg_hit(ctx, _payee("2026-10-20T08:00:00Z"), MANDATE) is False


def test_original_iban_and_missing_payee():
    ctx = _ctx()
    assert handler._reg_hit(ctx, _payee("2099-01-01T00:00:00Z", change_id=None), MANDATE) is True
    assert handler._reg_hit(ctx, None, MANDATE) is False
    p = _payee("2026-10-19T11:00:00Z")
    del p["iban_history"][1]["from"]
    assert handler._reg_hit(ctx, p, MANDATE) is False


def test_malformed_tool_call_is_logged():
    """WS-E finding: a schema-invalid POST /tools/{name} is refused 400 but still leaves a tool_call leaf."""
    import json

    ctx = _ctx()
    for step in (1.5, -1, "1", None):
        st, r = handler.dispatch("POST", "/tools/mandate.write", None,
                                 {"session_id": "ses_x", "step": step, "args": {"max_total_minor": 1.5},
                                  "manifest_sha256": "0" * 64}, principal="agent", ctx=ctx)
        assert st == 400 and r["error"] == "invalid_request"
    leaves = [json.loads(x["event"]) for x in ctx.store.query("audit", ("log_id", "audit"))]
    bad = [e for e in leaves if e["type"] == "tool_call" and e["data"]["rule_ids"] == ["T-BAD-REQUEST"]]
    assert len(bad) == 4 and all(e["data"]["result"] == "error" and e["data"]["tool"] == "mandate.write" for e in bad)
    assert ctx.store.scan("tool_calls") == []
