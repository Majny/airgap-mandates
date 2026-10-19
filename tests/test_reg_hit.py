"""I-REGISTRY input: payee IBAN inside the registry snapshot pinned by the mandate (CHG-3). Owner: WS-A."""
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
