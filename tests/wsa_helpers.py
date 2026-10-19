"""Shared test harness for the executor API (memory backend, fake clock). Owner: WS-A."""
from __future__ import annotations

from typing import Any

from eth_account import Account
from eth_account.messages import encode_defunct

from executor import handler
from executor.config import Settings
from executor.store import seed
from executor.store.memory import MemoryStore

NOW = "2026-10-19T12:00:00Z"


class Harness:
    def __init__(self, **settings: Any) -> None:
        settings.setdefault("data_dir", seed.dev_data_dir())
        self.settings = Settings(backend="memory", fake_now=settings.pop("fake_now", NOW), **settings)
        self.store = MemoryStore(self.settings)
        self.ctx = handler.Context(self.settings, self.store)
        seed.seed_registry(self.store)
        self.clerk, self.treasury, self.stranger = Account.create(), Account.create(), Account.create()
        seed.enroll_signer(self.store, self.clerk.address, "clerk", device="GENUINE", settings=self.settings)
        seed.enroll_signer(self.store, self.treasury.address, "treasury", device="EMULATOR", settings=self.settings)

    def call(self, method: str, path: str, body: Any = None, principal: str | None = None,
             query: dict | None = None) -> tuple[int, Any]:
        return handler.dispatch(method, path, query, body, principal=principal, ctx=self.ctx)

    @staticmethod
    def sign(acct: Any, text: str) -> str:
        sig = acct.sign_message(encode_defunct(text=text)).signature.hex()
        return sig if sig.startswith("0x") else "0x" + sig

    def submit(self, challenge: dict, acct: Any, *, role: str | None = None, text: str | None = None,
               nonce: str | None = None, **extra: Any) -> tuple[int, Any]:
        body = {"nonce": nonce or challenge["nonce"], "role": role or challenge["role"],
                "sig": self.sign(acct, text if text is not None else challenge["text"]), **extra}
        return self.call("POST", "/signatures", body, "host")

    def mandate(self, *, per: int = 8_000_000, total: int = 25_000_000, count: int = 20) -> dict:
        st, r = self.call("POST", "/mandates", {"max_per_payment_minor": per, "max_total_minor": total,
                                                "max_count": count, "payee_scope": "existing_only",
                                                "valid_until": "2026-10-20T16:00:00Z", "currency": "CZK"}, "host")
        assert st == 201, r
        st, r = self.submit(r["challenge"], self.clerk)
        assert st == 200, r
        if r["mandate"]["status"] != "ACTIVE":
            st, r = self.submit(r["challenge"], self.treasury)
            assert st == 200, r
        assert r["mandate"]["status"] == "ACTIVE"
        return r["mandate"]

    def propose(self, amount: int, *, vendor: str = "ven_12345678", no: str = "FV-1", issue: str = "2026-10-15",
                hints: list | None = None, cite: bool = True) -> tuple[int, Any]:
        """POST /proposals as tools. By default the invoice cites a DKIM-signed source email from the vendor's
        registered domain carrying exactly this invoice (FACTS-1: no source document, no autopay); cite=False, or
        a vendor that is not registered, posts it without one."""
        inv = {"vendor_id": vendor, "invoice_no": no, "invoice_ref": "doc_43592996ab5306ac", "issue_date": issue,
               "amount_minor": amount, "currency": "CZK", "vs": "20261019", "reason_code": "DUE"}
        if cite:
            inv = self.cited(inv)
        return self.call("POST", "/proposals", {"invoice": inv, "hints": hints or []}, "tools")

    def cited(self, invoice: dict) -> dict:
        """`invoice` + email_id/invoice_ref of its ingested source email (tools/invoice_mail.py); unchanged for a
        vendor that has no registered domain/DKIM key (e.g. an unknown vendor_id, which 404s anyway)."""
        from tools import invoice_mail

        try:
            raw = invoice_mail.invoice_email(invoice, data_dir=self.settings.data_dir)
        except KeyError:
            return invoice
        st, r = self.call("POST", "/ingest", invoice_mail.ingest_body(raw), "ingest")
        assert st == 201, r
        return invoice_mail.cite(invoice, raw, r["email_id"])

    def leaves(self) -> list[dict]:
        import json

        return [json.loads(r["event"]) for r in self.store.query("audit", ("log_id", "audit"))]
