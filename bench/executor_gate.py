"""A3 gate on the real executor: `executor.handler.dispatch` with the memory backend. Owner: WS-F.

Each episode gets its own MemoryStore seeded with the bench vendor master, an ACTIVE mandate signed 2/2 (clerk +
treasury EIP-191 keys) and the episode's prior payments. Proposals go to POST /proposals; a PAY challenge is shown to
the simulated human as the executor-rendered device text, and an approval is a real EIP-191 signature submitted to
POST /signatures. Payee changes go to POST /changes; while the change FSM (WS-D) is not merged they fall back to
the bench twin (`RefAirGap.request_change`) and `gate_parts()` says so.
"""
from __future__ import annotations

import re
from typing import Any

from eth_account import Account
from eth_account.messages import encode_defunct

from bench import humans
from bench.arms import RefAirGap, norm
from bench.world import iban_valid

NOW = "2026-10-19T12:00:00Z"
_FALLBACKS: set[str] = set()


def gate_parts() -> dict[str, str]:
    """What served A3 in this process (for the run meta)."""
    return {"proposals": "executor.handler.dispatch (memory backend)",
            "facts": "executor facts (ws-a-fallback until WS-D compute merges)",
            "changes": "bench twin RefAirGap (change FSM not merged)" if "changes" in _FALLBACKS
            else "executor.handler.dispatch"}


def _sign(acct: Any, text: str) -> str:
    sig = acct.sign_message(encode_defunct(text=text)).signature.hex()
    return sig if sig.startswith("0x") else "0x" + sig


def parse_pay_text(text: str) -> dict[str, Any]:
    """What a human reads on the device: amount (line 2) and the payee IBAN (lines 3+)."""
    lines = text.splitlines()
    m = re.match(r"^(\d+)(?:\.(\d{2}))? CZK$", lines[1]) if len(lines) > 1 else None
    amount = int(m.group(1)) * 100 + int(m.group(2) or 0) if m else -1
    flat = "".join(lines[2:6]).replace(" ", "")
    iban = next((flat[:n] for n in range(34, 14, -1) if iban_valid(flat[:n])), "")
    return {"amount_minor": amount, "iban": iban}


class ExecutorGate:
    name = "executor"

    def __init__(self, ep: Any) -> None:
        from executor import handler
        from executor.config import Settings
        from executor.store import seed
        from executor.store.memory import MemoryStore

        self.ep, self.w, self.handler = ep, ep.world, handler
        self.settings = Settings(backend="memory", fake_now=NOW)
        self.store = MemoryStore(self.settings)
        self.ctx = handler.Context(self.settings, self.store)
        seed.seed_registry(self.store, [self._registry_row(v) for v in self.w.vendors.values()])
        self.clerk, self.treasury = Account.create(), Account.create()
        seed.enroll_signer(self.store, self.clerk.address, "clerk", device="GENUINE")
        seed.enroll_signer(self.store, self.treasury.address, "treasury", device="EMULATOR")
        self._mandate()
        self._ref = RefAirGap(ep)
        for p in [t for t in self.w.ledger if t.get("prior")]:
            self._post_proposal({"vendor_id": p["vendor_id"], "invoice_no": p["invoice_no"],
                                 "amount_minor": p["amount_minor"], "vs": p.get("vs", "")}, record=False)

    @staticmethod
    def _registry_row(v: dict[str, Any]) -> dict[str, Any]:
        return {"vendor_id": v["vendor_id"], "ico": v["ico"], "name": v["name"], "domain": v["domain"],
                "iban": v["iban"], "country": "CZ", "phone": "+420 200 000 000", "contact_email": v["contact"],
                "registered_since": "2023-01-01", "in_network": True, "issuer_pins": [],
                "iban_history": [{"iban": v["iban"], "from": v.get("iban_since", "2024-03-01"), "to": None,
                                  "change_id": None}]}

    def call(self, method: str, path: str, body: Any = None, principal: str = "host") -> tuple[int, Any]:
        return self.handler.dispatch(method, path, None, body, principal=principal, ctx=self.ctx)

    def _mandate(self) -> None:
        m = self.w.mandate
        st, r = self.call("POST", "/mandates", {"max_per_payment_minor": m["max_per_payment_minor"],
                                                "max_total_minor": m["max_total_minor"], "max_count": m["max_count"],
                                                "payee_scope": "existing_only", "valid_until": "2026-10-20T16:00:00Z",
                                                "currency": "CZK"})
        assert st == 201, r
        for acct in (self.clerk, self.treasury):
            ch = r["challenge"]
            st, r = self.call("POST", "/signatures", {"nonce": ch["nonce"], "role": ch["role"], "sig": _sign(acct, ch["text"])})
            assert st == 200, r
            if r["mandate"]["status"] == "ACTIVE":
                return
        raise AssertionError("mandate not ACTIVE")

    def _post_proposal(self, args: dict[str, Any], *, record: bool = True) -> dict[str, Any]:
        inv = {"vendor_id": str(args.get("vendor_id", "")), "invoice_no": str(args.get("invoice_no") or "N/A"),
               "invoice_ref": "doc_" + "0" * 16, "issue_date": "2026-10-15",
               "amount_minor": int(args["amount_minor"]), "currency": str(args.get("currency") or "CZK"),
               "reason_code": "DUE"}
        vs = re.sub(r"\D", "", str(args.get("vs") or ""))[:10]
        if vs:
            inv["vs"] = vs
        hints = [{"source": "agent", "text": str(h.get("text", ""))[:200]} for h in args.get("hints") or []
                 if isinstance(h, dict)]
        st, r = self.call("POST", "/proposals", {"invoice": inv, "hints": hints}, principal="tools")
        if st >= 400:
            self.ep.rule_ids.add(r.get("error", "error"))
            return {"error": r.get("error"), "message": r.get("message")}
        dec = r["decision"]
        self.ep.rule_ids.update(dec.get("rule_ids", []))
        if dec["decision"] == "allow":
            if record:
                self._record(r["tx"], inv)
            return {"status": "EXECUTED", "decision": "allow"}
        if dec["decision"] == "deny":
            return {"status": "DENIED", "rule_ids": dec["rule_ids"]}
        ch = dec["challenge"]
        self.w.challenges.append({"channel": "device", "kind": "pay", "role": ch["role"]})
        shown = {"kind": "pay", "vendor_id": inv["vendor_id"], **parse_pay_text(ch["text"])}
        if not humans.decide(self.ep.human_policy, shown, self.ep.truth):
            return {"status": "PENDING_SIG", "decision": "challenge", "note": "approver did not confirm on device"}
        st, s = self.call("POST", "/signatures", {"nonce": ch["nonce"], "role": ch["role"], "sig": _sign(self.clerk, ch["text"])})
        if st != 200:
            self.ep.rule_ids.add(s.get("error", "sig_error"))
            return {"status": "REJECTED", "error": s.get("error")}
        tx = s.get("tx")
        if tx and record:
            self._record(tx, inv)
        return {"status": "EXECUTED" if tx else "PENDING", "decision": "challenge"}

    def _record(self, tx: dict[str, Any], inv: dict[str, Any]) -> None:
        iban = tx.get("iban") or self.store.get("registry", {"vendor_id": inv["vendor_id"]})["iban"]
        self.w.pay(vendor_id=inv["vendor_id"], iban=norm(iban), amount_minor=int(tx.get("amount_minor", inv["amount_minor"])),
                   invoice_no=inv["invoice_no"], vs=inv.get("vs", ""), via="A3-executor")

    def propose(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._post_proposal(args)

    def request_change(self, args: dict[str, Any]) -> dict[str, Any]:
        body = {"vendor_id": str(args.get("vendor_id", "")), "new_iban": norm(args.get("new_iban")),
                "evidence_ids": [str(x) for x in args.get("evidence_ids") or []]}
        try:
            st, r = self.call("POST", "/changes", body, principal="tools")
        except NotImplementedError:
            _FALLBACKS.add("changes")
            return self._ref.request_change(args)
        if st >= 400:
            return {"error": r.get("error"), "message": r.get("message")}
        self.ep.rule_ids.update(r["decision"].get("rule_ids", []))
        return {"status": r["change"]["state"], "rule_ids": r["decision"].get("rule_ids", [])}
