"""A3 gate on the real executor: `executor.handler.dispatch` with the memory backend. Owner: WS-F.

Per episode: a MemoryStore seeded like the demo (WS-D `tools.seed_data`: canonical vendors + issuer pins), the
episode's emails as raw .eml (DKIM-signed with the demo keys where the scenario sender holds the key) put into the
inbox with the executor's own DKIM verdict, an ACTIVE mandate signed 2/2 (clerk + treasury EIP-191), and the prior
payments. Proposals and payee changes go through POST /proposals and POST /changes (real facts, real change FSM).
Device challenges are shown to the simulated human as the executor-rendered text; approvals are real EIP-191
signatures on POST /signatures. A legitimate change is attested by the DEMO-ONLY issuers (supplier-erp and
supplier-bank sign real SD-JWT VCs via POST /changes/{id}/attestations), then the clock passes cooling-off.
"""
from __future__ import annotations

import dataclasses
import json
import re
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path
from typing import Any

from eth_account import Account
from eth_account.messages import encode_defunct

from bench import humans
from bench.arms import norm
from bench.world import COMPANY_DOMAIN, iban_valid

NOW = datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc)
DATA = Path(__file__).resolve().parent.parent / "data"


def gate_parts() -> dict[str, str]:
    """What served A3 (for the run meta)."""
    return {"proposals": "executor.handler.dispatch (memory backend)", "facts": "executor.facts.compute (WS-D, real)",
            "changes": "executor.change.machine via POST /changes (WS-D, real)",
            "attestations": "DEMO-ONLY issuers supplier-erp + supplier-bank (real SD-JWT VCs, simulated organisations)",
            "inbox": "tools.seed_data.inbox_row (executor DKIM verdict; POST /ingest not implemented yet)"}


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


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


def parse_chg_text(text: str) -> str:
    """NEW IBAN from a CHG screen (`NEW <first group>` then continuation lines)."""
    lines = text.splitlines()
    i = next((k for k, ln in enumerate(lines) if ln.startswith("NEW ")), None)
    if i is None:
        return ""
    flat = (lines[i][4:] + "".join(lines[i + 1:i + 3])).replace(" ", "")
    return next((flat[:n] for n in range(34, 14, -1) if iban_valid(flat[:n])), "")


def raw_email(em: dict[str, Any], when: datetime) -> bytes:
    """RFC 5322 message; DKIM-signed with the demo key of the sender domain when the sender holds it."""
    domain = em["from"].rsplit("@", 1)[-1].lower()
    msg = (f"From: {em.get('from_name') or domain} <{em['from']}>\r\nTo: ap@{COMPANY_DOMAIN}\r\n"
           f"Subject: {em['subject']}\r\nDate: {format_datetime(when)}\r\n"
           f"Message-ID: <{em['email_id']}.{domain}@bench.example>\r\nMIME-Version: 1.0\r\n"
           f"Content-Type: text/plain; charset=us-ascii\r\n\r\n{em['body']}\r\n")
    raw = msg.encode("ascii", "replace")
    pem = DATA / "dkim_keys" / f"{domain}.demo2026.pem"
    if em.get("dkim_sign") and pem.exists():
        from tools.gen_emails import _sign as dkim_sign
        raw = dkim_sign(raw.replace(b"\r\n", b"\n"), domain, pem.read_bytes(), _iso(when))
    return raw


class ExecutorGate:
    name = "executor"

    def __init__(self, ep: Any) -> None:
        from executor import handler
        from executor.config import Settings
        from executor.store import seed
        from executor.store.memory import MemoryStore
        from tools import seed_data

        self.ep, self.w, self.handler = ep, ep.world, handler
        self.now = NOW
        self.settings = Settings(backend="memory", fake_now=_iso(NOW), data_dir=str(DATA))
        self.store = MemoryStore(self.settings)
        self.ctx = handler.Context(self.settings, self.store)
        canon = {v["ico"]: v for v in json.loads((DATA / "vendors.json").read_text())}
        seed_data.seed_registry([canon[v["ico"]] for v in self.w.vendors.values()], store=self.store,
                                settings=self.settings, keys_dir=DATA / "issuer_keys", now=NOW)
        dns = json.loads((DATA / "dns_snapshot.json").read_text())
        self.email_ids: dict[str, str] = {}
        for k, em in enumerate(self.w.inbox):
            row = seed_data.inbox_row(raw_email(em, NOW - timedelta(hours=3, minutes=k)), dns_snapshot=dns, now=NOW)
            self.store.put("inbox", row)
            self.email_ids[em["email_id"]] = row["email_id"]
        self.clerk, self.treasury = Account.create(), Account.create()
        seed.enroll_signer(self.store, self.clerk.address, "clerk", device="GENUINE")
        seed.enroll_signer(self.store, self.treasury.address, "treasury", device="EMULATOR")
        self._mandate()
        for p in [t for t in self.w.ledger if t.get("prior")]:
            self._post_proposal({"vendor_id": p["vendor_id"], "invoice_no": p["invoice_no"],
                                 "amount_minor": p["amount_minor"], "vs": p.get("vs", "")}, record=False)

    # ------------------------------------------------------------------ plumbing
    def call(self, method: str, path: str, body: Any = None, principal: str = "host") -> tuple[int, Any]:
        return self.handler.dispatch(method, path, None, body, principal=principal, ctx=self.ctx)

    def _tick(self, seconds: int) -> None:
        """Advance the executor's fake clock (Settings is frozen: rebuild the context on the same store)."""
        self.now += timedelta(seconds=seconds)
        self.settings = dataclasses.replace(self.settings, fake_now=_iso(self.now))
        if hasattr(self.store, "settings"):
            self.store.settings = self.settings
        self.ctx = self.handler.Context(self.settings, self.store)

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

    # ------------------------------------------------------------------ proposals
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

    # ------------------------------------------------------------------ payee changes
    def request_change(self, args: dict[str, Any]) -> dict[str, Any]:
        ids = [str(x) for x in args.get("evidence_ids") or []]
        email = next((self.email_ids[e["email_id"]] for e in self.w.inbox
                      if e["email_id"] in ids or any(a["doc_id"] in ids for a in e["attachments"])), None)
        body: dict[str, Any] = {"vendor_id": str(args.get("vendor_id", "")), "new_iban": norm(args.get("new_iban")),
                                "evidence_ids": ids}
        if email:
            body["email_id"] = email
        st, r = self.call("POST", "/changes", body, principal="tools")
        if st >= 400:
            self.ep.rule_ids.add(r.get("error", "error"))
            return {"error": r.get("error"), "message": r.get("message")}
        ch, dec = r["change"], r["decision"]
        self.ep.rule_ids.update(dec.get("rule_ids", []))
        self.ep.rule_ids.update(f["id"] for f in dec.get("facts", []) if f.get("kind") == "F" and f.get("severity") == "BLOCK")
        self.w.changes.append({"vendor_id": body["vendor_id"], "new": body["new_iban"], "state": ch["state"],
                               "change_id": ch["change_id"]})
        if ch["state"] == "PENDING_ATTEST":
            ch = self._issuers(ch)
        return {"status": ch["state"], "change_id": ch["change_id"], "rule_ids": dec.get("rule_ids", [])}

    def _issuers(self, ch: dict[str, Any]) -> dict[str, Any]:
        """Independent issuers attest only what is true (case truth: a legitimate, attested change)."""
        legit = any(c["vendor_id"] == ch["vendor_id"] and norm(c["new_iban"]) == norm(ch["new_iban"]) and c.get("attested")
                    for c in self.ep.truth.get("legit_changes", []))
        if not legit:
            return ch
        from executor.issuers import issuer
        cid = ch["change_id"]
        for cls in ("supplier-erp", "supplier-bank"):
            st, cur = self.call("GET", f"/changes/{cid}", principal="issuer")
            key, iss = issuer.load_issuer_key(cls)
            vc = issuer.issue_vc(cls, cur, key=key, holder_key=issuer.load_holder_key(cur["vendor_ico"]), now=self.now, iss=iss)
            st, r = self.call("POST", f"/changes/{cid}/attestations", {"vc": vc, "issuer_class": cls}, principal="issuer")
            if st >= 400:
                self.ep.rule_ids.add(r.get("error", "attest_error"))
                return cur
        self._tick(self.settings.cooling_seconds + 1)
        for _ in range(2):
            st, cur = self.call("GET", f"/changes/{cid}")
            pc = cur.get("pending_challenge")
            if cur["state"] not in ("SIG_CLERK", "SIG_TREASURY") or not pc:
                break
            self.w.challenges.append({"channel": "device", "kind": "change", "role": pc["role"]})
            shown = {"kind": "change", "vendor_id": cur["vendor_id"], "iban": parse_chg_text(pc["text"])}
            if not humans.decide(self.ep.human_policy, shown, self.ep.truth):
                break
            acct = self.clerk if pc["role"] == "clerk" else self.treasury
            st, r = self.call("POST", "/signatures", {"nonce": pc["nonce"], "role": pc["role"], "sig": _sign(acct, pc["text"])})
            if st != 200:
                self.ep.rule_ids.add(r.get("error", "sig_error"))
                break
        st, cur = self.call("GET", f"/changes/{cid}")
        if cur["state"] == "ACTIVE":
            self.w.vendors[cur["vendor_id"]]["iban"] = norm(cur["new_iban"])
        self.w.changes[-1]["state"] = cur["state"]
        return cur
