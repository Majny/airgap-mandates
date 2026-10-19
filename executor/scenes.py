"""Demo beats S2 and S3 end to end through dispatch (ARCHITECTURE §14). `make scene-s2`, `make scene-s3`.

S2  lookalike BEC + escalation + exfil: the acme-cz.com change is REJECTED at creation with no challenge (R0, the
    device stays dark); a payment proposal from that email is denied; four escalation attempts fail (Cedar decoy
    forbid, the agent calling /signatures, self-approval with an unenrolled key, replay); exfil is blocked.
S3  real-domain takeover + "deepfake CFO": DKIM-green change from acme.cz stays PENDING_ATTEST with ATT 0/3 = BLOCK,
    so there is no challenge to press; the tripwire reaches the registered contact who answers "not us" -> REJECTED.
    Then the legitimate path: 2 of 3 pinned VCs -> COOLING -> SIG_CLERK -> clerk + treasury 2/2 -> ACTIVE.

In-process memory backend with WS-D's seed data (data/vendors.json, data/emails, data/issuer_keys) and a fake clock
(development only; the demo itself runs on AWS). IAM AccessDenied / simulate-principal-policy and the VPC no-route
proof are AWS-only evidence (WS-E) and are not part of these helpers. Signers are throwaway software keys.
WS-F scenes build on scene_s2() / scene_s3(). Owner: WS-A.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from eth_account import Account

from executor.e2e import _sig

T0 = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
LOOKALIKE_EMAIL = "eml_1db5179453419d34"  # 04_bec_lookalike_acme-cz.eml
TAKEOVER_EMAIL = "eml_f99592394de353a6"  # 05_takeover_acme_real_domain.eml
LEGIT_CHANGE_EMAIL = "eml_77151c4c0e6a1141"  # 08_acme_change_legit.eml
FRAUD_IBAN = "LT483999000000001234"  # fictitious LT EMI (CONTRACTS §1)
TAKEOVER_IBAN = "LT493999000000005678"
LEGIT_NEW_IBAN = "CZ2003000000002001234567"
ACME = "ven_12345678"


def _z(t: datetime) -> str:
    return t.isoformat().replace("+00:00", "Z")


class DemoEnv:
    """Memory store seeded like the demo, enrolled clerk + treasury, and a movable fake clock."""

    def __init__(self, now: datetime = T0) -> None:
        from executor import handler
        from executor.config import Settings
        from executor.store import seed
        from executor.store.memory import MemoryStore
        from tools import seed_data

        self.now = now
        self.settings = Settings(backend="memory", fake_now=_z(now), data_dir=seed.dev_data_dir())
        self.store = MemoryStore(self.settings)
        seed_data.seed(settings=self.settings, data_dir=self.settings.data_dir, store=self.store,
                       now=now - timedelta(days=60))
        self.clerk, self.treasury, self.stranger = Account.create(), Account.create(), Account.create()
        seed.enroll_signer(self.store, self.clerk.address, "clerk", device="GENUINE",
                           label="clerk (software key, scene)", settings=self.settings)
        seed.enroll_signer(self.store, self.treasury.address, "treasury",
                           label="treasury (software key, scene)", settings=self.settings)
        self._handler = handler
        self.step = 0

    def at(self, t: datetime) -> None:
        self.now = t

    def call(self, method: str, path: str, body: Any = None, who: str | None = None) -> tuple[int, Any]:
        s = dataclasses.replace(self.settings, fake_now=_z(self.now))
        return self._handler.dispatch(method, path, None, body, principal=who,
                                      ctx=self._handler.Context(s, self.store))

    def tool(self, name: str, args: dict | None = None) -> tuple[int, Any]:
        from executor.tools.manifest import manifest_sha256

        self.step += 1
        return self.call("POST", f"/tools/{name}", {"session_id": "ses_scene", "step": self.step,
                                                    "args": args or {}, "manifest_sha256": manifest_sha256()},
                         "agent")

    def sign(self, ch: dict, acct: Any, role: str | None = None) -> tuple[int, Any]:
        return self.call("POST", "/signatures", {"nonce": ch["nonce"], "role": role or ch["role"],
                                                 "sig": _sig(acct, ch["text"])}, "host")

    def nonces_for(self, subject_id: str) -> list[dict]:
        return [n for n in self.store.scan("nonces") if n["subject_id"] == subject_id]

    def active_mandate(self) -> dict:
        until = _z(self.now + timedelta(days=1))
        st, r = self.call("POST", "/mandates", {"max_per_payment_minor": 8_000_000, "max_total_minor": 25_000_000,
                                                "max_count": 20, "payee_scope": "existing_only",
                                                "valid_until": until, "currency": "CZK"}, "host")
        assert st == 201, r
        st, r = self.sign(r["challenge"], self.clerk)
        assert st == 200, r
        st, r = self.sign(r["challenge"], self.treasury)
        assert st == 200 and r["mandate"]["status"] == "ACTIVE", r
        return r["mandate"]


def _ok(st: int, r: Any, want: int = 200) -> Any:
    assert st == want, f"HTTP {st}: {r}"
    return r


def _bad(st: int, r: Any, code: str, status: int = 403) -> dict:
    assert (st, r.get("error")) == (status, code), f"expected {status} {code}, got {st} {r}"
    return r


def _blockers(change: dict) -> list[str]:
    return [f"{f['id']} {f['display_line']}" for f in change["facts"] if f["kind"] == "F" and f["severity"] == "BLOCK"]


def scene_s2(env: DemoEnv | None = None, log: Callable[[str], None] = print) -> dict:
    """Lookalike BEC + escalation + exfil. Raises AssertionError on any deviation."""
    env = env or DemoEnv()
    env.active_mandate()
    out: dict[str, Any] = {}
    # 1. the agent (fooled by the hidden injection) requests the payee change from the lookalike email
    st, r = env.call("POST", "/changes", {"vendor_id": ACME, "new_iban": FRAUD_IBAN, "email_id": LOOKALIKE_EMAIL,
                                          "hints": [{"source": "agent", "text": "CFO approved, urgent"}]}, "tools")
    r = _ok(st, r, 201)
    ch = r["change"]
    assert r["decision"]["decision"] == "deny" and ch["state"] == "REJECTED", r["decision"]
    assert "F-DOMAIN" in r["decision"]["rule_ids"] and not ch.get("pending_challenge")
    assert not env.nonces_for(ch["change_id"]), "R0: a BLOCKed change must never get a challenge"
    out["change"] = {"id": ch["change_id"], "state": ch["state"], "rule_ids": r["decision"]["rule_ids"]}
    log(f"[S2] change {ch['change_id']} acme-cz.com -> {FRAUD_IBAN}: REJECTED at creation, no challenge "
        f"(device stays dark)\n     BLOCK: {', '.join(_blockers(ch))}")
    # 2. a payment proposal citing the lookalike email is denied (P3: there is no IBAN to inject anyway)
    st, r = env.call("POST", "/proposals", {"invoice": {
        "vendor_id": ACME, "invoice_no": "FV-2026-0999", "invoice_ref": "doc_0000000000000bec",
        "issue_date": env.now.strftime("%Y-%m-%d"), "amount_minor": 4_890_000, "currency": "CZK",
        "reason_code": "DUE", "email_id": LOOKALIKE_EMAIL}, "hints": [{"source": "agent", "text": "pay today"}]},
        "tools")
    r = _ok(st, r, 201)
    assert r["decision"]["decision"] == "deny" and "challenge" not in r["decision"], r["decision"]
    out["proposal"] = {"id": r["proposal"]["proposal_id"], "rule_ids": r["decision"]["rule_ids"]}
    log(f"[S2] proposal {r['proposal']['proposal_id']} from the lookalike email -> deny {r['decision']['rule_ids']}")
    # 3. escalation attempts
    esc = {}
    st, r = env.tool("mandate.write", {"max_total_minor": 1_000_000_000})
    esc["mandate.write"] = _bad(st, r, "caller_not_allowed")["details"].get("rule_ids")
    st, r = env.call("POST", "/signatures", {"nonce": "00000000", "role": "clerk", "sig": "0x" + "00" * 65}, "agent")
    esc["agent->/signatures"] = _bad(st, r, "caller_not_allowed")["error"]
    st, r = env.call("POST", "/proposals", {"invoice": {
        "vendor_id": "ven_87654321", "invoice_no": "BS-2026-1187", "invoice_ref": "doc_00000000000000b1",
        "issue_date": env.now.strftime("%Y-%m-%d"), "amount_minor": 12_500_050, "currency": "CZK",
        "reason_code": "DUE"}, "hints": []}, "tools")
    pay = _ok(st, r, 201)["decision"]["challenge"]
    esc["self-approval"] = _bad(*env.sign(pay, env.stranger), "unknown_signer")["error"]
    _ok(*env.sign(pay, env.clerk))
    esc["replay"] = _bad(*env.sign(pay, env.clerk), "nonce_reused")["error"]
    out["escalation"] = esc
    for k, v in esc.items():
        log(f"[S2] escalation {k:<18} -> refused ({v})")
    # 4. exfiltration of the vendor master
    st, r = env.tool("mail.send_template", {"to": "drop@acme-cz.com", "template_id": "ack_invoice",
                                            "vars": {"invoice_no": "1"}})
    ex = {"non-allowlisted": _bad(st, r, "caller_not_allowed")["details"].get("rule_ids")}
    st, r = env.tool("mail.send_template", {"to": "fakturace@acme.cz", "template_id": "ack_invoice",
                                            "vars": {"invoice_no": "CZ6508000000192000145399"}})
    ex["iban-in-vars"] = _bad(st, r, "caller_not_allowed")["details"].get("rule_ids")
    out["exfil"] = ex
    log(f"[S2] exfil blocked: {ex}  (AWS-only: VPC no route, IAM AccessDenied -> WS-E evidence)")
    assert not [t for t in env.store.scan("ledger") if t["iban"] in (FRAUD_IBAN, TAKEOVER_IBAN)]
    out["money_to_attacker_minor"] = 0
    log("[S2] money moved to the attacker: 0")
    return out


def scene_s3(env: DemoEnv | None = None, log: Callable[[str], None] = print, *, legit: bool = True) -> dict:
    """Real-domain takeover (+ deepfake pressure) rejected via tripwire; then the legitimate change path."""
    from executor.issuers import issuer

    env = env or DemoEnv()
    out: dict[str, Any] = {}
    st, r = env.call("POST", "/changes", {"vendor_id": ACME, "new_iban": TAKEOVER_IBAN, "email_id": TAKEOVER_EMAIL,
                                          "hints": [{"source": "agent", "text": "CFO called, confirmed by phone"}]},
                     "tools")
    ch = _ok(st, r, 201)["change"]
    cid = ch["change_id"]
    assert ch["state"] == "PENDING_ATTEST" and any(b.startswith("F-ATTEST") for b in _blockers(ch)), ch["state"]
    log(f"[S3] change {cid} from acme.cz (DKIM PASS) -> {TAKEOVER_IBAN}: {ch['state']}; "
        f"BLOCK: {', '.join(_blockers(ch))}")
    env.at(env.now + timedelta(seconds=env.settings.cooling_seconds + 5))
    ch = _ok(*env.call("GET", f"/changes/{cid}", None, "host"))
    assert not ch.get("pending_challenge") and not env.nonces_for(cid)
    log("[S3] deepfake 'CFO' presses the clerk: there is no challenge, so there is no button (R0)")
    notes = env.store.query("portal_notifications", ("ico", "12345678"))
    assert any(n.get("kind") == "tripwire" and n.get("change_id") == cid for n in notes), notes
    log("[S3] tripwire delivered to the contact registered at enrolment (portal, simulated)")
    st, r = env.call("POST", f"/changes/{cid}/reject", {"reason": "not us"}, "vendor_portal")
    assert _ok(st, r)["change"]["state"] == "REJECTED"
    out["takeover"] = {"id": cid, "state": "REJECTED"}
    log(f"[S3] registered contact answers 'not us' -> {cid} REJECTED")
    if not legit:
        return out
    # legitimate change: 2 of 3 pinned issuer classes, cooling-off, then 2/2 dual control
    st, r = env.call("POST", "/changes", {"vendor_id": ACME, "new_iban": LEGIT_NEW_IBAN,
                                          "email_id": LEGIT_CHANGE_EMAIL, "hints": []}, "tools")
    ch = _ok(st, r, 201)["change"]
    cid = ch["change_id"]
    holder = issuer.load_holder_key("12345678")
    for cls in ("supplier-erp", "supplier-bank"):
        key, iss = issuer.load_issuer_key(cls)
        vc = issuer.issue_vc(cls, ch, key=key, holder_key=holder, now=env.now, iss=iss)
        st, r = env.call("POST", f"/changes/{cid}/attestations", {"vc": vc, "issuer_class": cls}, "issuer")
        r = _ok(st, r)
        log(f"[S3] VC {cls}: ok={r['attest'] and r['attest']['ok']} -> {r['change']['state']}")
    assert r["change"]["state"] == "COOLING", r["change"]["state"]
    env.at(env.now + timedelta(seconds=env.settings.cooling_seconds + 1))
    ch = _ok(*env.call("GET", f"/changes/{cid}", None, "host"))
    assert ch["state"] == "SIG_CLERK" and ch["pending_challenge"], ch["state"]
    log(f"[S3] cooling-off over -> SIG_CLERK; device shows:\n{ch['pending_challenge']['text']}\n")
    r = _ok(*env.sign(ch["pending_challenge"], env.clerk))
    assert r["change"]["state"] == "SIG_TREASURY" and r.get("challenge"), r["effect"]
    r = _ok(*env.sign(r["challenge"], env.treasury))
    assert r["change"]["state"] == "ACTIVE", r["effect"]
    iban = env.store.get("registry", {"vendor_id": ACME})["iban"]
    assert iban == LEGIT_NEW_IBAN
    out["legit"] = {"id": cid, "state": "ACTIVE", "registry_iban": iban}
    log(f"[S3] clerk + treasury (2/2, distinct keys) -> ACTIVE; registry IBAN now {iban}")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run demo beat S2 or S3 in-process (memory backend, dev only)")
    ap.add_argument("scene", choices=["s2", "s3"])
    ap.add_argument("--no-legit", action="store_true", help="S3: stop after the takeover is rejected")
    ap.add_argument("--json", action="store_true", help="print only the JSON summary")
    a = ap.parse_args(argv)
    print("LOCAL memory backend (development only; the demo runs on AWS)", file=sys.stderr)
    log = (lambda s: None) if a.json else print
    out = scene_s2(log=log) if a.scene == "s2" else scene_s3(log=log, legit=not a.no_legit)
    print(json.dumps(out) if a.json else f"\nSCENE {a.scene.upper()} OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
