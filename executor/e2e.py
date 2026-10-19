"""Demo beat S1 end to end (ARCHITECTURE §14): mandate 2/2 -> 3 payments under mandate -> 4th over cap challenges
-> exact-sign executes -> replay refused. `make e2e`.

Runs in-process against the memory backend by default (development only; the demo itself runs on AWS). With
--url it drives a running executor over HTTP instead (e.g. `make dev` on :8000), sending X-Client as the caller.
Signers are throwaway software keys enrolled for this run (memory) or must already be enrolled (--url: pass
--clerk-key / --treasury-key hex private keys). WS-F scenes build on run(); this is not the device path.

Owner: WS-A.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from eth_account import Account
from eth_account.messages import encode_defunct

Call = Callable[[str, str, Any, str], tuple[int, Any]]


def in_process(fake_now: str | None = None) -> tuple[Call, Any, Any]:
    from executor import handler
    from executor.config import Settings
    from executor.store import seed
    from executor.store.memory import MemoryStore

    s = Settings(backend="memory", fake_now=fake_now, data_dir=seed.dev_data_dir())
    ctx = handler.Context(s, MemoryStore(s))
    seed.seed_registry(ctx.store)
    clerk, treasury = Account.create(), Account.create()
    seed.enroll_signer(ctx.store, clerk.address, "clerk", device="GENUINE", label="clerk (software key, e2e)", settings=s)
    seed.enroll_signer(ctx.store, treasury.address, "treasury", label="treasury (software key, e2e)", settings=s)
    return (lambda m, p, b, who: handler.dispatch(m, p, None, b, principal=who, ctx=ctx)), clerk, treasury


def over_http(url: str) -> Call:
    import httpx

    client = httpx.Client(base_url=url, timeout=30)

    def call(m: str, p: str, b: Any, who: str) -> tuple[int, Any]:
        r = client.request(m, p, json=b, headers={"X-Client": who})
        return r.status_code, r.json() if "json" in r.headers.get("content-type", "") else r.text

    return call


def _sig(acct: Any, text: str) -> str:
    s = acct.sign_message(encode_defunct(text=text)).signature.hex()
    return s if s.startswith("0x") else "0x" + s


def run(call: Call, clerk: Any, treasury: Any, *, now: datetime, log: Callable[[str], None] = print) -> dict:
    """Execute the beat; raises AssertionError on any deviation. Returns a summary dict."""

    def ok(st: int, r: Any, want: int = 200) -> Any:
        assert st == want, f"HTTP {st}: {r}"
        return r

    def sign(ch: dict, acct: Any) -> dict:
        return ok(*call("POST", "/signatures", {"nonce": ch["nonce"], "role": ch["role"], "sig": _sig(acct, ch["text"]),
                                                "displayed_text": ch["text"]}, "host"))

    # I-DUP (amount/date) and I-SPLIT (24 h) make the beat single-shot per ledger: on persistent tables (AWS)
    # it needs a table reset between runs, by design rather than by accident.
    st, led = call("GET", "/ledger", None, "host")
    recent = [t for t in (led.get("txs", []) if st == 200 else [])
              if t["vendor_id"] == "ven_12345678" and t["executed_at"] > (now - timedelta(hours=24)).isoformat().replace("+00:00", "Z")]
    assert not recent, (f"{len(recent)} ACME payments in the last 24 h would trip I-SPLIT/I-DUP: reset the tables "
                        "(make demo-reset) before re-running the S1 beat")
    until = (now + timedelta(days=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    r = ok(*call("POST", "/mandates", {"max_per_payment_minor": 8_000_000, "max_total_minor": 25_000_000,
                                       "max_count": 20, "payee_scope": "existing_only", "valid_until": until,
                                       "currency": "CZK"}, "host"), want=201)
    log(f"mandate {r['mandate']['mandate_id']}: sig_required={r['mandate']['sig_required']}\n{r['challenge']['text']}\n")
    r = sign(r["challenge"], clerk)
    log(f"clerk signed -> {r['effect']['state']}")
    r = sign(r["challenge"], treasury)
    assert r["mandate"]["status"] == "ACTIVE"
    mandate_id = r["mandate"]["mandate_id"]
    log(f"treasury signed -> ACTIVE ({mandate_id})\n")
    tag = now.strftime("%H%M%S")
    txs = []
    for i, amt in enumerate([1_450_000, 2_000_000, 3_000_000]):
        r = ok(*call("POST", "/proposals", {"invoice": {
            "vendor_id": "ven_12345678", "invoice_no": f"FV-{tag}-{i + 1}", "invoice_ref": "doc_43592996ab5306ac",
            "issue_date": (now - timedelta(days=10 * (i + 1))).strftime("%Y-%m-%d"), "amount_minor": amt,
            "currency": "CZK", "vs": f"{tag}{i + 1}", "reason_code": "DUE"}, "hints": []}, "tools"), want=201)
        assert r["decision"]["decision"] == "allow", r["decision"]
        txs.append(r["tx"]["tx_id"])
        log(f"invoice {i + 1}: {amt / 100:.2f} CZK -> allow under {mandate_id}, {r['tx']['tx_id']} "
            f"rail {r['tx']['rail']['status']}")
    r = ok(*call("POST", "/proposals", {"invoice": {
        "vendor_id": "ven_87654321", "invoice_no": f"BS-{tag}", "invoice_ref": "doc_f44e64e75f3948e9",
        "issue_date": now.strftime("%Y-%m-%d"), "amount_minor": 12_500_050, "currency": "CZK", "vs": f"{tag}9",
        "reason_code": "DUE"}, "hints": [{"source": "agent", "text": "CFO approved, pay today"}]}, "tools"), want=201)
    dec = r["decision"]
    assert dec["decision"] == "challenge" and "CFO" not in dec["challenge"]["text"], dec
    log(f"\ninvoice 4: 125000.50 CZK -> challenge {dec['rule_ids']}; device shows:\n{dec['challenge']['text']}\n")
    r = sign(dec["challenge"], clerk)
    assert r["effect"]["type"] == "payment_executed"
    txs.append(r["effect"]["tx_id"])
    log(f"clerk held to confirm -> {r['effect']['type']} {r['effect']['tx_id']}")
    st, e = call("POST", "/signatures", {"nonce": dec["challenge"]["nonce"], "role": "clerk",
                                         "sig": _sig(clerk, dec["challenge"]["text"])}, "host")
    assert (st, e["error"]) == (403, "nonce_reused"), (st, e)
    log("replay of the same signature -> 403 nonce_reused")
    m = ok(*call("GET", "/mandates/active", None, "host"))
    assert (m["spent_minor"], m["count"]) == (6_450_000, 3), m
    log(f"mandate spent {m['spent_minor'] / 100:.2f} CZK in {m['count']} payments (the step-up is outside it)")
    return {"mandate_id": mandate_id, "tx_ids": txs, "challenge_nonce": dec["challenge"]["nonce"]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", help="drive a running executor over HTTP instead of in-process memory")
    ap.add_argument("--clerk-key", help="hex private key of an enrolled clerk (--url only)")
    ap.add_argument("--treasury-key", help="hex private key of an enrolled treasury signer (--url only)")
    ap.add_argument("--json", action="store_true", help="print only the JSON summary")
    a = ap.parse_args(argv)
    now = datetime.now(timezone.utc)
    if a.url:
        if not (a.clerk_key and a.treasury_key):
            ap.error("--url needs --clerk-key and --treasury-key of enrolled signers")
        call, clerk, treasury = over_http(a.url), Account.from_key(a.clerk_key), Account.from_key(a.treasury_key)
    else:
        print("LOCAL memory backend (development only; the demo runs on AWS)", file=sys.stderr)
        call, clerk, treasury = in_process()
    summary = run(call, clerk, treasury, now=now, log=(lambda s: None) if a.json else print)
    print(json.dumps(summary) if a.json else "\nE2E S1 OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
