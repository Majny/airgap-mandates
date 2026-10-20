"""AirGap Mandates operations console (`make ui`): what the agent proposed, what the executor decided and why,
what waits for a hardware signature, payee changes, approvals, the signed mandate, audit and reports.
CONTRACTS.md §4. Owner: WS-F.

Untrusted host (TB3): it only reads the public executor API (`AIRGAP_EXECUTOR_URL`) and the frozen bench files.
`AIRGAP_EXECUTOR_URL=memory:` runs a seeded in-process executor (visual test, no AWS). The COMPROMISED switch
(`AIRGAP_UI_DEMO_TOOLS=1`) sends every view model through `host.compromised.lie()`: the device text is the only truth.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from urllib.parse import urlencode

# `streamlit run host/ui.py` puts only host/ on sys.path; infra/ (SigV4 signing) is not an installed package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from host import auth, compromised, story  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
EXECUTOR = os.environ.get("AIRGAP_EXECUTOR_URL", "http://127.0.0.1:8000")
DEMO_TOOLS = os.environ.get("AIRGAP_UI_DEMO_TOOLS") == "1"
REFRESH_S = int(os.environ.get("AIRGAP_UI_REFRESH_S", "5"))
FSM_STATES = ["PENDING_ATTEST", "CALLBACK_PENDING", "COOLING", "SIG_CLERK", "SIG_TREASURY", "ACTIVE"]
FSM_PLAIN = {"PENDING_ATTEST": "waiting for 2 of 3 confirmations", "CALLBACK_PENDING": "waiting for callback",
             "COOLING": "cooling-off", "SIG_CLERK": "waiting for clerk", "SIG_TREASURY": "waiting for treasury",
             "ACTIVE": "active", "REJECTED": "rejected", "EXPIRED": "expired"}
SEV_COLOUR = {"BLOCK": "#b42318", "WARN": "#b54708", "INFO": "#067647"}
CSS = """<style>
html, body, [class*="css"] { font-size: 18px; }
.block-container { padding-top: 3.2rem; max-width: 1400px; }
.device { font-family: 'JetBrains Mono', Menlo, monospace; font-size: 22px; line-height: 1.25; background: #111;
          color: #f5f5f5; padding: 12px 16px; border-radius: 10px; white-space: pre; display: inline-block; }
.fact { display: inline-block; padding: 3px 9px; margin: 2px; border-radius: 6px; color: white; font-weight: 600;
        font-size: 15px; }
.hint { display: inline-block; padding: 3px 9px; margin: 2px; border-radius: 6px; border: 2px dashed #98a2b3;
        color: #98a2b3; font-size: 15px; }
.banner-local { background: #b42318; color: white; padding: 6px 12px; border-radius: 8px; font-weight: 700; }
.banner-aws { background: #067647; color: white; padding: 6px 12px; border-radius: 8px; font-weight: 700; }
.card { border-left: 6px solid var(--c); padding: 10px 16px; margin: 0 0 10px 0; border-radius: 6px;
        background: rgba(127,127,127,0.08); }
.card .t { font-weight: 700; font-size: 20px; }
.card .b { opacity: 0.85; margin-top: 2px; }
.status { display: inline-block; padding: 2px 10px; border-radius: 999px; color: white; font-weight: 700; }
</style>"""
STATUS = {  # proposal status -> (plain label, colour)
    "EXECUTED": ("Paid", "#067647"), "CHALLENGED": ("Waiting for Trezor", "#1d4ed8"),
    "PENDING_SIG": ("Waiting for Trezor", "#1d4ed8"),
    "DENIED": ("Blocked", "#b42318"), "EXPIRED": ("Expired", "#475467"), "REJECTED": ("Rejected", "#b42318"),
}
WAITING_SIG = ("PENDING_SIG", "CHALLENGED")  # proposal statuses that need a hardware signature


def _memory_call() -> Any:
    """In-process executor on the memory backend, seeded and run through a normal day, a lookalike BEC with agent
    escalation, a mailbox takeover and a legitimate payee change (executor.scenes). Cached per Streamlit server."""
    import streamlit as st

    @st.cache_resource
    def env() -> Any:
        from executor import e2e, scenes
        from tools.local_stack import seed_pending_overcap
        e = scenes.DemoEnv()
        e2e.run(e.call, e.clerk, e.treasury, now=e.now, log=lambda s: None)
        scenes.scene_s2(e, log=lambda s: None)
        scenes.scene_s3(e, log=lambda s: None)
        # one over-cap payment left PENDING_SIG, so the Approve-on-Trezor button and the attack-h demo have a target
        seed_pending_overcap(e.call, e.now, data_dir=e.settings.data_dir)
        return e

    return env().call


_CALL: Any = None


def _call() -> Any:
    """SigV4 to the AWS regional API as the principal's IAM role (host.signer.executor_call); plain HTTP locally."""
    global _CALL
    if _CALL is None:
        if EXECUTOR.startswith("memory:"):
            _CALL = _memory_call()
        else:
            from host.signer import executor_call
            _CALL = executor_call(EXECUTOR)
    return _CALL


def api(path: str, who: str = "host", **query: Any) -> tuple[int, Any]:
    q = {k: v for k, v in query.items() if v is not None}
    try:
        return _call()("GET", path + ("?" + urlencode(q) if q else ""), None, who)
    except Exception as exc:  # noqa: BLE001 - unreachable executor, expired SSO credentials: show, never crash
        return 0, {"error": "unreachable", "message": f"{type(exc).__name__}: {exc}"[:300]}


def _login_expired(resp: Any) -> bool:
    """Expired operator credentials (SSO token, or a security token API Gateway refuses), not a broken executor."""
    text = str(resp.get("message", "")) if isinstance(resp, dict) else ""
    return "expired" in text.lower() and ("token" in text.lower() or "sso" in text.lower())


def _list(path: str, key: str, **query: Any) -> list[dict[str, Any]]:
    code, body = api(path, **query)
    return body.get(key, []) if code == 200 and isinstance(body, dict) else []


def export_bundle() -> dict[str, Any] | None:
    code, b = api("/audit/export", "auditor", log_id="audit", from_seq=0)
    return b if code == 200 and isinstance(b, dict) else None


_PAIN001: dict[tuple[str, str], dict[str, Any]] = {}  # (executor, tx_id) -> export; immutable once executed


def pain001(tx_id: str, who: str = "host") -> dict[str, Any] | None:
    """GET /export/pain001/{tx_id}, cached per process (the XML of an executed payment never changes)."""
    key = (EXECUTOR, tx_id)
    if key not in _PAIN001:
        code, b = api(f"/export/pain001/{tx_id}", who)
        if code != 200 or not isinstance(b, dict) or "xml" not in b:
            return None
        _PAIN001[key] = b
    return _PAIN001[key]


def c14n_sha256(xml: str) -> str:
    """The executor hashes the C14N of its element tree (no pretty-print whitespace); recompute that from the file."""
    from lxml import etree

    parser = etree.XMLParser(remove_blank_text=True, resolve_entities=False, no_network=True)
    root = etree.fromstring(xml.encode("utf-8"), parser)
    return hashlib.sha256(etree.tostring(root, method="c14n")).hexdigest()


def rail_hashes(bundle: dict[str, Any] | None) -> dict[str, tuple[int, str]]:
    """tx_id -> (seq, xml_c14n_sha256) of its first `rail_submitted` leaf in the witnessed log."""
    out: dict[str, tuple[int, str]] = {}
    for leaf in (bundle or {}).get("leaves", []):
        ev = leaf.get("event") or {}
        d = ev.get("data") or {}
        if ev.get("type") == "rail_submitted" and d.get("tx_id") and d["tx_id"] not in out:
            out[d["tx_id"]] = (int(leaf.get("seq", 0)), str(d.get("xml_c14n_sha256")))
    return out


def pain001_check(exp: dict[str, Any], logged: tuple[int, str] | None) -> tuple[bool, str]:
    """Three hashes must agree: recomputed from the XML bytes, the export's own claim, and the rail_submitted leaf."""
    try:
        h = c14n_sha256(exp["xml"])
    except Exception as e:  # noqa: BLE001 - malformed XML from a broken executor or proxy
        return False, f"XML does not parse ({type(e).__name__})"
    if h != exp.get("xml_c14n_sha256"):
        return False, "XML does not match the hash the executor sent with it"
    if logged is None:
        return False, "no rail_submitted entry in the audit log yet"
    if logged[1] != h:
        return False, f"XML hash differs from the audit log entry (seq {logged[0]})"
    return True, f"hash matches the signed audit log (seq {logged[0]})"


PAIN001_README = """One ISO 20022 pain.001.001.09 file per payment, exactly as the AirGap executor exported it.
Each file's C14N SHA-256 equals the `rail_submitted` entry of the signed, witnessed audit log (seq in manifest.json).
The files are deliberately not merged into one batch message: a merged file would get a new MsgId and a hash that
is not in the audit log. Import each file, or let core banking check each hash against the exported log first.
Payments whose hashes did not agree are listed under "excluded" in manifest.json and are not in this zip.
"""


def pain001_zip(day: str, txs: list[dict[str, Any]], exports: dict[str, dict[str, Any]],
                logged: dict[str, tuple[int, str]]) -> bytes:
    """One pain.001 file per payment (exactly the bytes the executor logged) + manifest.json + README.txt. Only
    payments whose three hashes agree go in; the others are listed in the manifest as `excluded` with the reason.
    Deterministic (fixed zip timestamps): the same day always gives the same zip."""
    files: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    buf = io.BytesIO()
    stamp = (2026, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for tx in txs:
            tx_id = tx["tx_id"]
            exp = exports.get(tx_id)
            ok, why = pain001_check(exp, logged.get(tx_id)) if exp else (False, "export unavailable")
            if not ok:
                excluded.append({"tx_id": tx_id, "reason": why})
                continue
            name = f"pain001-{tx_id}.xml"
            z.writestr(zipfile.ZipInfo(name, stamp), exp["xml"].encode("utf-8"))
            files.append({"file": name, "tx_id": tx_id, "msg_id": exp.get("msg_id"),
                          "xml_c14n_sha256": exp["xml_c14n_sha256"], "audit_seq": logged[tx_id][0],
                          "amount_minor": tx.get("amount_minor"), "currency": tx.get("currency"),
                          "vendor_id": tx.get("vendor_id"), "executed_at": tx.get("executed_at")})
        manifest = {"date_utc": day, "format": "pain.001.001.09", "files": files, "excluded": excluded,
                    "nb_of_txs": len(files), "ctrl_sum_minor": sum(int(f["amount_minor"] or 0) for f in files)}
        z.writestr(zipfile.ZipInfo("manifest.json", stamp), json.dumps(manifest, indent=2, sort_keys=True))
        z.writestr(zipfile.ZipInfo("README.txt", stamp), PAIN001_README)
    return buf.getvalue()


def executed_on(txs: list[dict[str, Any]]) -> list[str]:
    """Distinct UTC execution dates, newest first."""
    return sorted({str(t.get("executed_at", ""))[:10] for t in txs if t.get("executed_at")}, reverse=True)


def device_labels(bundle: dict[str, Any] | None) -> dict[str, str]:
    """address -> GENUINE | EMULATOR, from the `enroll` leaves (set by the enrolment tool, never by the host)."""
    out: dict[str, str] = {}
    for leaf in (bundle or {}).get("leaves", []):
        ev = leaf.get("event") or {}
        if ev.get("type") == "enroll":
            d = ev.get("data") or {}
            out[str(d.get("address", "")).lower()] = d.get("device") or "UNKNOWN"
    return out


def emulator_only() -> bool:
    """WS-C fallback mode: the clerk signs on the emulator (AIRGAP_TREZOR_PATH=udp:...)."""
    try:
        from host import signer
        fn = getattr(signer, "emulator_only", None)
        if fn is not None:
            return bool(fn())
    except Exception:  # noqa: BLE001 - signer extras (trezorlib) may be missing on a UI-only laptop
        pass
    return os.environ.get("AIRGAP_TREZOR_PATH", "").startswith("udp:")


def device_chip(label: str) -> str:
    colour = {"GENUINE": "#067647", "EMULATOR": "#b54708"}.get(label, "#475467")
    return f'<span class="fact" style="background:{colour}">{label}</span>'


def view(v: dict[str, Any]) -> dict[str, Any]:
    """Everything the host shows passes here; a compromised host rewrites it."""
    return compromised.lie(v) if compromised.is_compromised() else v


def fact_chips(facts: list[dict[str, Any]]) -> str:
    chips = []
    for f in facts:
        if f.get("kind") == "H":
            chips.append(f'<span class="hint">agent claim (ignored): {f.get("display_line", "")[:60]}</span>')
        else:
            colour = SEV_COLOUR.get(f.get("severity", "INFO"), "#475467")
            title = str(f.get("label", "")).replace('"', "'")
            chips.append(f'<span class="fact" title="{title}" style="background:{colour}">'
                         f'{f.get("display_line", f.get("id"))}</span>')
    return " ".join(chips)


def _ts(v: Any) -> str:
    return str(v or "")[:16].replace("T", " ")


def status_chip(label: str, colour: str) -> str:
    return f'<span class="status" style="background:{colour}">{label}</span>'


def proposal_view(p: dict[str, Any], names: dict[str, str]) -> dict[str, Any]:
    dec = p.get("decision", {})
    return {"kind": "pay", "id": p["proposal_id"], "vendor_id": p["vendor_id"],
            "vendor_name": names.get(p["vendor_id"], p["vendor_id"]),
            "amount_minor": p["invoice"]["amount_minor"], "expected_amount_minor": p["invoice"]["amount_minor"],
            "status": p.get("status"), "decision": dec.get("decision"), "rule_ids": dec.get("rule_ids", []),
            "facts": p.get("facts", []), "challenge": dec.get("challenge")}


def render_cards(st: Any, cards: list[dict[str, Any]]) -> None:
    for c in cards:
        icon, colour = story.TONES[c["tone"]]
        body = f'<div class="b">{c["body"]}</div>' if c["body"] else ""
        st.markdown(f'<div class="card" style="--c:{colour}"><div class="t">{icon} {c["title"]}</div>{body}</div>',
                    unsafe_allow_html=True)
        if c.get("device"):
            st.markdown(f'<div class="device">{c["device"]}</div>', unsafe_allow_html=True)


def tab_overview(st: Any, data: dict[str, Any]) -> None:
    if not data["cards"]:
        st.info("No activity yet.")
    render_cards(st, data["cards"])


def pain001_batch(st: Any, data: dict[str, Any]) -> None:
    txs = data.get("ledger") or []
    days = executed_on(txs)
    if not days:
        return
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with st.container(border=True):
        c1, c2 = st.columns([2, 3])
        day = c1.selectbox("Payments executed on (UTC)", days, index=days.index(today) if today in days else 0,
                           format_func=lambda d: f"{d} (today)" if d == today else d)
        day_txs = [t for t in txs if str(t.get("executed_at", "")).startswith(day)]
        exports = {t["tx_id"]: e for t in day_txs if (e := pain001(t["tx_id"])) is not None}
        what = "today's" if day == today else day
        c2.download_button(f"Download {what} payments as pain.001 files (zip, {len(day_txs)})",
                           pain001_zip(day, day_txs, exports, data["rail"]), file_name=f"pain001-{day}.zip",
                           mime="application/zip", on_click="ignore", key=f"pain001-zip-{day}", type="primary")
        c2.caption("For core banking: one ISO 20022 pain.001 file per payment, each checked against the signed "
                   "audit log, plus a manifest. Not merged into one batch message, because a merged file would "
                   "carry a hash that is not in the log.")


def approve_on_trezor(st: Any, nonce: str, role: str, *, key: str) -> None:
    """Operator presses this to exact-sign a waiting payment on the clerk's Trezor. The honest flow shows the executor
    text on the device and pays on confirm. If the clerk's PC is compromised (host.implant, attacker level H4) the
    device shows the attacker's IBAN instead — this console never reveals that — and the outcome is mapped to a plain
    message. Never crashes when no device is attached."""
    from host import signer

    if not st.button("Approve on Trezor", key=f"approve-{key}", type="primary"):
        return
    driver = None
    try:
        if signer.software_clerk_allowed(EXECUTOR):
            driver = signer.software_clerk_driver()
    except Exception:  # noqa: BLE001 - fall back to the physical device path
        driver = None
    note = ("Signing with a software key (test)." if driver is not None
            else "Check the Trezor: confirm only if payee, IBAN and amount match the invoice.")
    try:
        with st.spinner(note):
            res = signer.sign_challenge(nonce, role, call=_call(), driver=driver)
    except signer.SignerCancelled:
        st.warning("You rejected it on the Trezor. Nothing was paid; the payment still waits for approval.")
        return
    except TimeoutError:
        st.warning("No confirmation on the Trezor in time. Nothing was paid; the payment still waits for approval.")
        return
    except Exception as exc:  # noqa: BLE001 - no device attached, trezorlib missing, transport error: never crash
        st.error(f"No Trezor connected ({type(exc).__name__}). Attach the clerk's Safe 3 and try again.")
        return
    http, err = res.get("_http"), res.get("error")
    eff = (res.get("effect") or {}).get("type")
    if http == 200 and eff == "payment_executed":
        st.success("Paid · confirmed on Trezor.")
    elif err == "render_mismatch":
        st.error("Refused by the executor: the Trezor was asked to sign a different payment than the bank issued "
                 "(the account number was changed on this PC). Nothing was paid. Treat this PC as compromised.")
    elif err:
        st.error(f"Refused by the executor: {err}. Nothing was paid.")
    else:
        st.info(f"Signature submitted: {eff or 'done'}.")


def tab_payments(st: Any, data: dict[str, Any]) -> None:
    if not data["proposals"]:
        st.info("No payment proposals yet.")
    pain001_batch(st, data)
    for p in data["proposals"]:
        v = view(proposal_view(p, data["names"]))
        label, colour = STATUS.get(v.get("status") or "", (str(v.get("status")), "#475467"))
        if v.get("status") == "EXECUTED":
            label += " · confirmed on Trezor" if v.get("decision") == "challenge" else " · within mandate"
        inv = p.get("invoice") or {}
        with st.container(border=True):
            c1, c2 = st.columns([4, 2])
            c1.markdown(f"**{v['vendor_name']}** · invoice {inv.get('invoice_no', '-')} · "
                        f"**{story.czk(v['amount_minor'])}**")
            c2.markdown(status_chip(label, colour), unsafe_allow_html=True)
            blocks = story._reasons(v.get("facts", []), ("BLOCK", "WARN"))
            if blocks and v.get("status") == "EXECUTED":
                st.markdown(f"{blocks}: the clerk confirmed the exact amount and account on the Trezor.")
            elif blocks:
                st.markdown(f"Why: {blocks}")
            ch = v.get("challenge")
            if ch and v.get("status") in WAITING_SIG:
                st.caption("Exactly this text is on the clerk's Trezor. The device signs what it shows, "
                           "not what this screen shows.")
                st.markdown(f'<div class="device">{ch["text"]}</div>', unsafe_allow_html=True)
                if data.get("who") == "host" and ch.get("nonce"):  # operators only; auditors never reach this tab
                    approve_on_trezor(st, ch["nonce"], ch.get("role", "clerk"), key=p["proposal_id"])
            tx_id = p.get("tx_id")
            if p.get("status") == "EXECUTED" and tx_id:
                exp = pain001(tx_id)
                d1, d2 = st.columns([1, 4], vertical_alignment="center")
                if exp is None:
                    d2.caption("pain.001 export unavailable")
                else:
                    ok, why = pain001_check(exp, data["rail"].get(tx_id))
                    d1.download_button("pain.001 (ISO 20022)", exp["xml"].encode("utf-8"),
                                       file_name=f"pain001-{tx_id}.xml", mime="application/xml",
                                       on_click="ignore", key=f"pain001-{tx_id}", disabled=not ok)
                    d2.caption(("✓ " if ok else "✗ ") + why)
            with st.expander("Facts checked by the executor"):
                st.markdown(fact_chips(v.get("facts", [])), unsafe_allow_html=True)
                st.caption(f"{v['id']} · rules {', '.join(v.get('rule_ids') or []) or '-'}"
                           + (f" · {tx_id}" if tx_id else ""))


def tab_changes(st: Any, data: dict[str, Any]) -> None:
    if not data["changes"]:
        st.info("No payee changes yet.")
    for c in data["changes"]:
        v = view({"kind": "change", "vendor_id": c.get("vendor_id"),
                  "vendor_name": c.get("vendor_name") or data["names"].get(c.get("vendor_id"), c.get("vendor_id")),
                  "iban": c.get("new_iban"), "registry_iban": c.get("old_iban"), "facts": c.get("facts", [])})
        state = c.get("state", "")
        colour = {"ACTIVE": "#067647", "REJECTED": "#b42318", "EXPIRED": "#475467"}.get(state, "#1d4ed8")
        with st.container(border=True):
            c1, c2 = st.columns([4, 2])
            c1.markdown(f"**{v['vendor_name']}** · `{c.get('old_iban')}` → `{v.get('iban')}`")
            c2.markdown(status_chip(FSM_PLAIN.get(state, state), colour), unsafe_allow_html=True)
            if state not in ("REJECTED", "EXPIRED"):
                steps = [f"**{FSM_PLAIN[s]}**" if s == state else FSM_PLAIN[s] for s in FSM_STATES]
                st.markdown(" → ".join(steps))
            hist = c.get("history") or []
            if hist:
                st.markdown(f"Last step: {story.plain_reason(str(hist[-1].get('reason', '')))}")
            blocks = story._reasons(v.get("facts", []))
            if blocks:
                st.markdown(f"Why blocked: {blocks}")
            with st.expander("Facts checked by the executor"):
                st.markdown(fact_chips(v.get("facts", [])), unsafe_allow_html=True)
                st.caption(f"{c.get('change_id')} · {c.get('attest_count', 0)}/3 confirmations")


def tab_approvals(st: Any, data: dict[str, Any]) -> None:
    bundle = data["bundle"]
    if bundle is None:
        st.info("audit export unavailable")
        return
    labels = device_labels(bundle)
    sigs = [leaf for leaf in bundle.get("leaves", []) if (leaf.get("event") or {}).get("type") == "signature"]
    if not sigs:
        st.caption("no approvals yet")
    for leaf in reversed(sigs[-50:]):
        ev = leaf["event"]
        d = ev.get("data") or {}
        addr = str(d.get("signer_address") or "").lower()
        label = labels.get(addr, "NOT ENROLLED" if addr else "-")
        ok = d.get("accepted")
        outcome = status_chip("accepted", "#067647") if ok else status_chip(f"refused: {d.get('error')}", "#b42318")
        st.markdown(f"{_ts(ev.get('ts'))} · **{d.get('purpose')}** · {d.get('role')} · "
                    f"`{addr[:10]}…` {device_chip(label)} {outcome} · `{ev.get('subject_id')}`",
                    unsafe_allow_html=True)


def tab_mandate(st: Any, data: dict[str, Any]) -> None:
    code, m = api("/mandates/active")
    if code != 200 or not isinstance(m, dict) or not m.get("mandate_id"):
        st.info("No active mandate: every payment needs a hardware signature.")
        return
    c1, c2, c3 = st.columns(3)
    c1.metric("Per payment", story.czk(m.get("max_per_payment_minor")))
    c2.metric("Total", story.czk(m.get("max_total_minor")))
    c3.metric("Payments", f"{m.get('count', 0)} / {m.get('max_count')}")
    spent, total = m.get("spent_minor") or 0, m.get("max_total_minor") or 1
    st.progress(min(spent / total, 1.0), text=f"Spent {story.czk(spent)} of {story.czk(total)}")
    scope = "existing payees only" if m.get("payee_scope") == "existing_only" else m.get("payee_scope")
    st.markdown(f"Valid {_ts(m.get('valid_from'))} → {_ts(m.get('valid_until'))} UTC · {scope} · "
                f"Verification of Payee required: {', '.join(m.get('require_vop') or [])}")
    labels = device_labels(data["bundle"])
    for s in m.get("signers") or []:
        st.markdown(f"Signed by **{s.get('role')}** `{s.get('address', '')[:10]}…` "
                    f"{device_chip(labels.get(str(s.get('address', '')).lower(), 'NOT ENROLLED'))} "
                    f"at {_ts(s.get('signed_at'))} UTC", unsafe_allow_html=True)
    st.caption(f"{m.get('mandate_id')} · policy {str(m.get('policy_hash'))[:16]}")


def tab_receipts(st: Any, who: str = "host") -> None:
    tx_id = st.text_input("Transaction ID (tx_...)")
    if not tx_id:
        return
    code, r = api(f"/receipts/{tx_id}", who)
    if code != 200:
        st.warning(r)
        return
    try:  # short URL-form QR (AGR2, ~v8): scans with a stock phone camera; the full AGR1 receipt is file-only
        from executor.audit.receipt import short_qr_payload, short_qr_png
        st.image(short_qr_png(r), width=360)
        st.code(short_qr_payload(r), language="text")
        st.caption("scan → the verifier checks this receipt offline against the signed log")
    except (ImportError, NotImplementedError, RuntimeError) as exc:  # RuntimeError: segno missing
        st.info(f"receipt QR unavailable ({exc}); install the [ui] extra (segno)")
    st.json(r, expanded=False)


def tab_audit(st: Any, data: dict[str, Any]) -> None:
    code, note = api("/checkpoint", data.get("who", "host"), log_id="audit")
    st.markdown("**Latest signed checkpoint** (log key + witnesses)")
    st.code(note if code == 200 else f"unavailable: {note}", language="text")
    if st.button("Verify the full audit log now"):
        bundle = export_bundle()
        if bundle is None:
            st.error("audit export unavailable")
        else:
            try:
                from tools.verify_audit import verify
                rep = verify(bundle, replay=True)
                st.success(f"verify_audit: {rep}") if getattr(rep, "ok", False) else st.error(f"verify_audit: {rep}")
            except NotImplementedError:
                st.info("verify_audit not available on this build")
    st.caption("This page is rendered by the host and could lie. The proof is the offline check: "
               "python -m tools.verify_audit on an exported bundle, with keys obtained out of band.")
    with st.expander("Supervisor view of the log"):
        try:
            from witness.supervisor import render_html
            import streamlit.components.v1 as components
            if data["bundle"] is not None:
                components.html(render_html(data["bundle"], allow_uncovered_tail=True), height=620, scrolling=True)
        except ImportError:
            st.info("supervisor view not available on this build")
    st.markdown("**Receipts**")
    tab_receipts(st, data.get("who", "host"))


def tab_reports(st: Any) -> None:
    with st.expander("Attack benchmark (frozen runs)", expanded=True):
        st.caption("Frozen runs only (bench/results/FROZEN.md). Simulated humans are a model of a human, "
                   "not a user study.")
        # REPORT.md is the frozen page; report("bench/results") would also pull superseded and check-only runs
        st.markdown((ROOT / "bench" / "results" / "REPORT.md").read_text())
    with st.expander("AWS deployment evidence"):
        ev = ROOT / "infra" / "evidence"
        files = sorted(f for f in ev.glob("*") if f.suffix in (".json", ".txt")) if ev.exists() else []
        if not files:
            st.info("no evidence captured yet")
        for f in files:
            st.markdown(f"**{f.name}**")
            st.json(json.loads(f.read_text()), expanded=False) if f.suffix == ".json" else st.code(f.read_text())


def load(ident: auth.Identity) -> dict[str, Any]:
    """Operators: everything. Auditors: the audit export only, read with the auditor principal (no vendor master,
    proposals or payee changes are fetched for them, so none can leak into the page)."""
    if ident.role == "auditor":
        return {"who": ident.principal, "bundle": export_bundle()}
    vendors = _list("/vendors", "vendors")
    proposals = _list("/proposals", "proposals", limit=50)
    changes = _list("/changes", "changes")
    ledger = _list("/ledger", "txs")
    bundle = export_bundle()
    kpis, cards = story.build(bundle, vendors, changes, proposals)
    return {"who": ident.principal, "vendors": vendors,
            "names": {v["vendor_id"]: v.get("name") or v["vendor_id"] for v in vendors},
            "proposals": proposals, "changes": changes, "ledger": ledger, "bundle": bundle,
            "rail": rail_hashes(bundle), "kpis": kpis, "cards": cards}


TAB_RENDER = {
    "Overview": tab_overview, "Payments": tab_payments, "Payee changes": tab_changes, "Approvals": tab_approvals,
    "Mandate": tab_mandate, "Audit": tab_audit, "Reports": lambda st, data: tab_reports(st),
}


def body(st: Any, ident: auth.Identity | None = None) -> None:
    ident = ident or auth.Identity("local", "operator")
    data = load(ident)
    if ident.role == "operator":
        k = data["kpis"]
        waiting = [p for p in data["proposals"] if p.get("status") in WAITING_SIG]
        waiting += [c for c in data["changes"] if c.get("state") in ("SIG_CLERK", "SIG_TREASURY")]
        if waiting:
            st.warning(f"{len(waiting)} item(s) waiting for a hardware signature. Open the Payments tab and check the "
                       "text on the Trezor before you approve.")
        m = st.columns(4)
        m[0].metric("Paid to registered suppliers", story.czk(k["paid_minor"]), f"{k['paid_n']} payment{'' if k['paid_n'] == 1 else 's'}",
                    delta_color="off")
        m[1].metric("Paid to unregistered accounts", story.czk(k["attacker_minor"]))
        m[2].metric("Blocked attempts", k["attacks"])
        m[3].metric("Paid without a human", f"{k['auto_n']} of {k['paid_n']}", "inside the signed mandate",
                    delta_color="off")
    names = list(ident.tabs)
    for tab, name in zip(st.tabs(names), names):
        with tab:
            TAB_RENDER[name](st, data)


def main() -> None:
    """Streamlit entry point."""
    import streamlit as st

    st.set_page_config(page_title="AirGap Mandates", layout="wide", initial_sidebar_state="collapsed")
    st.markdown(CSS, unsafe_allow_html=True)
    ident = auth.gate(st)
    if ident is None:  # sign-in page or refusal already rendered; nothing else is fetched or shown
        return
    code, health = api("/health", ident.principal)
    backend = health.get("backend") if isinstance(health, dict) else None
    if backend == "aws":
        cls, label = "banner-aws", f"AWS eu-central-1 · {health.get('deployment')}"
    elif EXECUTOR.startswith("memory:") and backend:
        cls, label = "banner-local", "LOCAL in-process executor (seeded test data)"
    elif _login_expired(health):
        cls, label = "banner-local", "AWS sign-in expired"
    else:
        cls, label = "banner-local", f"LOCAL ({backend or 'executor unreachable'})"
    h1, h2 = st.columns([3, 2])
    h1.markdown("## AirGap Mandates  \nPayment control for AI agents")
    policy = str(health.get("policy_hash") or "-")[:16] if isinstance(health, dict) else "-"
    who = "Console: local, no SSO" if ident.mode == "local" else f"Signed in: {ident.email} ({ident.role})"
    h2.markdown(f'<div style="text-align:right"><span class="{cls}">{label}</span><br>'
                f'<small>policy {policy} · {who}</small></div>', unsafe_allow_html=True)
    if ident.mode == "sso":
        with st.sidebar:
            st.markdown(f"Signed in as **{ident.email}**  \nRole: **{ident.role}**")
            if st.button("Sign out"):
                st.logout()
    if _login_expired(health):
        st.error("The console's AWS sign-in has expired, so it cannot read the executor. Sign in again "
                 "(`aws sso login --profile hackathon`), then reload this page.")
    elif code != 200:
        st.error(f"executor: {health}")
    if emulator_only():
        st.markdown('<span class="banner-local">FALLBACK: EMULATOR CLERK (no physical Safe 3 attached)</span>',
                    unsafe_allow_html=True)
    if DEMO_TOOLS and ident.mode == "local":  # the stage "compromised host" switch never exists behind SSO
        with st.sidebar:
            on = st.toggle("COMPROMISED host", value=compromised.is_compromised(),
                           help="The UI lies (H1). The device text and the executor are unaffected.")
            compromised.set_compromised(on)
    if compromised.is_compromised():
        st.markdown('<span class="banner-local">COMPROMISED HOST: this screen may lie, trust the device</span>',
                    unsafe_allow_html=True)
    if REFRESH_S > 0 and hasattr(st, "fragment"):
        st.fragment(run_every=REFRESH_S)(body)(st, ident)
    else:
        body(st, ident)


if __name__ == "__main__":
    main()
