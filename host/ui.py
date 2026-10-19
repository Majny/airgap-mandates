"""Streamlit ops console (`make ui`): agent activity, facts [F] vs [H], decisions + rule IDs, COMPROMISED switch,
payee-change FSM, receipts, audit, AWS evidence, bench table. CONTRACTS.md §4, ARCHITECTURE §14. Owner: WS-F.

Untrusted host (TB3): it only reads the public executor API (`AIRGAP_EXECUTOR_URL`) and the frozen bench files.
With COMPROMISED on, every view model goes through `host.compromised.lie()` - the device text is the only truth.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx

from host import compromised

EXECUTOR = os.environ.get("AIRGAP_EXECUTOR_URL", "http://127.0.0.1:8000")
FSM_STATES = ["PENDING_ATTEST", "CALLBACK_PENDING", "COOLING", "SIG_CLERK", "SIG_TREASURY", "ACTIVE"]
SEV_COLOUR = {"BLOCK": "#b42318", "WARN": "#b54708", "INFO": "#067647"}
CSS = """<style>
html, body, [class*="css"] { font-size: 20px; }
.device { font-family: 'JetBrains Mono', Menlo, monospace; font-size: 26px; line-height: 1.25; background: #111;
          color: #f5f5f5; padding: 14px 18px; border-radius: 10px; white-space: pre; display: inline-block; }
.fact { display: inline-block; padding: 4px 10px; margin: 3px; border-radius: 6px; color: white; font-weight: 600; }
.hint { display: inline-block; padding: 4px 10px; margin: 3px; border-radius: 6px; border: 2px dashed #98a2b3;
        color: #475467; }
.banner-local { background: #b42318; color: white; padding: 8px 14px; border-radius: 8px; font-weight: 700; }
.banner-aws { background: #067647; color: white; padding: 8px 14px; border-radius: 8px; font-weight: 700; }
</style>"""


def api(path: str, **query: Any) -> tuple[int, Any]:
    try:
        r = httpx.get(EXECUTOR + path, params={k: v for k, v in query.items() if v is not None}, timeout=5)
    except httpx.HTTPError as exc:
        return 0, {"error": "unreachable", "message": str(exc)}
    ct = r.headers.get("content-type", "")
    return r.status_code, (r.json() if "json" in ct else r.text)


def view(v: dict[str, Any]) -> dict[str, Any]:
    """Everything the host shows passes here; a compromised host rewrites it."""
    return compromised.lie(v) if compromised.is_compromised() else v


def fact_chips(facts: list[dict[str, Any]]) -> str:
    chips = []
    for f in facts:
        if f.get("kind") == "H":
            chips.append(f'<span class="hint">[H] {f.get("display_line", "")[:60]}</span>')
        else:
            colour = SEV_COLOUR.get(f.get("severity", "INFO"), "#475467")
            chips.append(f'<span class="fact" style="background:{colour}">[F] {f.get("display_line", f.get("id"))}</span>')
    return " ".join(chips)


def proposal_view(p: dict[str, Any]) -> dict[str, Any]:
    dec = p.get("decision", {})
    return {"kind": "pay", "id": p["proposal_id"], "vendor_id": p["vendor_id"], "vendor_name": p["vendor_id"],
            "amount_minor": p["invoice"]["amount_minor"], "expected_amount_minor": p["invoice"]["amount_minor"],
            "status": p.get("status"), "decision": dec.get("decision"), "rule_ids": dec.get("rule_ids", []),
            "facts": p.get("facts", []), "challenge": dec.get("challenge")}


def tab_activity(st: Any) -> None:
    code, body = api("/proposals", limit=30)
    if code != 200:
        st.info(f"executor: {body}")
        return
    for p in body.get("proposals", []):
        v = view(proposal_view(p))
        with st.container(border=True):
            c1, c2 = st.columns([3, 2])
            c1.markdown(f"**{v['id']}** · {v['vendor_id']} · **{v['amount_minor'] / 100:,.2f} CZK**")
            decision = v.get("decision") or "-"
            c2.markdown(f"decision **{decision.upper()}** · rules `{', '.join(v.get('rule_ids') or []) or '-'}`")
            st.markdown(fact_chips(v.get("facts", [])), unsafe_allow_html=True)
            ch = p.get("decision", {}).get("challenge")
            if ch:
                st.caption("Device text (rendered by the executor; the host cannot change what the device signs)")
                st.markdown(f'<div class="device">{ch["text"]}</div>', unsafe_allow_html=True)
            if decision == "deny":
                st.caption("R0: nothing to approve - the device stays dark.")


def tab_changes(st: Any) -> None:
    code, body = api("/changes")
    if code != 200:
        st.info(f"executor: {body}")
        return
    for c in body.get("changes", []):
        v = view({"kind": "change", "vendor_id": c.get("vendor_id"), "vendor_name": c.get("vendor_id"),
                  "iban": c.get("new_iban"), "registry_iban": c.get("old_iban"), "facts": c.get("facts", [])})
        with st.container(border=True):
            st.markdown(f"**{c.get('change_id')}** · {v['vendor_id']} → `{v.get('iban')}`")
            state = c.get("state", "")
            steps = [f"**[{s}]**" if s == state else s for s in FSM_STATES]
            st.markdown(" → ".join(steps) + (f" · **{state}**" if state in ("REJECTED", "EXPIRED") else ""))
            st.markdown(fact_chips(v.get("facts", [])), unsafe_allow_html=True)


def tab_receipts(st: Any) -> None:
    tx_id = st.text_input("tx_id")
    if not tx_id:
        return
    code, r = api(f"/receipts/{tx_id}")
    if code != 200:
        st.warning(r)
        return
    payload = json.dumps(r, separators=(",", ":"))
    import streamlit.components.v1 as components  # QR rendered client-side; offline fallback = the JSON below
    components.html(f"""<div id="qr"></div><script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js">
    </script><script>new QRCode(document.getElementById("qr"), {{text: {json.dumps(payload[:2900])}, width: 320,
    height: 320, correctLevel: QRCode.CorrectLevel.L}});</script>""", height=340)
    st.json(r, expanded=False)


def tab_audit(st: Any) -> None:
    code, note = api("/checkpoint", log_id="audit")
    st.markdown("**Latest checkpoint (C2SP signed note)**")
    st.code(note if code == 200 else f"unavailable: {note}", language="text")
    if st.button("Verify export bundle now"):
        code, bundle = api("/audit/export", log_id="audit", from_seq=0)
        if code != 200:
            st.error(bundle)
            return
        try:
            from tools.verify_audit import verify
            rep = verify(bundle, replay=True)
            st.success(f"verify_audit: {rep}") if getattr(rep, "ok", False) else st.error(f"verify_audit: {rep}")
        except NotImplementedError:
            st.info("verify_audit not merged yet (WS-B)")


def tab_evidence(st: Any) -> None:
    st.caption("AWS evidence (eu-central-1). Files under demo/evidence/ are captured in rehearsal and labelled so.")
    files = sorted(Path("demo/evidence").glob("*.json")) if Path("demo/evidence").exists() else []
    if not files:
        st.info("no evidence captured yet (WS-E probes: simulate-principal-policy, AccessDenied, Object Lock, Flow Logs)")
    for f in files:
        with st.expander(f.stem):
            st.json(json.loads(f.read_text()))


def tab_bench(st: Any) -> None:
    from bench.report import report
    st.caption("Frozen runs only (bench/results/FROZEN.md). Simulated humans are a model of a human, not a user study.")
    st.markdown(report("bench/results"))


def main() -> None:
    """Streamlit entry point."""
    import streamlit as st

    st.set_page_config(page_title="AirGap Mandates - ops console", layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)
    code, health = api("/health")
    backend = health.get("backend") if isinstance(health, dict) else None
    cls, label = ("banner-aws", "AWS eu-central-1") if backend == "aws" else ("banner-local", f"LOCAL ({backend or 'executor unreachable'}) - not the demo")
    st.markdown(f'<span class="{cls}">{label}</span>', unsafe_allow_html=True)
    with st.sidebar:
        on = st.toggle("COMPROMISED host", value=compromised.is_compromised(),
                       help="The UI lies (H1). The device text and the executor are unaffected.")
        compromised.set_compromised(on)
        if isinstance(health, dict):
            st.caption(f"deployment {health.get('deployment')} · policy {str(health.get('policy_hash'))[:16]}")
        if st.button("refresh"):
            st.rerun()
    tabs = st.tabs(["Activity", "Payee changes", "Receipts", "Audit", "AWS evidence", "Bench"])
    for tab, fn in zip(tabs, (tab_activity, tab_changes, tab_receipts, tab_audit, tab_evidence, tab_bench)):
        with tab:
            fn(st)


if __name__ == "__main__":
    main()
