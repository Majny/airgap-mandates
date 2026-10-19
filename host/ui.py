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

from urllib.parse import urlencode

from host import compromised

EXECUTOR = os.environ.get("AIRGAP_EXECUTOR_URL", "http://127.0.0.1:8000")
FSM_STATES = ["PENDING_ATTEST", "CALLBACK_PENDING", "COOLING", "SIG_CLERK", "SIG_TREASURY", "ACTIVE"]
# Beat order and cues from docs/STAGE.md (WS-C runbook) / ARCHITECTURE §14.
BEATS = [
    ("0:00 Hook", "Activity", "This agent is compromised right now. It still can't move a koruna."),
    ("0:15 S1 normal day", "Activity", "Invoices pay under the signed mandate; the over-cap one lights the Safe 3. "
                                       "Line 1 of the device = line 1 here."),
    ("0:45 S2 lookalike + escalation + exfil", "Payee changes",
     "Facts go red; the device stays dark (R0: nothing to approve). Escalations refused, exfil blocked."),
    ("1:35 S3 takeover + deepfake, then legit", "Payee changes",
     "DKIM green, ATT 0/3 = BLOCK: there is no button. Legit path: 2 of 3 attestations, cooling-off, clerk + treasury."),
    ("2:30 S5 offline audit", "Audit", "Wi-Fi off. Stock Go noteverify + verify_audit green; one flipped byte is red."),
    ("3:20 Bench + real vs simulated", "Bench", "Money to the attacker (frozen run): A0 571,077 CZK, A3 0 CZK, "
                                             "also with a rubber-stamp human."),
]
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


_CALL: Any = None


def _call() -> Any:
    """SigV4 to the AWS regional API as the principal's IAM role (host.signer.executor_call); plain HTTP locally."""
    global _CALL
    if _CALL is None:
        from host.signer import executor_call
        _CALL = executor_call(EXECUTOR)
    return _CALL


def api(path: str, who: str = "host", **query: Any) -> tuple[int, Any]:
    q = {k: v for k, v in query.items() if v is not None}
    try:
        return _call()("GET", path + ("?" + urlencode(q) if q else ""), None, who)
    except Exception as exc:  # noqa: BLE001 - unreachable executor, expired SSO credentials: show, never crash
        return 0, {"error": "unreachable", "message": f"{type(exc).__name__}: {exc}"[:300]}


def export_bundle() -> dict[str, Any] | None:
    code, b = api("/audit/export", "auditor", log_id="audit", from_seq=0)
    return b if code == 200 and isinstance(b, dict) else None


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


def tab_approvals(st: Any) -> None:
    bundle = export_bundle()
    if bundle is None:
        st.info("audit export unavailable")
        return
    labels = device_labels(bundle)
    sigs = [leaf for leaf in bundle.get("leaves", []) if (leaf.get("event") or {}).get("type") == "signature"]
    if not sigs:
        st.caption("no approvals yet")
    for leaf in reversed(sigs[-30:]):
        ev = leaf["event"]
        d = ev.get("data") or {}
        addr = str(d.get("signer_address") or "").lower()
        label = labels.get(addr, "NOT ENROLLED" if addr else "-")
        outcome = "accepted" if d.get("accepted") else f"rejected: {d.get('error')}"
        st.markdown(f"seq {leaf['seq']} · **{d.get('purpose')}** · {d.get('role')} · `{addr[:10]}…` "
                    f"{device_chip(label)} · {outcome} · `{ev.get('subject_id')}`", unsafe_allow_html=True)


def tab_receipts(st: Any) -> None:
    tx_id = st.text_input("tx_id")
    if not tx_id:
        return
    code, r = api(f"/receipts/{tx_id}")
    if code != 200:
        st.warning(r)
        return
    try:  # short URL-form QR (AGR2, ~v8): scans with a stock phone camera; the full AGR1 receipt is file-only
        from executor.audit.receipt import short_qr_payload, short_qr_png
        st.image(short_qr_png(r), width=480)
        st.code(short_qr_payload(r), language="text")
        st.caption("scan → the verifier checks this receipt offline against the signed log")
    except (ImportError, NotImplementedError, RuntimeError) as exc:  # RuntimeError: segno missing
        st.info(f"receipt QR unavailable ({exc}); install the [ui] extra (segno)")
    st.json(r, expanded=False)


def tab_audit(st: Any) -> None:
    bundle = export_bundle()
    try:
        from witness.supervisor import render_html
        import streamlit.components.v1 as components
        st.warning("Rendered by the host. Under a compromised host (H1) this view can lie. "
                   "Verify offline: python -m witness.supervisor bundle.json")
        if bundle is not None:
            components.html(render_html(bundle, allow_uncovered_tail=True), height=620, scrolling=True)
    except ImportError:
        st.info("supervisor view not merged on this branch yet (WS-B witness.supervisor)")
    code, note = api("/checkpoint", log_id="audit")
    st.markdown("**Latest checkpoint (C2SP signed note)**")
    st.code(note if code == 200 else f"unavailable: {note}", language="text")
    if st.button("Verify export bundle now"):
        code, bundle = api("/audit/export", "auditor", log_id="audit", from_seq=0)
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
        beat = st.radio("Stage beat (docs/STAGE.md)", [b[0] for b in BEATS], index=0)
        if st.button("refresh"):
            st.rerun()
    title, tab_name, cue = next(b for b in BEATS if b[0] == beat)
    st.markdown(f"### {title}  \n{cue}  \n*look at: {tab_name}*")
    clip = Path(__file__).resolve().parent.parent / "demo" / "assets" / "synthetic_cfo_call.mp3"
    if title.startswith("1:35") and clip.exists():
        st.caption("SYNTHETIC VOICE (Amazon Polly), fictional person: the 'CFO' pressing the clerk")
        st.audio(clip.read_bytes(), format="audio/mpeg")
    if emulator_only():
        st.markdown('<span class="banner-local">FALLBACK: EMULATOR CLERK (no physical Safe 5 attached)</span>',
                    unsafe_allow_html=True)
    tabs = st.tabs(["Activity", "Payee changes", "Approvals", "Receipts", "Audit", "AWS evidence", "Bench"])
    for tab, fn in zip(tabs, (tab_activity, tab_changes, tab_approvals, tab_receipts, tab_audit, tab_evidence,
                              tab_bench)):
        with tab:
            fn(st)


if __name__ == "__main__":
    main()
