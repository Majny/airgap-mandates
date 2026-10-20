"""Supplier invoicing (Streamlit, port 8503): the supplier's side, outside the bank. A registered supplier sends an
invoice email; the bank's agent proposes it; the executor decides (paid under the mandate, the clerk approves on the
Trezor, or refused). Nobody keys a payment into the bank by hand.

    AIRGAP_SUPPLIER_URL=<executor url>  streamlit run supplier/console.py --server.port 8503

`make supplier` points it at the AWS demo (SigV4 as each IAM role); `AIRGAP_SUPPLIER_URL=http://127.0.0.1:8000` at
`make local-stack`; `memory:` runs a seeded in-process executor (tests). Three screens on stage: supplier :8503 sends,
bank :8501 shows it, attacker :8502 attacks it. Owner: orchestrator.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import date
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from supplier import send  # noqa: E402

URL = (os.environ.get("AIRGAP_SUPPLIER_URL") or os.environ.get("AIRGAP_EXECUTOR_URL") or "http://127.0.0.1:8000")
AWS = ".execute-api." in URL
DATA_DIR = os.environ.get("AIRGAP_DATA_DIR") or str(send.DATA_DIR)
FINAL = {"paid", "refused", "expired", "rejected", "error"}
SIGNIN = "AWS sign-in expired: aws sso login --profile hackathon"

CSS = """<style>
html, body, [class*="css"] { font-size: 18px; }
.block-container { padding-top: 2.2rem; max-width: 1100px; }
.stApp { background: #f7f6f2; color: #1f2933; }
h1, h2, h3 { color: #1f2933 !important; }
.hdr { background: #ffffff; border: 1px solid #dcd8cc; border-radius: 10px; padding: 14px 20px; margin-bottom: 10px;
       display: flex; justify-content: space-between; align-items: center; }
.hdr .t { font-size: 28px; font-weight: 800; color: #2d3a2e; }
.hdr .s { color: #6b6f63; font-size: 16px; }
.badge { padding: 3px 12px; border-radius: 999px; font-weight: 700; font-size: 14px; border: 1px solid; }
.badge-aws { background: #e8f0fb; color: #1d4ed8; border-color: #a9c1ee; }
.badge-local { background: #f1efe7; color: #5b5a4f; border-color: #cfcab8; }
.row { background: #ffffff; border: 1px solid #e3dfd3; border-left: 6px solid #9aa58f; border-radius: 8px;
       padding: 8px 14px; margin-bottom: 8px; }
.row.paid { border-left-color: #067647; } .row.waiting { border-left-color: #1d4ed8; }
.row.refused, .row.error { border-left-color: #b42318; } .row.expired, .row.rejected { border-left-color: #b54708; }
.stButton button[kind="primary"] { background: #2d6a4f; border-color: #2d6a4f; color: #ffffff; }
.stButton button[kind="primary"]:hover { background: #24563f; border-color: #24563f; }
.row .k { font-weight: 700; } .row .m { color: #6b6f63; font-size: 15px; }
</style>"""


def _expired(x: object) -> bool:
    t = str(x.get("message", "")) if isinstance(x, dict) else str(x)
    return "expired" in t.lower() and ("token" in t.lower() or "sso" in t.lower() or "session" in t.lower())


@st.cache_resource
def _call(url: str):
    if url.startswith("memory:"):
        from executor import e2e
        from executor.scenes import DemoEnv

        env = DemoEnv()
        e2e.run(env.call, env.clerk, env.treasury, now=env.now, log=lambda s: None)  # mandate + the normal day
        return env.call
    from host.signer import executor_call

    return executor_call(url)


def _safe_call():
    """call() that never raises: an exception (unreachable, expired sign-in) becomes (0, {"error", "message"})."""
    base = _call(URL)

    def call(m, p, b, who):
        try:
            return base(m, p, b, who)
        except Exception as e:  # noqa: BLE001
            return 0, {"error": "unreachable", "message": f"{type(e).__name__}: {e}"[:300]}

    return call


def _agent_lambda():
    """AWS only: the real agent Lambda (quarantined mode, Bedrock) as invoke(task) -> result."""

    def invoke(task: str) -> dict:
        import boto3
        from botocore.config import Config

        lam = boto3.client("lambda", region_name="eu-central-1", config=Config(read_timeout=330))
        r = lam.invoke(FunctionName="airgap-agent", Payload=json.dumps({"task": task, "mode": "quarantined"}).encode())
        return json.loads(r["Payload"].read())

    return invoke


def _new_invoice_no() -> str:
    return send.new_invoice("ven_12345678", 0)["invoice_no"]


def _do_send(call, names: dict[str, str], real_agent: bool) -> None:
    """on_click of "Send invoice": send, remember the result, then prefill a fresh invoice number."""
    ss = st.session_state
    agent = send.lambda_agent(call, _agent_lambda()) if (real_agent and AWS) else None
    try:
        out = send.send(call, ss["vendor"], round(float(ss["amount"]) * 100), invoice_no=ss["inv_no"].strip() or None,
                        due_date=ss["due"].isoformat(), data_dir=DATA_DIR, agent=agent)
    except Exception as e:  # noqa: BLE001 - expired sign-in, Lambda error: show, never crash
        out = {"kind": "error", "proposal_id": None, "invoice": {"invoice_no": ss["inv_no"]},
               "text": SIGNIN if _expired(e) else f"Sending failed: {type(e).__name__}: {e}"[:300]}
    if out["kind"] == "error" and _expired(out.get("raw") or out["text"]):
        out["text"] = SIGNIN
    inv = out.get("invoice") or {}
    ss["last"] = out
    ss["sent"].insert(0, {"invoice_no": inv.get("invoice_no", ss["inv_no"]), "vendor": names.get(ss["vendor"]),
                          "amount_minor": round(float(ss["amount"]) * 100), "proposal_id": out.get("proposal_id"),
                          "kind": out["kind"], "text": out["text"],
                          "agent": "real AI agent" if agent else "agent step scripted"})
    ss["inv_no"] = _new_invoice_no()


def _show(out: dict) -> None:
    kind, text = out["kind"], out["text"]
    {"paid": st.success, "waiting": st.info, "expired": st.warning, "rejected": st.warning}.get(kind, st.error)(text)


def _sent_list(call) -> None:
    def render() -> None:
        rows = st.session_state.get("sent") or []
        if not rows:
            st.caption("Nothing sent yet in this session.")
            return
        for r in rows:
            if r["kind"] not in FINAL and r.get("proposal_id"):
                live = send.status(call, r["proposal_id"])
                if live["kind"] != "error":
                    r["kind"], r["text"] = live["kind"], live["text"]
            st.markdown(f"<div class='row {r['kind']}'><span class='k'>{r['invoice_no']}</span> &middot; {r['vendor']}"
                        f" &middot; {send.czk(r['amount_minor']).replace(' ', '&nbsp;')}<br>{r['text']}"
                        f"<br><span class='m'>{r['agent']} &middot; {r.get('proposal_id') or 'no proposal'}</span>"
                        "</div>", unsafe_allow_html=True)

    if hasattr(st, "fragment"):
        st.fragment(run_every=5)(render)()
    else:
        render()


def main() -> None:
    st.set_page_config(page_title="Supplier mail", layout="wide", initial_sidebar_state="expanded")
    st.markdown(CSS, unsafe_allow_html=True)
    call = _safe_call()
    hst, health = call("GET", "/health", None, "host")
    expired = _expired(health)
    badge = ("badge-aws", "AWS eu-central-1") if AWS else ("badge-local", "LOCAL")
    st.markdown(f"<div class='hdr'><div><div class='t'>Supplier mail &middot; invoices to the bank</div>"
                "<div class='s'>Supplier invoicing (outside the bank): you send an invoice email, the bank's agent "
                "proposes it, the bank's executor decides.</div></div>"
                f"<span class='badge {badge[0]}'>{badge[1]}</span></div>", unsafe_allow_html=True)
    if expired:
        st.error(SIGNIN)
    elif hst != 200:
        st.error(f"The bank is not reachable at {URL}: {health.get('message') if isinstance(health, dict) else health}")

    with st.sidebar:
        st.markdown("### Bank's agent step")
        real = False
        if AWS:
            mode = st.radio("How the bank's agent handles the email",
                            ["agent step scripted", "real AI agent on AWS (Bedrock, ~1 min)"], key="agent_mode")
            real = mode.startswith("real")
        else:
            st.markdown("**agent step scripted** (the real AI agent runs on AWS only)")
        st.caption("Scripted: the agent's proposal is sent for it (POST /proposals as the agent's tools role). Either "
                   "way the bank's executor alone decides whether the invoice is paid.")
        st.markdown(f"**Bank:** `{URL}`")

    vendors = send.vendors(DATA_DIR)
    names = {v["vendor_id"]: v["name"] for v in vendors}
    ss = st.session_state
    ss.setdefault("sent", [])
    ss.setdefault("inv_no", _new_invoice_no())
    ss.setdefault("due", date.today())
    ss.setdefault("amount", 12_500.0)

    left, right = st.columns([3, 2])
    with left:
        st.markdown("#### New invoice")
        st.selectbox("Supplier (registered with the bank)", list(names), format_func=lambda v: names[v], key="vendor")
        st.number_input("Amount (CZK)", min_value=1.0, step=500.0, format="%.2f", key="amount")
        cap = send.cap_minor(call) if not expired else None
        st.caption(f"Up to {send.czk(cap or send.DEFAULT_CAP_MINOR)} the bank pays automatically under its mandate; "
                   "above that a clerk approves on the Trezor (within 5 minutes)."
                   + ("" if cap else " (limit of the demo mandate; the bank's live mandate was not readable)"))
        c1, c2 = st.columns(2)
        c1.text_input("Invoice number", key="inv_no")
        c2.date_input("Due date", key="due")
        st.button("Send invoice", key="send", type="primary", on_click=_do_send, args=(call, names, real),
                  disabled=False)
        if ss.get("last"):
            _show(ss["last"])
    with right:
        st.markdown("#### Sent invoices (this session)")
        _sent_list(call)


main()
