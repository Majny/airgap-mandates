"""AirGap Mandates operations console (`make ui`): what the agent proposed, what the executor decided and why,
what waits for a hardware signature, payee changes, approvals, the signed mandate, audit and reports.
CONTRACTS.md §4. Owner: WS-F.

Untrusted host (TB3): it only reads the public executor API (`AIRGAP_EXECUTOR_URL`) and the frozen bench files.
`AIRGAP_EXECUTOR_URL=memory:` runs a seeded in-process executor (visual test, no AWS). The COMPROMISED switch
(`AIRGAP_UI_DEMO_TOOLS=1`) sends every view model through `host.compromised.lie()`: the device text is the only truth.
"""
from __future__ import annotations

import hashlib
import html
import io
import json
import os
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from urllib.parse import urlencode, urlparse

# `streamlit run host/ui.py` puts only host/ on sys.path; infra/ (SigV4 signing) is not an installed package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from executor.audit import explain as X  # noqa: E402
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
.block-container { padding-top: 2.6rem; max-width: 1400px; }
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
.alarm { background: #b42318; color: white; padding: 10px 16px; border-radius: 8px; font-weight: 700;
         font-size: 19px; margin: 4px 0 12px 0; }
.alarm small { font-weight: 500; opacity: 0.92; font-size: 16px; }
.alarm.breach { background: #7a0916; border: 3px solid #fda29b; font-size: 21px; }
.alarm.calm { background: #067647; }
.inc { border: 2px solid var(--c); border-left: 10px solid var(--c); border-radius: 8px; padding: 12px 18px 10px;
       margin: 0 0 16px 0; background: rgba(180,35,24,0.04); }
.inc-head { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
.inc-badge { background: var(--c); color: white; font-weight: 800; padding: 2px 10px; border-radius: 6px;
             letter-spacing: 0.03em; font-size: 15px; }
.inc-kind { font-weight: 800; font-size: 22px; }
.inc-when { margin-left: auto; opacity: 0.7; font-size: 15px; }
.inc-title { font-size: 17px; margin: 4px 0 2px 0; }
.inc-what { font-style: italic; opacity: 0.8; font-size: 16px; margin-bottom: 8px; }
.inc-grid { display: grid; grid-template-columns: 1fr 1.25fr 0.55fr; gap: 10px 14px;
            grid-template-areas: "who tried money" "how how money"; }
.inc-grid .g-who { grid-area: who; } .inc-grid .g-tried { grid-area: tried; }
.inc-grid .g-how { grid-area: how; } .inc-grid .g-money { grid-area: money; }
@media (max-width: 1000px) { .inc-grid { grid-template-columns: 1fr; grid-template-areas: "who" "tried" "how" "money"; } }
.inc-grid > div { background: rgba(127,127,127,0.07); border-radius: 6px; padding: 8px 12px; font-size: 16px; }
.inc .lbl { text-transform: uppercase; font-size: 12px; font-weight: 800; letter-spacing: 0.06em; opacity: 0.65;
            margin-bottom: 4px; }
.inc ul { margin: 0; padding-left: 18px; }
.inc li { margin: 0 0 4px 0; }
.inc .kv { font-size: 15px; margin-top: 6px; }
.inc .kv b.mono { font-family: 'JetBrains Mono', Menlo, monospace; font-weight: 600; }
.inc .rule { font-family: 'JetBrains Mono', Menlo, monospace; font-size: 12px; opacity: 0.7; }
.inc .money { text-align: center; }
.inc .money .big { font-size: 26px; font-weight: 800; color: #067647; }
.inc .money .big.lost { color: #b42318; }
.inc-foot { font-size: 14px; opacity: 0.7; margin-top: 8px; }
.inc-next { margin-top: 10px; padding: 8px 12px; border-radius: 8px; background: rgba(181,71,8,0.12);
            border-left: 4px solid #b54708; font-size: 16px; }
.atk-tag { display: inline-block; background: #b42318; color: #fff; border-radius: 999px; padding: 1px 10px;
           font-size: 13px; font-weight: 700; margin-left: 6px; }
.door { font-size: 14px; border: 1px dashed #b42318; border-radius: 8px; padding: 6px 12px; margin: 6px 0 12px; }
.kinds span { display: inline-block; border: 1px solid #b42318; color: #b42318; border-radius: 999px;
              padding: 1px 10px; margin: 2px 4px 2px 0; font-size: 15px; font-weight: 600; }
table.evlog { width: 100%; border-collapse: collapse; font-size: 15px; table-layout: fixed; }
table.evlog col.t { width: 165px; } table.evlog col.l { width: 115px; } table.evlog col.s { width: 120px; }
table.evlog col.q { width: 80px; }
table.evlog td.mono.s { white-space: normal; overflow-wrap: anywhere; }
table.evlog td { padding: 5px 8px; border-bottom: 1px solid rgba(127,127,127,0.2); vertical-align: top; }
table.evlog tr.ATTACK td, table.evlog tr.ERROR td { background: rgba(180,35,24,0.08); }
table.evlog tr.demo td { background: rgba(127,127,127,0.08); opacity: 0.8; }
table.evlog .lv { display: inline-block; min-width: 92px; color: white; font-weight: 700; padding: 1px 6px;
                  border-radius: 5px; font-size: 13px; white-space: nowrap; }
table.evlog .why { opacity: 0.75; font-size: 14px; }
table.evlog .mono { font-family: 'JetBrains Mono', Menlo, monospace; font-size: 13px; white-space: nowrap; }
/* Security tab, projector layout (summary row, newest incident big, older ones as one-liners) */
.sumrow { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 0 0 10px 0; }
.sumrow .tile { border: 2px solid #d0d5dd; border-radius: 10px; padding: 4px 12px 6px; text-align: center; }
.sumrow .n { font-size: 30px; font-weight: 800; line-height: 1.1; }
.sumrow .g { font-size: 14px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.05em; opacity: 0.75; }
.sumrow .tile.hot { border-color: #b42318; background: rgba(180,35,24,0.08); } .sumrow .tile.hot .n { color: #b42318; }
.sumrow .tile.money { border-color: #067647; background: rgba(6,118,71,0.08); }
.sumrow .tile.money .n { color: #067647; font-size: 30px; }
.sumrow .tile.money.lost { border-color: #7a0916; background: rgba(122,9,22,0.15); }
.sumrow .tile.money.lost .n { color: #7a0916; }
@media (max-width: 900px) { .sumrow { grid-template-columns: repeat(2, 1fr); } }
.threat { background: #101828; color: #fff; font-weight: 800; letter-spacing: 0.06em; padding: 3px 12px;
          border-radius: 6px; font-size: 19px; }
.threat.sm { font-size: 13px; padding: 1px 8px; letter-spacing: 0.04em; }
.newest { font-size: 13px; font-weight: 800; text-transform: uppercase; color: #b42318; letter-spacing: 0.1em;
          margin: 2px 0 2px 2px; }
.inc .inc-title { font-size: 23px; font-weight: 700; margin: 6px 0 2px 0; line-height: 1.25; }
.inc .inc-what { margin-bottom: 8px; }
.inc .inc-grid { grid-template-columns: 1fr 1.1fr 1.4fr 0.62fr; grid-template-areas: "who tried how money"; }
@media (max-width: 1100px) { .inc .inc-grid { grid-template-columns: 1fr 1fr;
                             grid-template-areas: "who tried" "how money"; } }
.inc .layer { font-size: 19px; color: var(--c); } .inc .layer b { font-weight: 800; }
.inc .because { font-size: 16px; margin: 2px 0 6px 0; }
.inc .because code.rid { font-size: 14px; font-weight: 700; color: #101828; background: rgba(127,127,127,0.15); }
.inc .inc-grid > div { font-size: 15px; padding: 6px 10px; line-height: 1.35; }
.inc li { margin: 0 0 2px 0; }
.inc .mono { font-family: 'JetBrains Mono', Menlo, monospace; }
.inc .stake { font-size: 15px; margin-bottom: 4px; }
.inc .money .big { font-size: 30px; }
.inc-foot { opacity: 0.8; } .inc-foot code { font-size: 13px; }
.inc-when .det { color: #067647; font-weight: 700; font-size: 14px; opacity: 1; }
.inc-when { text-align: right; }
.earlier { font-size: 13px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.08em; opacity: 0.65;
           margin: 6px 0 4px 2px; }
details.incl { margin: 0 0 6px 0; }
details.incl > summary { border: 1px solid rgba(127,127,127,0.25); border-left: 8px solid var(--c); border-radius: 6px;
                         padding: 6px 12px; cursor: pointer; font-size: 17px; list-style: none; }
details.incl > summary::-webkit-details-marker { display: none; }
details.incl > summary .to { opacity: 0.8; } details.incl > summary .meta { opacity: 0.6; font-size: 14px; }
details.incl[open] > summary { margin-bottom: 6px; }
details.backdrop { margin-top: 14px; opacity: 0.85; }
details.backdrop > summary { cursor: pointer; font-size: 15px; color: #667085; }
.waitline { background: rgba(181,71,8,0.12); border-left: 4px solid #b54708; padding: 6px 12px; border-radius: 6px;
            margin: 0 0 6px 0; font-size: 16px; }
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
        from executor import e2e, oplog, scenes
        from tools.local_stack import seed_pending_overcap
        e = scenes.DemoEnv()
        with oplog.replay("S2+S3"):  # request-level refusals while seeding are the backdrop, not live attacks
            e2e.run(e.call, e.clerk, e.treasury, now=e.now, log=lambda s: None)
            scenes.scene_s2(e, log=lambda s: None)
            scenes.scene_s3(e, log=lambda s: None)
        # test/visual only: enrol the deterministic software clerk so "Approve on Trezor" (and the honest re-sign after
        # attack h) can sign without a physical device. Same gate as tools/local_stack; never reachable against AWS.
        import os
        if os.environ.get("AIRGAP_TEST_SOFTWARE_CLERK") == "1":
            from executor.store import seed
            from host.signer import software_clerk_account
            acct = software_clerk_account()
            seed.enroll_signer(e.store, acct.address, "clerk", device="GENUINE",
                               label="clerk (software key, test)", settings=e.settings)
        # one over-cap payment left PENDING_SIG, so the Approve-on-Trezor button and the attack-h demo have a target
        seed_pending_overcap(e.call, e.now, data_dir=e.settings.data_dir)
        from tools.local_stack import audit_next_seq
        e.seed_seq = audit_next_seq(e.call)  # everything from here on is live: earlier attacks are the demo backdrop
        return e

    global _SEED_SEQ, _STORE
    e = env()
    _SEED_SEQ = getattr(e, "seed_seq", None)
    _STORE = e.store
    return e.call


_CALL: Any = None
_SEED_SEQ: int | None = None  # first live audit seq on a seeded demo stack; None on AWS (no backdrop)
_SEED_ASKED = False
_STORE: Any = None  # the memory: executor's store (its request-level attacks, executor.oplog.recent)


def seed_seq() -> int | None:
    """Where the replayed demo backdrop (scenes S2/S3, the ops log's [demo replay]) ends and live traffic starts:
    AIRGAP_DEMO_SEED_SEQ, the memory: seeding, or tools.local_stack's /_local/seed on a loopback URL (asked once).
    None against AWS: every attack there is live."""
    global _SEED_SEQ, _SEED_ASKED
    if os.environ.get("AIRGAP_DEMO_SEED_SEQ", "").isdigit():
        return int(os.environ["AIRGAP_DEMO_SEED_SEQ"])
    if EXECUTOR.startswith("memory:"):
        _call()
        return _SEED_SEQ
    if not _SEED_ASKED and EXECUTOR.startswith(("http://127.0.0.1", "http://localhost")):
        _SEED_ASKED = True
        try:
            from tools.local_stack import SEED_PATH
            code, b = _call()("GET", SEED_PATH, None, "auditor")  # read-only; auditors may ask too
            q = b.get("seed_seq") if code == 200 and isinstance(b, dict) else None
            _SEED_SEQ = q if isinstance(q, int) and not isinstance(q, bool) else None
        except Exception:  # noqa: BLE001 - an older stack without the route: no backdrop marking
            _SEED_SEQ = None
    return _SEED_SEQ


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


def render_cards(st: Any, cards: list[dict[str, Any]], seed: int | None = None) -> None:
    """seed: first live audit seq; an attack card before it is the replayed demo backdrop, shown grey and quiet."""
    for c in cards:
        icon, colour = story.TONES[c["tone"]]
        title = c["title"]
        if seed is not None and c["tone"] in ("attack", "hold") and isinstance(c.get("seq"), int) and c["seq"] < seed:
            icon, colour, title = "🎬", "#98a2b3", f'<span style="opacity:.75">demo backdrop · {title}</span>'
        body = f'<div class="b">{c["body"]}</div>' if c["body"] else ""
        st.markdown(f'<div class="card" style="--c:{colour}"><div class="t">{icon} {title}</div>{body}</div>',
                    unsafe_allow_html=True)
        if c.get("device"):
            st.markdown(f'<div class="device">{c["device"]}</div>', unsafe_allow_html=True)


_RULE_TAIL = __import__("re").compile(r"\s*\[([^\]]+)\]$")


def _seq_txt(seqs: list[int]) -> str:
    if not seqs:
        return "no audit entry yet"
    if len(seqs) > 2 and seqs[-1] - seqs[0] == len(seqs) - 1:
        return f"audit seq {seqs[0]}–{seqs[-1]}"
    return "audit seq " + ", ".join(str(q) for q in seqs)


def _card_look(c: dict[str, Any]) -> tuple[str, str]:
    """(colour, badge) of an incident card."""
    breach = bool(c.get("breach"))  # only money to an account outside the vendor master, never a bank rejection
    waiting = bool(c.get("next")) and c["headline"].startswith("Attack blocked, payment still waiting")
    backdrop = bool(c.get("backdrop"))  # replayed demo scene seeded before the stack went live, not a live attack
    colour = ("#7a0916" if breach else "#667085" if backdrop else "#b54708" if c.get("held") or waiting
              else "#b42318")
    badge = ("💥 MONEY LOST" if breach else "🎬 DEMO BACKDROP (seeded scene) · [demo replay]" if backdrop else
             "⏸ ON HOLD · SUSPECTED ATTACK" if c.get("held") else
             "🛑 ATTACK BLOCKED · PAYMENT STILL WAITING" if waiting else "🛑 ATTACK STOPPED")
    return colour, badge


def _cap(t: str) -> str:
    return t[:1].upper() + t[1:]


def _proof_line(c: dict[str, Any]) -> str:
    """Explainability footer: deterministic, replayable, where the proof is."""
    e = html.escape
    if c.get("request_level"):
        where = ("refused at the door: no audit entry, so it lives in the executor's operations log (CloudWatch on "
                 "AWS, the local stack's terminal), on a line marked 🛑 ATTACK")
    else:
        pol = str(c.get("policy") or "")
        proof = c.get("proof") or "log"
        # say only what tools.verify_audit really re-checks: decide() replays decision leaves only
        what = {"decision": "decision replayed offline", "signature": "signatures re-verified offline"}.get(
            proof, "log integrity re-verified offline (hash chain + witnesses)")
        where = (f"{e(_seq_txt(c['seqs']))} in the signed, witnessed audit log · {what}: "
                 f"<code>{e(X.REPLAY_CMD)}</code>"
                 + (f" · policy <code>sha256:{e(pol[:8])}…</code>" if pol and proof == "decision" else ""))
    return f'<div class="inc-foot">✔ {e(_cap(X.DETERMINISTIC))} · {where}</div>'


def _evidence_html(ev: str) -> str:
    """'render_mismatch: the Trezor signed …' -> rule id in mono, the value in plain words (wraps less)."""
    e = html.escape
    rid, sep, rest = ev.partition(": ")
    if sep and len(rid) <= 40 and " " not in rid.replace(", ", ","):
        return f'<code class="rid">{e(rid)}</code> {e(rest)}'
    return e(ev)


def incident_html(c: dict[str, Any], *, steps: int = 3) -> str:
    """One incident card, readable from the back of a room: threat label, what happened in one line, who / from
    where, what they tried, which defence layer stopped it and the evidence, money at stake vs moved, and the proof
    (deterministic, replayable, audit seq, policy hash). Every value is escaped except the `who` lines, which
    story.security() escapes itself."""
    e = html.escape
    colour, badge = _card_look(c)
    kind = c["kind"].rstrip("?")
    threat = c.get("threat") or ""
    who = "".join(f"<li>{w}</li>" for w in c["who"])
    kv = "".join(f'<div class="kv">{e(k)}: <b class="{"" if k in ("Supplier", "Amount") else "mono"}">{e(v)}</b></div>'
                 for k, v in c["facts"])
    stopped = []
    for seq, why in c["stopped"][-steps:]:
        m = _RULE_TAIL.search(why)
        text, rules = (why[:m.start()], m.group(1)) if m else (why, "")
        tag = " · ".join(t for t in (rules, f"seq {seq}" if seq is not None else "") if t)
        stopped.append(f"<li>{e(_cap(text))}" + (f' <span class="rule">[{e(tag)}]</span>' if tag else "") + "</li>")
    verb = "Held by" if c.get("held") else "Stopped by"
    layer = (f'<div class="layer">{verb} <b>{e(c["layer"])}</b></div>' if c.get("layer") else "")
    because = f'<div class="because">because {_evidence_html(c["evidence"])}</div>' if c.get("evidence") else ""
    moved, stake = c["moved_minor"], c.get("at_stake_minor")
    money = ((f'<div class="stake">at stake <b>{e(story.czk(stake))}</b></div>' if stake else "")
             + f'<div class="big{" lost" if moved else ""}">{e(story.czk(moved))}</div><div>moved to the attacker</div>')
    return (f'<div class="inc" style="--c:{colour}">'
            f'<div class="inc-head">' + (f'<span class="threat">{e(threat)}</span>' if threat else "")
            + f'<span class="inc-badge">{badge}</span><span class="inc-kind">{e(_cap(kind))}</span>'
            f'<span class="inc-when">{e(c["when"])} · {e(_seq_txt(c["seqs"]) if c["seqs"] else "no audit entry")}'
            '<br><span class="det">✔ deterministic · verifiable offline</span></span></div>'
            f'<div class="inc-title">{e(c["title"])}</div>'
            + (f'<div class="inc-what">{e(c["what"])}</div>' if c.get("what") else "")
            + '<div class="inc-grid">'
            f'<div class="g-who"><div class="lbl">Who / from where</div><ul>{who}</ul></div>'
            f'<div class="g-tried"><div class="lbl">What they tried</div>{e(c["tried"])}{kv}</div>'
            f'<div class="g-how"><div class="lbl">{"Why it is held" if c.get("held") else "How it was stopped"}'
            f'</div>{layer}{because}<ul>{"".join(stopped)}</ul></div>'
            f'<div class="g-money money"><div class="lbl">Money</div>{money}</div>'
            "</div>"
            + (f'<div class="inc-next"><b>Your next step:</b> {e(c["next"])}</div>' if c.get("next") else "")
            + _proof_line(c) + "</div>")


def incident_line_html(c: dict[str, Any]) -> str:
    """An older incident as one line (threat · what happened → stopped by layer · seq) that opens into its card."""
    e = html.escape
    colour, _ = _card_look(c)
    verb = "held by" if c.get("held") else "stopped by"
    stop = f' <span class="to">→ {verb} {e(c["layer"])}</span>' if c.get("layer") else ""
    seq = e(_seq_txt(c["seqs"]) if c["seqs"] else "no audit entry")
    return (f'<details class="incl" style="--c:{colour}"><summary>'
            f'<span class="threat sm">{e(c.get("threat") or "ATTACK")}</span> <b>{e(c["title"])}</b>{stop}'
            f' <span class="meta">{e(c["when"][11:] if len(c["when"]) > 11 else c["when"])} · {seq}</span>'
            f"</summary>{incident_html(c)}</details>")


def security_summary_html(sec: dict[str, Any]) -> str:
    """One glance: live attacks per threat group (the Track 3 brief's three + fraud & tampering) and money moved."""
    e = html.escape
    groups = sec.get("groups") or {}
    lost = sec.get("attacker_minor") or 0
    tiles = "".join(f'<div class="tile{" hot" if n else ""}"><div class="n">{n}</div><div class="g">{e(g)}</div></div>'
                    for g, n in groups.items())
    money = (f'<div class="tile money{" lost" if lost else ""}"><div class="n">{e(story.czk(lost))}</div>'
             f'<div class="g">moved to attackers</div></div>')
    return f'<div class="sumrow">{tiles}{money}</div>'


def attack_tag(inc: dict[str, Any]) -> str:
    """Red tag on a Payments / Approvals row whose payment is part of an incident on the Security tab."""
    seq = max(inc.get("seqs") or [], default=None)
    return (' <span class="atk-tag">🛑 linked to attack: ' + html.escape(inc.get("kind", "").rstrip("?"))
            + (f" (seq {seq})" if seq is not None else "") + "</span>")


def attack_banner(st: Any, sec: dict[str, Any] | None) -> None:
    """One red line on every page while live attacks exist (the demo backdrop never counts); loud when money reached
    an attacker."""
    if not sec or not sec.get("n"):
        return
    n, lost, latest = sec["n"], sec["attacker_minor"], sec.get("latest") or {}
    last = (f" · latest: {html.escape(latest.get('threat') or latest.get('kind', '').rstrip('?'))}, "
            f"{html.escape(latest.get('when', '')[11:] or latest.get('when', ''))}") if latest else ""
    if lost:
        st.markdown(f'<div class="alarm breach">💥 {html.escape(story.czk(lost))} REACHED AN ACCOUNT OUTSIDE THE VENDOR '
                    f"MASTER · {n} incident{'' if n == 1 else 's'} in the log{last}. Open the Security tab now.</div>",
                    unsafe_allow_html=True)
        return
    st.markdown(f'<div class="alarm">🛑 Under attack: {n} incident{"" if n == 1 else "s"} blocked · 0.00 CZK reached an '
                f"attacker{last} · <small>details on the <b>Security</b> tab</small></div>", unsafe_allow_html=True)


def tab_security(st: Any, data: dict[str, Any]) -> None:
    """Projector layout: summary row, the newest live incident as one big card, older incidents as one-liners that
    open on click, the demo backdrop collapsed at the bottom. Refreshes with the console (AIRGAP_UI_REFRESH_S)."""
    sec = data.get("security") or {}
    if data.get("bundle") is None:
        st.info("audit export unavailable")
        return
    cards = sec.get("incidents") or []
    live = [c for c in cards if not c.get("backdrop")]
    demo = [c for c in cards if c.get("backdrop")]
    st.markdown(security_summary_html(sec), unsafe_allow_html=True)
    if not live:
        st.markdown('<div class="alarm calm">✅ No live attacks. Every payment so far went through the mandate or a '
                    "person on a Trezor.</div>", unsafe_allow_html=True)
    else:
        waiting = [c for c in live[1:] if c.get("next")]
        if waiting:
            st.markdown(f'<div class="waitline">⚠ {len(waiting)} more payment{"" if len(waiting) == 1 else "s"} '
                        "touched by an attack still wait for approval: open the card below for the next step."
                        "</div>", unsafe_allow_html=True)
        st.markdown('<div class="newest">Newest</div>' + incident_html(live[0], steps=1), unsafe_allow_html=True)
        if live[1:]:
            st.markdown(f'<div class="earlier">Earlier ({len(live) - 1}) · click a line for the full card</div>'
                        + "".join(incident_line_html(c) for c in live[1:]), unsafe_allow_html=True)
    if not data.get("refusals_live"):
        st.caption("Requests refused at the door (stolen AI-agent credentials, an account number smuggled into a "
                   "request) write no audit entry; on AWS they are in CloudWatch: Logs Insights "
                   "`fields @timestamp, @message | filter @message like /ATTACK/ | sort @timestamp desc`.")
    if demo:
        st.markdown(f'<details class="backdrop"><summary>🎬 Demo backdrop: {len(demo)} attack'
                    f'{"" if len(demo) == 1 else "s"} from the seeded scenes (replayed before the stack went live, '
                    "[demo replay] in the ops log), not counted above</summary>"
                    + "".join(incident_line_html(c) for c in demo) + "</details>", unsafe_allow_html=True)


EVLOG_MAX = 300


def event_log_html(rows: list[Any], seed: int | None = None) -> str:
    """seed: first live audit seq (seed_seq()); earlier rows are the replayed demo backdrop, tagged [demo replay]."""
    e = html.escape
    out = ['<table class="evlog"><colgroup><col class="t"><col class="l"><col><col class="s"><col class="q">'
           "</colgroup>"]
    for x in rows[:EVLOG_MAX]:
        icon, label, colour = story.LEVEL_LOOK.get(x.level, ("•", x.level, "#475467"))
        why = f'<div class="why">{e(x.why)}</div>' if x.why else ""
        demo = seed is not None and x.seq is not None and x.seq < seed
        out.append(f'<tr class="{e(x.level)}{" demo" if demo else ""}"><td class="mono">{e(str(x.ts or "")[:19].replace("T", " "))}</td>'
                   f'<td><span class="lv" style="background:{colour}">{icon} {label}</span></td>'
                   f'<td>{f"<span class=\"threat sm\">{e(x.threat)}</span> " if x.threat else ""}'
                   f'<b>{"[demo replay] " if demo else ""}{e(x.title)}</b>{why}</td><td class="mono s">{e(str(x.subject or ""))}</td>'
                   f'<td class="mono">seq {x.seq if x.seq is not None else "-"}</td></tr>')
    out.append("</table>")
    return "".join(out)


def event_log(st: Any, data: dict[str, Any]) -> None:
    st.markdown("**Event log** · every audit entry in plain words, newest first")
    show = st.radio("Show", list(story.LOG_FILTERS), index=1, horizontal=True, key="eventlog-filter",
                    label_visibility="collapsed")
    rows = story.event_log(data.get("bundle"), data.get("vendors") or [], data.get("changes") or [],
                           data.get("proposals") or [], show=show)
    counts = {lv: sum(1 for x in rows if x.level == lv) for lv in story.LEVEL_LOOK}
    n_inc = (data.get("security") or {}).get("n", 0)
    st.caption(f"{len(rows)} audit entr{'y' if len(rows) == 1 else 'ies'} shown: "
               + " · ".join(f"{story.LEVEL_LOOK[lv][0]} {story.LEVEL_LOOK[lv][1]} {n}" for lv, n in counts.items()
                            if n)
               + (f" · the attack entries are grouped into {n_inc} incident{'' if n_inc == 1 else 's'} on the "
                  "Security tab" if n_inc else "")
               + (f" · showing the newest {EVLOG_MAX}" if len(rows) > EVLOG_MAX else ""))
    if not rows:
        st.info("nothing to show" if data.get("bundle") is not None else "audit export unavailable")
        return
    st.markdown(event_log_html(rows, seed_seq()), unsafe_allow_html=True)


def tab_overview(st: Any, data: dict[str, Any]) -> None:
    if not data["cards"]:
        st.info("No activity yet.")
    render_cards(st, data["cards"], seed_seq())


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


SIGN_TIMEOUT_S = float(os.environ.get("AIRGAP_UI_SIGN_TIMEOUT_S", "90"))


def expires_in(challenge: dict[str, Any]) -> int | None:
    """Seconds left on a challenge (it lives 300 s from the proposal and is never re-issued); None on the seeded
    executors, whose clock is fixed in the past."""
    from datetime import datetime, timezone

    exp = challenge.get("exp")
    if not exp or EXECUTOR.startswith("memory:") or urlparse(EXECUTOR).hostname in ("127.0.0.1", "localhost"):
        return None  # the seeded executors (memory:, tools/local_stack) run on a fixed clock in the past
    try:
        t = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0, int((t - datetime.now(timezone.utc)).total_seconds()))


def approve_on_trezor(st: Any, nonce: str, role: str, *, key: str) -> None:
    """Operator presses this to exact-sign a waiting payment on the clerk's Trezor. The honest flow shows the executor
    text on the device and pays on confirm. If the clerk's PC is compromised (host.implant, attacker level H4) the
    device shows the attacker's IBAN instead — this console never reveals that — and the outcome is mapped to a plain
    message. Never crashes when no device is attached."""
    from host import signer

    done = st.session_state.setdefault("approve_outcome", {})
    if not st.button("Approve on Trezor", key=f"approve-{key}", type="primary"):
        if key in done:  # keep the last outcome visible across the auto-refresh reruns
            getattr(st, done[key][0])(done[key][1])
        return
    driver = None
    try:
        if signer.software_clerk_allowed(EXECUTOR):
            driver = signer.software_clerk_driver()
    except Exception:  # noqa: BLE001 - fall back to the physical device path
        driver = None
    note = ("Signing with a software key (test)." if driver is not None
            else "Check the Trezor: confirm only if payee, IBAN and amount match the text above. To reject, press "
                 "the left button until the first screen, then once more.")
    try:
        with st.spinner(note):  # well under the 300 s challenge life, so a reject leaves time to approve again
            res = signer.sign_challenge(nonce, role, call=_call(), driver=driver, timeout=SIGN_TIMEOUT_S)
        http, err = res.get("_http"), res.get("error")
        eff = (res.get("effect") or {}).get("type")
        if http == 200 and eff == "payment_executed":
            out = ("success", "Paid · confirmed on Trezor.")
        elif err == "render_mismatch":
            out = ("error", "Refused by the executor: the Trezor was asked to sign a different payment than the bank "
                            "issued (the account number was changed on this PC). Nothing was paid. Treat this PC as "
                            "compromised.")
        elif err:
            out = ("error", f"Refused by the executor: {err}. Nothing was paid.")
        else:
            out = ("info", f"Signature submitted: {eff or 'done'}.")
    except signer.SignerCancelled:
        out = ("warning", "You rejected it on the Trezor. Nothing was paid; the payment still waits for approval.")
    except TimeoutError:
        out = ("warning", "No confirmation on the Trezor in time. Nothing was paid; the payment still waits for "
                          "approval.")
    except Exception as exc:  # noqa: BLE001 - no device attached, trezorlib missing, device error: never a signature
        out = ("error", f"Not signed: no usable Trezor ({type(exc).__name__}). Attach and unlock the clerk's Safe 3 "
                        "and try again.")
    done[key] = out  # stored before any st.* call: an auto-refresh rerun may stop the script at the next one
    getattr(st, out[0])(out[1])


def tab_payments(st: Any, data: dict[str, Any]) -> None:
    if not data["proposals"]:
        st.info("No payment proposals yet.")
    linked = story.linked(data.get("security"))
    pain001_batch(st, data)
    for p in data["proposals"]:
        v = view(proposal_view(p, data["names"]))
        label, colour = STATUS.get(v.get("status") or "", (str(v.get("status")), "#475467"))
        if v.get("status") == "EXECUTED":
            label += " · confirmed on Trezor" if v.get("decision") == "challenge" else " · within mandate"
        inv = p.get("invoice") or {}
        inc = linked.get(str(p.get("proposal_id")))
        with st.container(border=True):
            c1, c2 = st.columns([4, 2])
            c1.markdown(f"**{v['vendor_name']}** · invoice {inv.get('invoice_no', '-')} · "
                        f"**{story.czk(v['amount_minor'])}**")
            c2.markdown(status_chip(label, colour) + (attack_tag(inc) if inc else ""), unsafe_allow_html=True)
            if inc and inc.get("next"):
                st.error(f"Linked to an attack ({inc['kind'].rstrip('?')}): {inc['next']}")
            blocks = story._reasons(v.get("facts", []), ("BLOCK", "WARN"))
            if blocks and v.get("status") == "EXECUTED":
                st.markdown(f"{blocks}: the clerk confirmed the exact amount and account on the Trezor.")
            elif blocks:
                st.markdown(f"Why: {blocks}")
            ch = v.get("challenge")
            if ch and v.get("status") in WAITING_SIG:
                st.caption("The clerk's Trezor must show exactly this text. The device signs what it shows, not "
                           "what this screen shows: if anything on the Trezor differs, reject it there.")
                left = expires_in(ch)
                if left is not None:
                    st.markdown(f"**Approve within {left // 60}:{left % 60:02d}**" if left > 0 else
                                "**Expired:** this approval request can no longer be signed; the invoice must be "
                                "submitted again.")
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
    linked = story.linked(data.get("security"))
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
        inc = linked.get(str(ev.get("subject_id")))
        st.markdown(f"{_ts(ev.get('ts'))} · **{d.get('purpose')}** · {d.get('role')} · "
                    f"`{addr[:10]}…` {device_chip(label)} {outcome} · `{ev.get('subject_id')}`"
                    + (f" {attack_tag(inc)}" if inc else ""), unsafe_allow_html=True)


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
    with st.container(border=True):
        event_log(st, data)
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
    refusals = recent_attacks()
    if ident.role == "auditor":
        bundle = export_bundle()
        return {"who": ident.principal, "bundle": bundle, "refusals_live": refusals is not None,
                "security": story.security(bundle, seed_seq=seed_seq(), refusals=refusals or [])}
    vendors = _list("/vendors", "vendors")
    proposals = _list("/proposals", "proposals", limit=50)
    changes = _list("/changes", "changes")
    ledger = _list("/ledger", "txs")
    bundle = export_bundle()
    kpis, cards = story.build(bundle, vendors, changes, proposals)
    return {"who": ident.principal, "vendors": vendors,
            "names": {v["vendor_id"]: v.get("name") or v["vendor_id"] for v in vendors},
            "proposals": proposals, "changes": changes, "ledger": ledger, "bundle": bundle,
            "rail": rail_hashes(bundle), "kpis": kpis, "cards": cards,
            "refusals_live": refusals is not None,
            "security": story.security(bundle, vendors, changes, proposals, seed_seq=seed_seq(),
                                       refusals=refusals or [])}


def recent_attacks() -> list[dict[str, Any]] | None:
    """Request-level attacks that wrote no audit leaf (executor.oplog ring): in-process on memory:, the loopback
    stack's RECENT_PATH on a local URL; None against AWS (they are CloudWatch lines there)."""
    from executor import oplog

    if ".execute-api." in EXECUTOR:
        return None
    if EXECUTOR.startswith("memory:"):
        _call()
        return oplog.recent(scope=_STORE)
    if EXECUTOR.startswith(("http://127.0.0.1", "http://localhost")):
        return oplog.fetch_recent(_call())
    return None


TAB_RENDER = {
    "Overview": tab_overview, "Security": tab_security, "Payments": tab_payments, "Payee changes": tab_changes, "Approvals": tab_approvals,
    "Mandate": tab_mandate, "Audit": tab_audit, "Reports": lambda st, data: tab_reports(st),
}


def body(st: Any, ident: auth.Identity | None = None) -> None:
    ident = ident or auth.Identity("local", "operator")
    data = load(ident)
    attack_banner(st, data.get("security"))
    if ident.role == "operator":
        k = data["kpis"]
        pend = [p for p in data["proposals"] if p.get("status") in WAITING_SIG]
        dead = [p for p in pend if expires_in((p.get("decision") or {}).get("challenge") or {}) == 0]
        n = len(pend) - len(dead) + sum(c.get("state") in ("SIG_CLERK", "SIG_TREASURY") for c in data["changes"])
        if n:
            st.warning(f"{n} {'item waits' if n == 1 else 'items wait'} for a hardware signature. Open the Payments "
                       "tab and check the text on the Trezor before you approve."
                       + (f" ({len(dead)} older approval request{'' if len(dead) == 1 else 's'} expired and can no "
                          "longer be signed.)" if dead else ""))
        m = st.columns(4)
        m[0].metric("Paid to registered suppliers", story.czk(k["paid_minor"]), f"{k['paid_n']} payment{'' if k['paid_n'] == 1 else 's'}",
                    delta_color="off")
        m[1].metric("Paid to unregistered accounts", story.czk(k["attacker_minor"]))
        m[2].metric("Incidents blocked", (data.get("security") or {}).get("n", 0), "see the Security tab",
                    delta_color="off")
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
