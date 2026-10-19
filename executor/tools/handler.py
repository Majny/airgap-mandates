"""Tools λ handler (POST /tools/{name}). CONTRACTS.md v2 §4.1 #18, §4.5. Owner: WS-E.

Order per call: request check (step int >= 0, canonical args; else logged 400) -> claim (session_id, step) (T-STEP-REUSE) -> manifest hash pin -> known tool -> argument schema -> Cedar tool policy (A2) -> executor call with the
tools role (no token passthrough; in-process dispatch on memory/moto, SigV4 HTTP to the executor on aws) -> one
`tool_call` leaf + `tool_calls` row (F-ANOM toollog). Untrusted content is returned wrapped in <untrusted> tags.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import date, timedelta
from typing import Any

import jsonschema

from executor.canonical import canonical_json, sha256_hex
from executor.config import now
from executor.egress import allowlist
from executor.errors import ApiError, ErrorCode
from executor.store import shims
from executor.docs import extract
from executor.tools import policy as tool_policy
from executor.tools.manifest import DECOY_TOOLS, TOOL_MANIFEST, manifest_sha256

UNTRUSTED_WINDOW = 3  # steps; taint rule "untrusted read within the last 3 steps" (LOG_ONLY, feeds F-ANOM)
UNTRUSTED_SECONDS = 120  # ...or any untrusted read in the last 120 s, whatever the (agent-chosen) session and step
LOOKUP_WINDOW_MINUTES = 10  # T-LOOKUP-RATE also counts per principal over a rolling window, not only per session
MAX_HINTS = 5
_AT_FMT = "%Y-%m-%dT%H:%M:%SZ"
_IBAN_RE = re.compile(r"[A-Z]{2}\s?\d{2}(?:\s?[A-Z0-9]){11,30}", re.I)
_REGISTRY_META_ID = "registry#meta"

# mail.send_template: the agent picks a template and fills short vars; the body text is ours, not the model's.
MAIL_TEMPLATES: dict[str, str] = {
    "ack_invoice": "Hello, we received invoice {invoice_no}. Thank you.",
    "payment_scheduled": "Hello, payment for invoice {invoice_no} is scheduled for {date}.",
    "request_resend": "Hello, please resend invoice {invoice_no}; the attachment could not be read.",
    "query_amount": "Hello, the amount on invoice {invoice_no} does not match our order {po}. Please confirm.",
}
_VAR_RE = re.compile(r"^[A-Za-z0-9 ._/:-]{0,40}$")
_VAR_SHAPE = {"date": re.compile(r"^\d{4}-\d{2}-\d{2}$"), "po": re.compile(r"^PO-[A-Za-z0-9-]{1,20}$")}
_PO_RE = re.compile(r"PO-[A-Za-z0-9-]+")
_DATE_RANGE = (date(2020, 1, 1), date(2035, 12, 31))


# ---------------------------------------------------------------- executor transport

def _executor(method: str, path: str, body: Any, *, store: Any, settings: Any,
              query: dict[str, str] | None = None) -> Any:
    """Call the executor as the tools principal; ApiError on 4xx/5xx."""
    if settings.backend == "aws":
        status, out = _executor_http(method, path, body, settings=settings, query=query)
    else:
        from executor import handler

        status, out = handler.dispatch(method, path, query, body, principal="tools",
                                       ctx=handler.Context(settings, store))
    if status >= 400:
        assert isinstance(out, dict)
        raise ApiError(out.get("error", ErrorCode.INTERNAL_ERROR), out.get("message", ""), out.get("details"))
    return out


def _executor_http(method: str, path: str, body: Any, *, settings: Any,
                   query: dict[str, str] | None) -> tuple[int, Any]:
    """SigV4 request to the private executor API with this λ's own role (execute-api:Invoke)."""
    from urllib.parse import urlencode

    import boto3
    import httpx
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    url = settings.executor_url.rstrip("/") + path + (f"?{urlencode(query)}" if query else "")
    data = None if body is None else json.dumps(body).encode()
    req = AWSRequest(method=method, url=url, data=data, headers={"content-type": "application/json"})
    SigV4Auth(boto3.Session().get_credentials(), "execute-api", settings.aws_region).add_auth(req)
    r = httpx.request(method, url, content=data, headers=dict(req.headers.items()), timeout=20)
    ctype = r.headers.get("content-type", "")
    return r.status_code, (r.json() if "json" in ctype else r.content)


# ---------------------------------------------------------------- session state (toollog)

def _history(store: Any, session_id: str) -> list[dict[str, Any]]:
    return store.query("tool_calls", ("session_id", session_id))


def _context(name: str, args: dict[str, Any], history: list[dict[str, Any]], step: int,
             vendors: list[dict[str, Any]], *, effect: str, store: Any, settings: Any) -> dict[str, Any]:
    to = str(args.get("to", ""))
    vars_text = canonical_json(args.get("vars") or {}).decode() if name == "mail.send_template" else ""
    reg_ibans = {str(v.get("iban", "")) for v in vendors}
    lookups = 1 + sum(1 for h in history if h.get("tool") == "vendor.lookup")
    if name == "vendor.lookup":
        lookups = max(lookups, _lookup_window(store, settings))
    return {
        "to_allowlisted": name != "mail.send_template" or allowlist.is_allowed("send_email", to, vendors=vendors),
        "vars_match_iban": bool(_IBAN_RE.search(vars_text)) or any(i and i in vars_text for i in reg_ibans),
        "lookup_count": lookups,
        "untrusted_read_recent": effect == "propose" and _untrusted_recent(history, step, store=store,
                                                                            settings=settings),
    }


def _lookup_window(store: Any, settings: Any) -> int:
    """Count this vendor.lookup; return all lookups by the agent principal in the last 10 minutes (any session)."""
    t = now(settings)
    names = [f"toolrate#vendor.lookup#{(t - timedelta(minutes=i)).strftime('%Y%m%d%H%M')}"
             for i in range(LOOKUP_WINDOW_MINUTES)]
    total = store.increment("counters", {"name": names[0]}, "value")
    return total + sum(int((store.get("counters", {"name": n}) or {}).get("value", 0)) for n in names[1:])


def _untrusted_recent(history: list[dict[str, Any]], step: int, *, store: Any, settings: Any) -> bool:
    """Untrusted read within UNTRUSTED_WINDOW steps of this session, or within UNTRUSTED_SECONDS in any session."""
    if any(h.get("untrusted_read") and step - int(h["sk"]) <= UNTRUSTED_WINDOW for h in history):
        return True
    since = (now(settings) - timedelta(seconds=UNTRUSTED_SECONDS)).strftime(_AT_FMT)
    return any(r.get("untrusted_read") and str(r.get("at", "")) >= since for r in store.scan("tool_calls"))


def _vendors(store: Any) -> list[dict[str, Any]]:
    return [r for r in store.scan("registry") if r.get("vendor_id") != _REGISTRY_META_ID]


def _reserve(name: str, req: dict[str, Any], *, store: Any, settings: Any) -> bool:
    """Claim (session_id, step) before anything runs; False when the agent reuses a step (rows are never overwritten)."""
    return store.put_if_absent("tool_calls", {"session_id": req["session_id"], "sk": f"{int(req['step']):06d}",
                                              "tool": name, "result": "pending", "rule_ids": [],
                                              "untrusted_read": False, "at": now(settings).strftime(_AT_FMT)}, "sk")


def _log(name: str, req: dict[str, Any], result: str, rule_ids: list[str], *, untrusted: bool,
         store: Any, settings: Any, row: bool = True) -> int:
    args_sha256 = sha256_hex(canonical_json(req.get("args") or {}))
    data = {"session_id": req["session_id"], "step": req["step"], "tool": name, "args_sha256": args_sha256,
            "result": result, "rule_ids": rule_ids, "untrusted_read": untrusted}
    seq = shims.append(shims.make_event("tool_call", data, subject_id=req["session_id"], actor="tools",
                                        settings=settings), store=store, settings=settings)
    if not row:
        return seq
    store.put("tool_calls", {"session_id": req["session_id"], "sk": f"{int(req['step']):06d}", "tool": name,
                             "args_sha256": args_sha256, "result": result, "rule_ids": rule_ids,
                             "untrusted_read": untrusted, "seq": seq,
                             "at": now(settings).strftime(_AT_FMT)})
    return seq


# ---------------------------------------------------------------- tools

def _mask(iban: str | None) -> str | None:
    return None if not iban else ".." + iban[-4:]


def _untrusted(source: str, text: str) -> str:
    text = text.replace("</untrusted", "&lt;/untrusted")
    return f'<untrusted source="{source}">\n{text}\n</untrusted>'


def _email_docs(email_id: str, *, store: Any, settings: Any) -> tuple[bytes, list[dict[str, Any]]]:
    raw = _executor("GET", f"/inbox/{email_id}/raw", None, store=store, settings=settings)
    raw = bytes(raw)
    return raw, extract.documents(raw)


def _find_doc(doc_id: str, *, store: Any, settings: Any) -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
    """(email_id, document, all documents of that email)."""
    emails = _executor("GET", "/inbox", None, store=store, settings=settings)["emails"]
    for e in emails:
        _, docs = _email_docs(e["email_id"], store=store, settings=settings)
        for d in docs:
            if d["doc_id"] == doc_id:
                return e["email_id"], d, docs
    raise ApiError(ErrorCode.NOT_FOUND, f"document {doc_id}")


def _run(name: str, args: dict[str, Any], hints: list[dict[str, Any]], *, store: Any, settings: Any) -> dict[str, Any]:
    ex = lambda m, p, b=None: _executor(m, p, b, store=store, settings=settings)  # noqa: E731
    if name == "inbox.list":
        return ex("GET", "/inbox")
    if name == "inbox.read":
        raw, docs = _email_docs(args["email_id"], store=store, settings=settings)
        hdr = extract.headers(raw)
        # sender = the ingest row's from_addr (parsed from the raw header by the DKIM path), never a decoded header:
        # an RFC 2047 display name can decode to an address-like string
        row = next((e for e in ex("GET", "/inbox")["emails"] if e.get("email_id") == args["email_id"]), {})
        return {"email_id": args["email_id"], "from": row.get("from_addr") or None, "subject": hdr["Subject"],
                "documents": [{"doc_id": d["doc_id"], "kind": d["kind"], "name": d["name"]} for d in docs],
                "content": _untrusted(f"email:{args['email_id']}", "\n\n".join(
                    d["text"] if d["kind"] == "body" else f"--- attachment {d['name']} ({d['doc_id']}) ---\n{d['text']}"
                    for d in docs))}
    if name == "invoice.extract":
        email_id, doc, _ = _find_doc(args["doc_id"], store=store, settings=settings)
        return {"email_id": email_id, "draft": extract.extract_draft(doc)}
    if name == "vendor.lookup":
        if args.get("vendor_id"):
            v = ex("GET", f"/vendors/{args['vendor_id']}")
        else:
            rows = [x for x in ex("GET", "/vendors")["vendors"] if x.get("ico") == args.get("ico")]
            if not rows:
                raise ApiError(ErrorCode.NOT_FOUND, f"vendor ico {args.get('ico')}")
            v = rows[0]
        return {"vendor_id": v["vendor_id"], "ico": v["ico"], "name": v["name"], "domain": v["domain"],
                "country": v.get("country"), "contact_email": v.get("contact_email"),
                "in_network": v.get("in_network"), "iban_masked": _mask(v.get("iban")),
                "iban_history_masked": [{"iban": _mask(h.get("iban")), "from": h.get("from"), "to": h.get("to")}
                                        for h in v.get("iban_history") or []]}
    if name == "mandate.status":
        try:
            m = ex("GET", "/mandates/active")
        except ApiError as e:
            if e.code == ErrorCode.NO_MANDATE:
                return {"active": False}
            raise
        return {"active": True, "mandate_id": m["mandate_id"], "currency": m.get("currency"),
                "max_per_payment_minor": m["max_per_payment_minor"],
                "remaining_minor": m["max_total_minor"] - m.get("spent_minor", 0),
                "remaining_count": m["max_count"] - m.get("count", 0), "valid_until": m["valid_until"]}
    if name == "payment.propose":
        email_id, doc, docs = _find_doc(args["invoice_ref"], store=store, settings=settings)
        vendor = ex("GET", f"/vendors/{args['vendor_id']}")
        siblings = [extract.extract_draft(d) for d in docs if d["doc_id"] != doc["doc_id"]]
        draft = extract.extract_draft(doc)
        inv, warn = invoice_from_document(args, draft, vendor, settings=settings, siblings=siblings)
        inv["email_id"] = email_id
        cap = max(a for d in [draft, *siblings] if (a := d["fields"]["amount_minor"]) is not None)
        _check_cumulative(inv, cap, store=store, settings=settings)
        out = ex("POST", "/proposals", {"invoice": inv, "hints": hints})
        return {"proposal_id": out["proposal"]["proposal_id"], "decision": out["decision"]["decision"],
                "rule_ids": out["decision"].get("rule_ids", []), "tx_id": (out.get("tx") or {}).get("tx_id"),
                "_warn": warn}
    if name == "payee.request_change":
        body = {"vendor_id": args["vendor_id"], "new_iban": re.sub(r"\s", "", args["new_iban"]).upper(),
                "evidence_ids": args.get("evidence_ids", []), "hints": hints}
        out = ex("POST", "/changes", body)
        ch = out["change"]
        return {"change_id": ch["change_id"], "state": ch.get("state")}
    if name == "mail.send_template":
        tpl = MAIL_TEMPLATES.get(args["template_id"])
        if tpl is None:
            raise ApiError(ErrorCode.INVALID_REQUEST, f"unknown template {args['template_id']}")
        vars_ = {k: str(v) for k, v in (args.get("vars") or {}).items()}
        bad = [k for k, v in vars_.items() if not _VAR_RE.match(v)
               or (k in _VAR_SHAPE and not _VAR_SHAPE[k].match(v))]
        if not bad:
            bad = _unbound_vars(vars_, args["to"], ex)
        if bad:
            raise ApiError(ErrorCode.INVALID_REQUEST, f"template vars not allowed: {bad}")
        try:
            content = tpl.format_map(_Strict(vars_))
        except KeyError as e:
            raise ApiError(ErrorCode.INVALID_REQUEST, f"missing template var {e}") from e
        out = ex("POST", "/egress", {"tool": "send_email", "target": args["to"], "content": content})
        return {"sent": out["decision"] == "allow", "simulated": True}
    raise ApiError(ErrorCode.NOT_FOUND, f"tool {name}")


def _sender_documents(to: str, ex: Any) -> list[dict[str, Any]]:
    """Documents of the emails received from the recipient's domain."""
    domain = to.rsplit("@", 1)[-1].lower()
    out: list[dict[str, Any]] = []
    for e in ex("GET", "/inbox")["emails"]:
        if str(e.get("from_domain", "")).lower() != domain:
            continue
        try:
            out += extract.documents(bytes(ex("GET", f"/inbox/{e['email_id']}/raw")))
        except ApiError:  # unreadable email: contributes nothing (fail closed)
            continue
    return out


def _unbound_vars(vars_: dict[str, str], to: str, ex: Any) -> list[str]:
    """Vars carrying digits must mean something (an IBAN split over messages needs digits): invoice_no and po must
    appear in the recipient's own documents, date must be a real calendar date in 2020..2035. Other vars: no digits."""
    digits = {k: v for k, v in vars_.items() if any(c.isdigit() for c in v)}
    if not digits:
        return []
    docs = _sender_documents(to, ex) if {"invoice_no", "po"} & set(digits) else []
    bad = []
    for k, v in digits.items():
        if k == "invoice_no":
            ok = v in {n for d in docs if (n := extract.extract_draft(d)["fields"]["invoice_no"])}
        elif k == "po":
            ok = any(v in _PO_RE.findall(d["text"]) for d in docs)
        elif k == "date":
            try:
                ok = _DATE_RANGE[0] <= date.fromisoformat(v) <= _DATE_RANGE[1]
            except ValueError:
                ok = False
        else:
            ok = False
        if not ok:
            bad.append(k)
    return bad


def _check_cumulative(inv: dict[str, Any], doc_amount: int, *, store: Any, settings: Any) -> None:
    """PARTIAL cannot add up past the email's document: live proposals (EXECUTED/PENDING_SIG) of the same email
    (body and attachments are one invoice) or the same invoice_ref count, whatever their vendor."""
    rows = _executor("GET", "/proposals", None, store=store, settings=settings)["proposals"]
    email_id = inv.get("email_id")
    prior = sum(int(r["invoice"]["amount_minor"]) for r in rows if r.get("status") in ("EXECUTED", "PENDING_SIG")
                and ((r.get("invoice") or {}).get("invoice_ref") == inv["invoice_ref"]
                     or (email_id and (r.get("invoice") or {}).get("email_id") == email_id)))
    if prior + int(inv["amount_minor"]) > doc_amount:
        raise DocMismatch(["T-AMOUNT-MISMATCH"],
                          f"amount {inv['amount_minor']} + earlier proposals {prior} > document {doc_amount}")


class DocMismatch(ApiError):
    """payment.propose args disagree with the provenance-hashed document (P3 extended to amounts)."""

    def __init__(self, rule_ids: list[str], detail: str) -> None:
        super().__init__(ErrorCode.CALLER_NOT_ALLOWED, detail, {"rule_ids": rule_ids})
        self.rule_ids = rule_ids


_SIBLING_FIELDS = ("invoice_no", "issue_date", "supplier_ico")


def bind_to_email(draft: dict[str, Any], siblings: list[dict[str, Any]]) -> dict[str, Any]:
    """The draft with invoice_no / issue_date / supplier_ico taken from the other documents of the same email when
    it lacks them (exactly one distinct value there, else left empty): the body and the ISDOC attachment of one
    email are one invoice, so I-DUP and the ICO check see the same values whichever document the agent cites."""
    fields = dict(draft["fields"])
    for k in _SIBLING_FIELDS:
        values = {v for s in siblings if (v := s["fields"].get(k))}
        if not fields.get(k) and len(values) == 1:
            fields[k] = values.pop()
    return {**draft, "fields": fields}


def invoice_from_document(args: dict[str, Any], draft: dict[str, Any], vendor: dict[str, Any], *,
                          settings: Any, siblings: list[dict[str, Any]] | None = None
                          ) -> tuple[dict[str, Any], list[str]]:
    """Build the proposal invoice from the document, never from the agent (P3 for amounts, VS, dates).

    The agent's amount/currency/vs/due/invoice_no only have to *agree* with the document: any disagreement raises
    DocMismatch (T-AMOUNT-MISMATCH for the amount, T-DOC-MISMATCH otherwise) and nothing reaches the executor.
    amount_minor below the document amount is allowed only with reason_code PARTIAL. A document without an amount
    fails closed (T-DOC-MISSING). Missing invoice_no / issue_date / supplier_ico come from the other documents of the
    same email (`siblings`, bind_to_email). Returns (invoice, WARN rule ids for fallbacks).
    """
    draft = bind_to_email(draft, siblings or [])
    f = draft["fields"]
    problems = extract.check_against_document(draft, args, vendor.get("ico"))
    if problems:
        raise DocMismatch(sorted({r for r, _ in problems}), "; ".join(w for _, w in problems)[:200])
    amount = int(args["amount_minor"])

    warn: list[str] = []
    issue = f["issue_date"]
    if not issue:  # I-DUP uses issue_date: a fallback is visible in the leaf
        warn.append("T-ISSUEDATE-FALLBACK")
        issue = f["due_date"] or now(settings).strftime("%Y-%m-%d")
    inv: dict[str, Any] = {"vendor_id": args["vendor_id"], "invoice_ref": draft["doc_id"],
                           "invoice_no": f["invoice_no"] or "DOC-" + draft["doc_id"][4:], "issue_date": issue,
                           "amount_minor": amount, "currency": f["currency"], "reason_code": args["reason_code"],
                           "attachment_sha256": draft["sha256"]}
    if not f["invoice_no"]:  # never the agent's (I-DUP keys on it): bound to the document id instead
        warn.append("T-INVOICENO-DOCID")
    if f["vs"]:
        inv["vs"] = f["vs"]
    if f["due_date"]:
        inv["due_date"] = f["due_date"]
    return inv, warn


class _Strict(dict):
    def __missing__(self, key: str) -> str:
        raise KeyError(key)


def call_tool(name: str, request: dict[str, Any], *, store: Any, settings: Any) -> dict[str, Any]:
    """Check manifest hash, evaluate the Cedar tool policy (A2), log a tool_call leaf, call the executor
    with the tools role (no token passthrough), mask IBANs to '..<last4>' in vendor.lookup results."""
    spec = TOOL_MANIFEST.get(name)
    effect = spec["effect"] if spec else ("decoy" if name in DECOY_TOOLS else "unknown")
    untrusted = effect == "read_untrusted"
    problem = _request_problem(request)
    if problem:  # before anything is reserved: no 'pending' row, one logged leaf, 400
        seq = _log_invalid(name, request, untrusted=untrusted, store=store, settings=settings)
        raise ApiError(ErrorCode.INVALID_REQUEST, problem, {"rule_ids": [], "seq": seq})
    args = dict(request.get("args") or {})
    log = lambda result, rule_ids: _log(name, request, result, rule_ids, untrusted=untrusted,  # noqa: E731
                                        store=store, settings=settings)

    history = _history(store, request["session_id"])
    if not _reserve(name, request, store=store, settings=settings):
        seq = _log(name, request, "forbidden", ["T-STEP-REUSE"], untrusted=untrusted, store=store, settings=settings,
                   row=False)
        raise ApiError(ErrorCode.CALLER_NOT_ALLOWED, f"step {request['step']} already used in this session",
                       {"rule_ids": ["T-STEP-REUSE"], "seq": seq})
    try:
        return _call_reserved(name, request, args, spec, effect, history, log, store=store, settings=settings)
    except Exception:
        key = {"session_id": request["session_id"], "sk": f"{request['step']:06d}"}
        if (store.get("tool_calls", key) or {}).get("result") == "pending":  # never leave a stale 'pending' row
            try:
                log("error", [])
            except Exception:  # noqa: BLE001 - the row at least must not stay pending
                store.put("tool_calls", {**key, "tool": name, "result": "error", "rule_ids": [],
                                         "untrusted_read": untrusted, "at": now(settings).strftime(_AT_FMT)})
        raise


def _call_reserved(name: str, request: dict[str, Any], args: dict[str, Any], spec: dict[str, Any] | None,
                   effect: str, history: list[dict[str, Any]], log: Any, *, store: Any,
                   settings: Any) -> dict[str, Any]:
    if request["manifest_sha256"] != manifest_sha256():
        seq = log("forbidden", ["T-MANIFEST"])
        raise ApiError(ErrorCode.CALLER_NOT_ALLOWED, "tool manifest hash mismatch",
                       {"rule_ids": ["T-MANIFEST"], "seq": seq})
    if spec is None and name not in DECOY_TOOLS:
        log("error", [])
        raise ApiError(ErrorCode.NOT_FOUND, f"unknown tool {name}")

    vendors = _vendors(store)
    ctx = _context(name, args, history, int(request["step"]), vendors, effect=effect, store=store, settings=settings)
    allowed, rule_ids = tool_policy.authorize(name, effect=effect, mode=str(request.get("mode", "unknown")),
                                              session_id=request["session_id"], context=ctx)
    if not allowed:
        seq = log("forbidden", rule_ids)
        raise ApiError(ErrorCode.CALLER_NOT_ALLOWED, f"tool {name} forbidden for Agent",
                       {"rule_ids": rule_ids, "seq": seq})
    if ctx["untrusted_read_recent"]:
        rule_ids = ["T-TAINT"]  # LOG_ONLY: recorded for F-ANOM, never blocks

    try:
        hints = _pop_hints(name, args)
        _validate_args(name, args)
        result = _run(name, args, hints, store=store, settings=settings)
    except DocMismatch as e:
        seq = log("forbidden", rule_ids + e.rule_ids)
        raise ApiError(e.code, e.message, {"rule_ids": e.rule_ids, "seq": seq}) from e
    except Exception:
        log("error", rule_ids)
        raise
    rule_ids = rule_ids + (result.pop("_warn", None) or [])
    seq = log("ok", rule_ids)
    return {"result": result, "seq": seq}


def _request_problem(request: dict[str, Any]) -> str | None:
    """Why the request cannot be logged canonically (step not an int >= 0, floats/NaN in args), or None."""
    step = request.get("step")
    if type(step) is not int or step < 0:
        return "step must be an integer >= 0"
    if not isinstance(request.get("session_id"), str):
        return "session_id must be a string"
    if not isinstance(request.get("args", {}), dict):
        return "args must be an object"
    try:
        canonical_json(request.get("args") or {})
    except (TypeError, ValueError) as e:
        return f"args are not canonical JSON ({type(e).__name__}: no floats/NaN)"
    return None


def _log_invalid(name: str, request: dict[str, Any], *, untrusted: bool, store: Any, settings: Any) -> int:
    """tool_call leaf for a request that cannot be canonicalised (no tool_calls row is written)."""
    try:
        raw = json.dumps(request.get("args"), sort_keys=True, default=repr).encode()
    except (TypeError, ValueError):
        raw = repr(request.get("args")).encode()
    step = request.get("step")
    data = {"session_id": str(request.get("session_id")), "step": step if type(step) is int else -1, "tool": name,
            "args_sha256": hashlib.sha256(raw).hexdigest(), "result": "error", "rule_ids": [],
            "untrusted_read": untrusted}
    return shims.append(shims.make_event("tool_call", data, subject_id=data["session_id"], actor="tools",
                                         settings=settings), store=store, settings=settings)


def _pop_hints(name: str, args: dict[str, Any]) -> list[dict[str, Any]]:
    """Validated hints ([] if absent): at most MAX_HINTS objects, exactly {source: 'agent', text: str <= 200}."""
    if "hints" not in TOOL_MANIFEST[name]["args"] or "hints" not in args:
        return []
    hints = args.pop("hints")
    ok = isinstance(hints, list) and len(hints) <= MAX_HINTS and all(
        isinstance(h, dict) and set(h) == {"source", "text"} and h["source"] == "agent"
        and isinstance(h["text"], str) and len(h["text"]) <= 200 for h in hints)
    if not ok:
        raise ApiError(ErrorCode.INVALID_REQUEST, f"hints: at most {MAX_HINTS} {{source: 'agent', text <= 200}}")
    return [{"source": "agent", "text": h["text"]} for h in hints]


def _validate_args(name: str, args: dict[str, Any]) -> None:
    spec = TOOL_MANIFEST[name]["args"]
    schema = {"type": "object", "properties": spec, "additionalProperties": False}
    try:
        jsonschema.validate(args, schema)
    except jsonschema.ValidationError as e:
        raise ApiError(ErrorCode.INVALID_REQUEST, f"args: {e.message}") from e
    required = {"inbox.read": ["email_id"], "invoice.extract": ["doc_id"],
                "payment.propose": ["vendor_id", "invoice_ref", "invoice_no", "amount_minor", "currency",
                                    "reason_code"],
                "payee.request_change": ["vendor_id", "new_iban"],
                "mail.send_template": ["to", "template_id"]}.get(name, [])
    missing = [k for k in required if k not in args]
    if name == "vendor.lookup" and not (args.get("vendor_id") or args.get("ico")):
        missing.append("vendor_id|ico")
    if missing:
        raise ApiError(ErrorCode.INVALID_REQUEST, f"args missing: {missing}")

