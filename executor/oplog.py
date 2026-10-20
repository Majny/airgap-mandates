"""Operational log of the executor (logger `airgap`): what is happening and why something failed, in plain English.
Stdout of `make local-stack` / `make dev`, CloudWatch on AWS. Owner: orchestrator.

    configure(fmt=None, level=None, stream=None) -> Logger     idempotent; entry points only (tests stay quiet)
    leaf(event, seq)                                           after every successful audit leaf write
    begin(method, path, principal) / end(...)                  one request scope per dispatch() (request id)
    internal_error(exc, method, path, principal) -> error_id   500: full traceback + an id the response carries
    emit(level, title, why, **kv)                              one explained line (e.g. a rail or witness failure)
    replay(label)                                              context: lines are a demo replay (scene=, [demo replay])
    recent(after=0) -> [dict]                                  request-level attacks of this process (no audit leaf)

One line per audit leaf (explained by executor.audit.explain), one per refused request (4xx: explain.refusal, so an
attack that only shows up as a refused call, e.g. stolen agent credentials, still produces an ATTACK line) and a
traceback per 500. A 2xx request line is DEBUG (the leaf lines carry the story) unless its response says more
(explain.response: a held payee change with red flags). Leaf lines of a request are written when it ends, after its
response body taught the explainer the supplier name (POST /changes -> change); no store read is made for logging.
A nested dispatch (an agent tool call re-entering dispatch as `tools`) shares the outer request id, its request
line is DEBUG and its leaves are told by the outer request.

Format: AIRGAP_LOG_FORMAT=text (default) | json; AIRGAP_LOG_LEVEL=INFO (default) | DEBUG (adds NOISE + request lines)
| WARNING (attacks and errors only). Colour only on a TTY and without NO_COLOR; never on Lambda. Text lines end with
key=value pairs (seq=, subject=, kind=, rule=, principal=, status=, req=; on ATTACK / ERROR lines also money=,
vendor_id=, sender_domain=, signer=, tool=, new_iban=) for CloudWatch Logs Insights `parse`; JSON lines carry the same
fields (money_minor as an integer).

ATTACK lines read `PROMPT INJECTION · <what happened> → stopped by <defence layer>: <evidence> · 0 CZK moved` (the
Track 3 vocabulary of executor.audit.explain: threat, layer, evidence); BLOCKED lines name the layer and evidence too.

Request-level attacks write no audit leaf (a caller refused at the door, an IBAN smuggled into a request, a held
payee change with red flags): besides their line they go into a small in-memory ring, `recent()`, which the loopback
stack serves read-only at RECENT_PATH for the consoles and the alert watcher. Why not an audit leaf: CONTRACTS §7.2
defines `iam_deny_mirror` as a mirror of an AWS IAM decision (source simulate|boto3|cloudtrail), not of the
executor's own caller check, and a leaf per refused request would let any credential holder grow the signed log at
will. On AWS (one ring per Lambda instance, no route) the lines are in CloudWatch.

Never breaks a request: every public function swallows its own exceptions. Never logs secrets: the explainer reads
only named fields, IBANs are masked (CZ65 …5399), untrusted text is stripped of control characters.
"""
from __future__ import annotations

import contextlib
import contextvars
import json
import logging
import os
import re
import secrets
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator, TextIO

LOGGER = logging.getLogger("airgap")
LOGGER.addHandler(logging.NullHandler())  # unconfigured (tests, libraries): no lastResort output on stderr

TAGS = {"ATTACK": "🛑 ATTACK ", "BLOCKED": "⛔ BLOCKED", "HUMAN": "✋ HUMAN  ", "PAID": "💸 PAID   ",
        "OK": "✅ OK     ", "INFO": "•  INFO   ", "NOISE": "·  NOISE  ", "ERROR": "💥 ERROR  ", "DEBUG": "·  DEBUG  "}
PY_LEVEL = {"ATTACK": logging.WARNING, "ERROR": logging.ERROR, "NOISE": logging.DEBUG, "DEBUG": logging.DEBUG}
_COLOUR = {"ATTACK": "\x1b[1;37;41m", "BLOCKED": "\x1b[33m", "HUMAN": "\x1b[1;34m", "PAID": "\x1b[1;32m",
           "OK": "\x1b[32m", "INFO": "", "NOISE": "\x1b[2m", "ERROR": "\x1b[1;35m", "DEBUG": "\x1b[2m"}
_TITLE_COLOUR = {"ATTACK": "\x1b[1;31m", "ERROR": "\x1b[1;35m", "PAID": "\x1b[1m", "HUMAN": "\x1b[1m"}
_DIM, _RESET = "\x1b[2m", "\x1b[0m"
_MARK = "_airgap_handler"


@dataclass
class _Request:
    id: str
    method: str
    path: str
    principal: str | None
    t0: float = field(default_factory=time.perf_counter)
    levels: list[str] = field(default_factory=list)  # levels of the leaf lines logged during this request
    error_logged: bool = False
    parent: _Request | None = None  # set for a nested dispatch (agent tool call): the outer request tells the story
    pending: list[tuple[dict[str, Any], int | None, str | None]] = field(default_factory=list)  # buffered leaves
    scope: int | None = None  # id() of the executor store serving the request (the ring is per store)

    @property
    def root(self) -> _Request:
        r = self
        while r.parent is not None:
            r = r.parent
        return r


_REQ: contextvars.ContextVar[_Request | None] = contextvars.ContextVar("airgap_request", default=None)
_SCENE: contextvars.ContextVar[str | None] = contextvars.ContextVar("airgap_scene", default=None)
# explain `extra` keys copied onto a line (JSON always, text on ATTACK / ERROR); all masked / shortened already
EXTRA_KEYS = ("vendor_id", "sender_domain", "signer", "tool", "session", "target", "new_iban", "iban", "tx_id",
              "invoice_no", "linked_attack")
RECENT_PATH = "/_local/recent-attacks"  # loopback stack / make dev only: outside the executor API, never on AWS
RECENT_MAX = 200
REMOTE_ATTR = "airgap_remote"  # set on a call() to the AWS API (host.signer.executor_call): fetch_recent skips it
_RECENT: list[dict[str, Any]] = []
_RECENT_N = 0
_LAST_SEQ: int | None = None  # last audit seq this process saw written (orders the ring among the leaves)
_LAST_TS: str | None = None  # its event ts (the executor's clock: fixed on the seeded demo stacks)
_KNOWN: Any = None  # explain.Known filled from the leaves this process has seen (sender domains, used approvals)
_KNOWN_MAX = 5000


def _known() -> Any:
    """Process-wide explain.Known built only from leaves already in hand (no store reads); reset when it grows."""
    global _KNOWN
    from executor.audit import explain

    k = _KNOWN
    if k is None or k.size() > _KNOWN_MAX:
        k = _KNOWN = explain.Known()
    return k


def _forget() -> None:
    global _KNOWN
    _KNOWN = None


@contextlib.contextmanager
def replay(label: str = "demo") -> Iterator[None]:
    """Lines logged inside are a replay of demo scenes, not live traffic: `scene=<label>` and a [demo replay] title
    prefix, so `grep ATTACK` / CloudWatch never mistakes them for a live attack."""
    token = _SCENE.set(label)
    try:
        yield
    finally:
        _SCENE.reset(token)


# ---------------------------------------------------------------- formatting

def _kv(rec: logging.LogRecord) -> dict[str, Any]:
    return getattr(rec, "airgap", None) or {}


class TextFormatter(logging.Formatter):
    """`2026-10-20T08:50:30.123Z 🛑 ATTACK  Replay attack stopped — why | seq=41 subject=prp_2 ...`"""

    def __init__(self, colour: bool = False) -> None:
        super().__init__()
        self.colour = colour

    def format(self, rec: logging.LogRecord) -> str:
        a = _kv(rec)
        lvl = a.get("level") or ("ERROR" if rec.levelno >= logging.ERROR else "DEBUG" if rec.levelno < logging.INFO
                                 else "ATTACK" if rec.levelno == logging.WARNING else "INFO")
        ts = datetime.fromtimestamp(rec.created, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        tag = TAGS.get(lvl, f"   {lvl:<7}")
        title, why = a.get("title") or rec.getMessage(), a.get("why")
        why = _without_evidence(why, a.get("evidence"))
        keys = ("log", "seq", "subject", "kind", "rule", "principal", "status", "ms", "error_id", "req", "scene")
        if lvl in ("ATTACK", "BLOCKED", "ERROR"):
            keys += ("threat", "layer")
        if lvl in ("ATTACK", "ERROR"):
            keys += ("money",) + EXTRA_KEYS
        pairs = [(k, a.get(k)) for k in keys]
        kv = " ".join(f"{k}={_q(v)}" for k, v in pairs if v not in (None, "", []))
        if self.colour:
            line = f"{_DIM}{ts}{_RESET} {_COLOUR.get(lvl, '')}{tag}{_RESET} {_TITLE_COLOUR.get(lvl, '')}{title}{_RESET}"
            line += f" — {why}" if why else ""
            line += f"  {_DIM}| {kv}{_RESET}" if kv else ""
        else:
            line = f"{ts} {tag} {title}" + (f" — {why}" if why else "") + (f"  | {kv}" if kv else "")
        if rec.exc_info:
            line += "\n" + self.formatException(rec.exc_info)
        return line


class JsonFormatter(logging.Formatter):
    """One JSON object per line (CloudWatch Logs Insights reads the fields directly)."""

    def format(self, rec: logging.LogRecord) -> str:
        a = dict(_kv(rec))
        out = {"ts": datetime.fromtimestamp(rec.created, timezone.utc).isoformat(timespec="milliseconds")
               .replace("+00:00", "Z"), "level": a.pop("level", None) or rec.levelname, "logger": rec.name,
               "title": a.pop("title", None) or rec.getMessage(), **{k: v for k, v in a.items() if v is not None}}
        if rec.exc_info:
            out["traceback"] = self.formatException(rec.exc_info)
        return json.dumps(out, ensure_ascii=False, default=str)


def _q(v: Any) -> str:
    """One key=value value: control characters stripped and IBANs masked (no forged line, no full IBAN), quoted with
    \\ and \" escaped when it holds a space, a quote, '=' or '|' (no forged key=value pair)."""
    from executor.audit import explain

    s = explain.safe(",".join(map(str, v)) if isinstance(v, (list, tuple)) else str(v))
    if not s or any(c in s for c in ' "=|\\'):
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def _without_evidence(why: Any, evidence: Any) -> Any:
    """The text line's '— why' without its first clause when the evidence already says it (no stutter)."""
    try:
        if not why or not evidence:
            return why
        first, _, rest = str(why).partition("; ")
        bare = re.sub(r"\s*\[[^\]]*\]$", "", first).strip()
        body = str(evidence).split(": ", 1)[-1].rstrip("…")
        if bare and (bare.rstrip("…") in str(evidence) or (len(body) > 12 and body in bare)):
            return rest or None
    except Exception:  # noqa: BLE001
        pass
    return why


# ---------------------------------------------------------------- setup

def _on_lambda() -> bool:
    return bool(os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))


def configure(fmt: str | None = None, level: str | int | None = None, stream: TextIO | None = None,
              colour: bool | None = None) -> logging.Logger:
    """Install (or replace) the `airgap` handler. Idempotent. Entry points only: local_stack, executor.app, Lambda."""
    fmt = (fmt or os.environ.get("AIRGAP_LOG_FORMAT") or "text").strip().lower()
    level = level if level is not None else (os.environ.get("AIRGAP_LOG_LEVEL") or "INFO").strip().upper()
    stream = stream if stream is not None else sys.stdout
    if colour is None:
        colour = (fmt == "text" and not _on_lambda() and "NO_COLOR" not in os.environ
                  and bool(getattr(stream, "isatty", lambda: False)()))
    for h in list(LOGGER.handlers):
        if getattr(h, _MARK, False):
            LOGGER.removeHandler(h)
    h = logging.StreamHandler(stream)
    setattr(h, _MARK, True)
    h.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter(colour=colour))
    LOGGER.addHandler(h)
    LOGGER.setLevel(level if isinstance(level, int) else logging.getLevelName(level) if isinstance(
        logging.getLevelName(level), int) else logging.INFO)
    LOGGER.propagate = False  # never twice (Lambda's root handler, uvicorn)
    return LOGGER


def emit(level: str, title: str, why: str = "", *, exc_info: Any = None, **kv: Any) -> None:
    """Log one explained line (level one of explain.LEVELS or DEBUG). Never raises."""
    try:
        py = PY_LEVEL.get(level, logging.INFO)
        if not LOGGER.isEnabledFor(py):
            return
        r = _REQ.get()
        if r is not None:
            kv.setdefault("req", r.id)
        scene = _SCENE.get()
        if scene:
            kv.setdefault("scene", scene)
            title = f"[demo replay] {title}"
        from executor.audit import explain

        # untrusted text can reach any field: no control characters (a newline would forge a line), IBANs masked
        title, why = explain.safe(title), explain.safe(why) if why else why
        kv = {k: explain.safe(v) if isinstance(v, str) else v for k, v in kv.items()}
        LOGGER.log(py, "%s", title, exc_info=exc_info,
                   extra={"airgap": {"level": level, "title": title, "why": why or None, **kv}})
    except Exception:  # noqa: BLE001 - logging must never break a request
        pass


def _emit_explained(x: Any, **kv: Any) -> None:
    from executor.audit import explain

    rule = ",".join(x.rule_ids) if x.rule_ids else None
    extra = {k: x.extra.get(k) for k in EXTRA_KEYS
             if isinstance(x.extra, dict) and x.extra.get(k) not in (None, "", "?")}
    if x.money_minor is not None:
        extra["money_minor"] = x.money_minor
        extra["money"] = explain.czk(x.money_minor)
    for k in ("threat", "layer", "evidence"):
        if getattr(x, k, ""):
            extra[k] = getattr(x, k)
    if x.level == "ATTACK":
        extra["money_moved_minor"] = 0
    emit(x.level, x.headline, x.why, seq=x.seq, subject=x.subject, kind=x.kind, rule=rule, **{**extra, **kv})


def _remember(x: Any, r: _Request, status: int) -> None:
    """Keep a request-level attack (no audit leaf) in the ring served at RECENT_PATH. Never raises."""
    global _RECENT_N
    try:
        if x.level != "ATTACK":
            return
        _RECENT_N += 1
        d = {k: v for k, v in x.as_dict().items() if k not in ("extra",)}
        d.update({"n": _RECENT_N, "ts": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                  "after_seq": _LAST_SEQ, "log_ts": _LAST_TS, "method": r.method, "path": r.path, "principal": r.principal,
                  "status": status, "req": r.id, "scene": _SCENE.get(), "_scope": r.root.scope,
                  "extra": {k: v for k, v in (x.extra or {}).items() if k in EXTRA_KEYS + ("principal", "path")}})
        _RECENT.append(d)
        del _RECENT[:-RECENT_MAX]
    except Exception:  # noqa: BLE001
        pass


def fetch_recent(call: Any, after: int = 0, scope: Any = None) -> list[dict[str, Any]]:
    """Request-level attacks as a console sees them: RECENT_PATH over `call(method, path, body, who)` (the loopback
    stack), else this process's own ring (an in-process executor: memory:, tests). Empty against AWS, where they are
    CloudWatch lines only. Never raises."""
    if getattr(call, REMOTE_ATTR, False):  # AWS: no such route (a {proxy+} 404 would still invoke the Lambda)
        return []
    try:
        code, b = call("GET", f"{RECENT_PATH}?after={int(after)}", None, "auditor")
        if code == 200 and isinstance(b, dict) and isinstance(b.get("attacks"), list):
            return [d for d in b["attacks"] if isinstance(d, dict)]
    except Exception:  # noqa: BLE001 - AWS / an older stack: no such route
        pass
    return recent(after, scope)


def recent(after: int = 0, scope: Any = None) -> list[dict[str, Any]]:
    """Request-level attacks this process refused (oldest first) with n > after, of the executor store `scope` when
    given (several in-process executors may share a process: tests, a console on memory:): explained dicts (masked, no secrets)
    plus n, ts (wall clock), after_seq and log_ts (the last audit seq written before it, and its ts), method, path, principal, status, scene."""
    try:
        sid = id(scope) if scope is not None else None
        return [{k: v for k, v in d.items() if k != "_scope"} for d in list(_RECENT)
                if d.get("n", 0) > after and (sid is None or d.get("_scope") in (sid, None))]
    except Exception:  # noqa: BLE001
        return []


# ---------------------------------------------------------------- hooks

def tool_call(session: Any, step: Any, tool: str, args: Any) -> None:
    """A refused agent tool call (executor.tools.handler): keep what its log line may say about the arguments (the
    mail recipient, a masked IBAN; explain.tool_args) for the tool_call leaf, which has only args_sha256. Never
    raises."""
    try:
        from executor.audit import explain

        info = explain.tool_args(session, step, tool, args)
        if info:
            _known().tool_args[f"{session}#{step}"] = info
    except Exception:  # noqa: BLE001
        pass


def leaf(event: dict[str, Any], seq: int | None = None) -> None:
    """Called after every successful audit leaf write. Explains it from the event alone (no store reads); inside a
    request the line is written when the request ends (its response may name the supplier)."""
    try:
        r = _REQ.get()
        _saw(event, seq)
        if r is not None:
            r.root.pending.append((event, seq, r.principal))
            return
        if _fresh_log(event, seq):
            _forget()
        _leaf_line(event, seq, None, None)
    except Exception:  # noqa: BLE001
        pass


def _saw(event: Any, seq: int | None) -> None:
    global _LAST_SEQ, _LAST_TS
    if isinstance(seq, int) and isinstance(event, dict) and event.get("log_id", "audit") == "audit":
        if seq == 0:
            _RECENT.clear()  # a brand-new log: refusals of an earlier store are not about this one
        _LAST_SEQ, _LAST_TS = seq, event.get("ts") if isinstance(event.get("ts"), str) else None


def _fresh_log(event: Any, seq: int | None) -> bool:
    """Seq 0 of the audit log: a brand-new log (fresh store), so forget what an earlier one taught us."""
    return seq == 0 and isinstance(event, dict) and event.get("log_id", "audit") == "audit"


def _leaf_line(event: dict[str, Any], seq: int | None, principal: str | None, r: _Request | None) -> None:
    try:
        from executor.audit import explain

        x = explain.explain(event, seq, known=_known())
        if x is None:
            return
        if r is not None:
            r.levels.append(x.level)
        log_id = event.get("log_id") if isinstance(event, dict) else None
        _emit_explained(x, principal=principal, log=log_id if log_id != "audit" else None)
    except Exception:  # noqa: BLE001
        pass


def _flush(r: _Request) -> None:
    """Write the buffered leaf lines of a request (oldest first). Learn names from all of them first, so the
    proposal line already says 'Beta Servis a.s.' that its decision leaf (facts) told."""
    try:
        from executor.audit import explain

        pending, r.pending = r.pending, []
        if any(_fresh_log(ev, q) for ev, q, _ in pending):
            _forget()
        k = _known()
        for ev, _, _ in pending:
            explain.learn(ev, k)
        for ev, seq, principal in pending:
            _leaf_line(ev, seq, principal, r)
    except Exception:  # noqa: BLE001
        pass


def begin(method: str, path: str, principal: str | None, scope: Any = None) -> contextvars.Token | None:
    """Open a request scope (request id on every line logged until end()). Reuses an outer scope's id. `scope`: the
    executor store serving it (request-level attacks are remembered per store)."""
    try:
        outer = _REQ.get()
        rid = outer.id if outer is not None else "r" + secrets.token_hex(3)
        return _REQ.set(_Request(rid, method.upper(), path.split("?")[0], principal, parent=outer,
                                 scope=id(scope) if scope is not None else None))
    except Exception:  # noqa: BLE001
        return None


def end(token: contextvars.Token | None, status: int, body: Any) -> None:
    """Close the request scope: log the request line (see module docstring) and reset the context."""
    try:
        r = _REQ.get()
        if r is not None:
            from executor.audit import explain

            explain.learn_body(body, _known())
            if r.parent is None:
                _flush(r)
            _request_line(r, status, body)
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            if token is not None:
                _REQ.reset(token)
        except Exception:  # noqa: BLE001
            pass


def _request_line(r: _Request, status: int, body: Any) -> None:
    from executor.audit import explain

    if r.path.startswith("/_local/"):  # a console probing the loopback-only routes of an in-process executor
        return

    ms = int((time.perf_counter() - r.t0) * 1000)
    who = r.principal or "local caller"
    summary = f"{r.method} {r.path} by {who} -> {status}"
    kv = {"principal": r.principal, "status": status, "ms": ms}
    if r.parent is not None:  # nested dispatch (agent tool call): the outer request and its leaves tell the story
        err = body.get("error") if isinstance(body, dict) else None
        emit("DEBUG", f"{summary} {err or ''} (nested, {ms} ms)".replace("  ", " "), **kv)
        return
    if status < 400:
        x = explain.response(r.method, r.path, r.principal, status, body)
        if x is not None:
            _emit_explained(x, **kv)
            _remember(x, r, status)
        elif r.method != "GET":
            emit("DEBUG", f"{summary} ({ms} ms)", **kv)
        return
    err = body.get("error") if isinstance(body, dict) else None
    msg = body.get("message") if isinstance(body, dict) else None
    if status >= 500:
        level = "DEBUG" if r.error_logged else "ERROR"
        emit(level, f"{summary} {err or ''} ({ms} ms)".replace("  ", " "), explain.redact(msg, 160),
             error_id=(body.get("details") or {}).get("error_id") if isinstance(body, dict) else None, **kv)
        return
    x = explain.refusal(r.method, r.path, r.principal, status, err, msg)
    if any(lv in ("ATTACK", "BLOCKED") for lv in r.levels):  # the leaf line above already tells the story
        emit("DEBUG", f"{summary} {err} ({ms} ms)", **kv)
        return
    _emit_explained(x, **kv)
    _remember(x, r, status)


def internal_error(exc: BaseException, method: str = "", path: str = "", principal: str | None = None) -> str:
    """Log a 500 with its full traceback; returns the error id put in the response `details`."""
    error_id = "err_" + secrets.token_hex(4)
    try:
        from executor.audit import explain

        r = _REQ.get()
        if r is not None:
            r.error_logged = True
            _flush(r.root)  # what did commit before the failure comes first
        where = f"{method.upper()} {path.split('?')[0]}".strip() or "request"
        msg = explain.redact(str(exc), 120)
        emit("ERROR", f"Internal error in {where} by {principal or 'local caller'}: {type(exc).__name__}"
             + (f": {msg}" if msg else ""),
             f"not an attack; the request failed and was not applied beyond what already committed (error_id="
             f"{error_id}, traceback below)",
             exc_info=(type(exc), exc, exc.__traceback__), error_id=error_id, principal=principal, status=500)
    except Exception:  # noqa: BLE001
        pass
    return error_id


def rail_failed(exc: BaseException, tx: dict[str, Any]) -> None:
    """The payment order of a committed execution did not reach the bank (handler._submit_rail). Never raises."""
    try:
        from executor.audit import explain

        tx = tx if isinstance(tx, dict) else {}
        r = _REQ.get()
        if r is not None:
            _flush(r.root)  # the PAID line of the committed execution first
        emit("ERROR", f"Payment order {tx.get('tx_id') or '?'} not delivered to the bank",
             f"{type(exc).__name__}: {explain.redact(str(exc), 120)}; not an attack: the payment stands (committed) "
             "and recover_unsubmitted() re-submits it", exc_info=(type(exc), exc, exc.__traceback__),
             subject=tx.get("proposal_id") or tx.get("tx_id"), tx_id=tx.get("tx_id"),
             money_minor=tx.get("amount_minor"),
             money=explain.czk(tx.get("amount_minor")) if tx.get("amount_minor") is not None else None)
    except Exception:  # noqa: BLE001
        pass


def witness_error(witness: str, error: str) -> None:
    """A witness relay failure that wrote no leaf (W2 relay in the checkpointer Lambda). A checkpoint our own leaves do
    not reproduce, or a witness that refuses (HTTP 422 / 400: not an append-only extension), is ATTACK "log fork /
    witness refusal"; an outage or anything else is ERROR. Never raises."""
    try:
        from executor.audit import explain

        e = str(error or "")
        fork = "do not reproduce the checkpoint root" in e or bool(re.match(r"W2 (422|400)\b", e))
        if fork:
            x = explain.finish(explain.Explained(
                "ATTACK", "log fork / witness refusal", f"Witness {witness} REFUSED to cosign the audit log, or our "
                "stored log does not match its checkpoint", f"{explain.redact(e, 200)}; the log may have been "
                "rewritten: compare with the witnessed checkpoints (python -m tools.verify_audit) before trusting it",
                type="witness_refusal", threat=explain.LT, layer=explain.L_TLOG,
                evidence=f"witness {witness}: {explain.redact(e, 120)}"))
            _emit_explained(x)
        else:
            emit("ERROR", f"Witness {witness} relay failed", f"{explain.redact(e, 200)}; not an attack by itself: the "
                 "relay catches up on the next tick", kind="witness relay")
    except Exception:  # noqa: BLE001
        pass
