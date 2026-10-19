"""Canonical display renderer (docs/CONTRACTS.md section 5).

Owner: WS-A. Shared by every workstream; the Python API in CONTRACTS 5.5 is frozen.

The executor renders the text a human signs on the Trezor from its own data
(invariant S2). The host keeps a copy of this module for previews only.
Output is deterministic: same inputs -> byte-identical ASCII text.
"""

from __future__ import annotations

import hashlib
import math
import unicodedata
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Iterable, Mapping, Sequence
from zoneinfo import ZoneInfo

DEFAULT_WIDTH = 32
MAX_LINES = 8
MIN_WIDTH = 24
DISPLAY_TZ = "Europe/Prague"

TEMPLATES = ("MANDATE", "CHG", "PAY", "VENDOR_ATTEST")

# CONTRACTS 2.1: display tiebreak order of fact ids.
FACT_ORDER = (
    "F-MANDATE",
    "F-ATTEST",
    "F-CALLBACK",
    "F-DOMAIN",
    "F-DKIM",
    "F-FIRSTSEEN",
    "F-BANK",
    "F-DPH",
    "F-VOP",
    "F-DUP",
    "F-SPLIT",
    "F-Z",
    "H-AGENT",
    "H-UI",
)
_KIND_RANK = {"F": 0, "H": 1}
_SEVERITY_RANK = {"BLOCK": 0, "WARN": 1, "INFO": 2}
_TRUNC = "~"


class RenderError(ValueError):
    """Raised when inputs cannot be rendered within the contract (fail closed)."""


@dataclass(frozen=True)
class Fact:
    id: str
    kind: str
    severity: str
    label: str
    display_line: str
    evidence: Mapping[str, Any] | None = field(default=None, compare=False)

    @classmethod
    def from_any(cls, f: "Fact | Mapping[str, Any]") -> "Fact":
        if isinstance(f, Fact):
            fact = f
        else:
            try:
                fact = cls(
                    id=str(f["id"]),
                    kind=str(f["kind"]),
                    severity=str(f["severity"]),
                    label=str(f.get("label", "")),
                    display_line=str(f["display_line"]),
                    evidence=f.get("evidence"),
                )
            except KeyError as e:
                raise RenderError(f"fact missing field {e}") from None
        if fact.kind not in _KIND_RANK:
            raise RenderError(f"bad fact kind {fact.kind!r}")
        if fact.severity not in _SEVERITY_RANK:
            raise RenderError(f"bad fact severity {fact.severity!r}")
        return fact


# --------------------------------------------------------------------------- helpers


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def sanitize(s: str, *, hint: bool = False) -> str:
    """Free text -> printable ASCII single line (CONTRACTS 5.1)."""
    s = unicodedata.normalize("NFKD", str(s))
    out = []
    for ch in s:
        if unicodedata.combining(ch):
            continue
        if ch in "\t\r\n\v\f":
            ch = " "
        if not (" " <= ch <= "~"):
            ch = "?"
        if hint and ch == "[":
            ch = "("
        elif hint and ch == "]":
            ch = ")"
        out.append(ch)
    return " ".join("".join(out).split())


def _fit(s: str, width: int) -> str:
    """Truncate free text to width, marking truncation with '~'."""
    if width < 1:
        raise RenderError("no room for text")
    if len(s) <= width:
        return s
    return s[: width - 1] + _TRUNC


def _check_line(line: str, width: int) -> str:
    if len(line) > width:
        raise RenderError(f"line exceeds width {width}: {line!r}")
    if any(not (" " <= c <= "~") for c in line):
        raise RenderError(f"non-ASCII in line: {line!r}")
    return line


def _norm_iban(iban: str) -> str:
    s = "".join(str(iban).split()).upper()
    if not (15 <= len(s) <= 34) or not s.isalnum() or not s.isascii():
        raise RenderError(f"bad IBAN {iban!r}")
    if not (s[:2].isalpha() and s[2:4].isdigit()):
        raise RenderError(f"bad IBAN {iban!r}")
    return s


def _iban_groups(iban: str) -> list[str]:
    s = _norm_iban(iban)
    return [s[i : i + 4] for i in range(0, len(s), 4)]


def format_iban(iban: str) -> str:
    """Full IBAN grouped by 4, e.g. 'CZ65 0800 0000 1920 0014 5399'."""
    return " ".join(_iban_groups(iban))


def format_iban_lines(label: str, iban: str, width: int) -> list[str]:
    """IBAN with optional label; wraps balanced, continuation indented to IBAN column."""
    groups = _iban_groups(iban)
    prefix = f"{label} " if label else ""
    indent = len(prefix)
    one = prefix + " ".join(groups)
    if len(one) <= width:
        return [one]
    per_line = (width - indent + 1) // 5
    if per_line < 1:
        raise RenderError("width too small for IBAN")
    n_lines = math.ceil(len(groups) / per_line)
    base, extra = divmod(len(groups), n_lines)
    lines, i = [], 0
    for li in range(n_lines):
        cnt = base + (1 if li < extra else 0)
        chunk = " ".join(groups[i : i + cnt])
        i += cnt
        lines.append((prefix if li == 0 else " " * indent) + chunk)
    return [_check_line(l, width) for l in lines]


def format_amount(minor: int, currency: str) -> str:
    if isinstance(minor, bool) or not isinstance(minor, int):
        raise RenderError("amount must be int minor units")
    if minor < 0:
        raise RenderError("negative amount")
    cur = _currency(currency)
    major, rest = divmod(minor, 100)
    return f"{major} {cur}" if rest == 0 else f"{major}.{rest:02d} {cur}"


def _currency(currency: str) -> str:
    if currency not in ("CZK", "EUR"):
        raise RenderError(f"bad currency {currency!r}")
    return currency


def _count_noun(n: int) -> str:
    if n == 1:
        return "platba"
    if 2 <= n <= 4:
        return "platby"
    return "plateb"


def _nonce(nonce: str) -> str:
    n = str(nonce)
    if len(n) != 6 or any(c not in "0123456789ABCDEF" for c in n):
        raise RenderError(f"bad nonce {nonce!r}")
    return n


def _posint(v: Any, name: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise RenderError(f"{name} must be a non-negative int")
    return v


def _ico(ico: str) -> str:
    s = str(ico)
    if len(s) != 8 or not s.isdigit() or not s.isascii():
        raise RenderError(f"bad ICO {ico!r}")
    return s


def _tz() -> ZoneInfo:
    return ZoneInfo(DISPLAY_TZ)


def _to_dt(v: datetime | str) -> datetime:
    if isinstance(v, datetime):
        dt = v
    elif isinstance(v, str):
        s = v.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            raise RenderError(f"bad datetime {v!r}") from None
    else:
        raise RenderError(f"bad datetime {v!r}")
    if dt.tzinfo is None:
        raise RenderError("datetime must be timezone-aware")
    return dt.astimezone(_tz())


def _to_date(v: date | str) -> date:
    if isinstance(v, datetime):
        raise RenderError("expected a date, got datetime")
    if isinstance(v, date):
        return v
    try:
        return date.fromisoformat(str(v))
    except ValueError:
        raise RenderError(f"bad date {v!r}") from None


def _hhmm(v: datetime | str) -> str:
    return _to_dt(v).strftime("%H:%M")


def order_facts(facts: Iterable[Fact | Mapping[str, Any]]) -> list[Fact]:
    """Deterministic display order (CONTRACTS 5.4)."""
    fs = [Fact.from_any(f) for f in facts]

    def key(f: Fact):
        try:
            pos = (0, FACT_ORDER.index(f.id), "")
        except ValueError:
            pos = (1, 0, f.id)
        return (_KIND_RANK[f.kind], _SEVERITY_RANK[f.severity], pos, f.display_line)

    return sorted(fs, key=key)


def _fact_line(f: Fact, width: int) -> str:
    body = sanitize(f.display_line, hint=(f.kind == "H"))
    return _fit(f"[{f.kind}] {body}", width)


def _fact_lines(facts: Sequence[Fact | Mapping[str, Any]], slots: int, width: int) -> list[str]:
    ordered = order_facts(facts)
    if slots < 0:
        raise RenderError("template exceeds line budget")
    if len(ordered) <= slots:
        return [_fact_line(f, width) for f in ordered]
    shown = ordered[:slots]
    rest = ordered[slots:]
    if all(f.kind == "H" for f in rest):
        return [_fact_line(f, width) for f in shown]
    if slots == 0:
        raise RenderError("no slot for fact overflow line")
    shown = ordered[: slots - 1]
    omitted = ordered[slots - 1 :]
    n_block = sum(1 for f in omitted if f.severity == "BLOCK")
    overflow = _check_line(f"[F] +{len(omitted)} dalsi fakta ({n_block} BLOCK)", width)
    return [_fact_line(f, width) for f in shown] + [overflow]


def _title(full: str, width: int) -> str:
    """Title line; drops the 'AIRGAP ' prefix if it does not fit (CONTRACTS 5.1)."""
    if len(full) <= width:
        return full
    return _check_line(full.removeprefix("AIRGAP "), width)


def _width(width: int | None) -> int:
    w = DEFAULT_WIDTH if width is None else width
    if isinstance(w, bool) or not isinstance(w, int) or w < MIN_WIDTH:
        raise RenderError(f"width must be int >= {MIN_WIDTH}")
    return w


def _finish(lines: list[str], width: int) -> str:
    if len(lines) > MAX_LINES:
        raise RenderError(f"{len(lines)} lines > {MAX_LINES}")
    for l in lines:
        _check_line(l, width)
    text = "\n".join(lines)
    text.encode("ascii")
    return text


# --------------------------------------------------------------------------- templates


def render_mandate(
    *,
    mandate_no: int,
    nonce: str,
    max_per_payment_minor: int,
    max_total_minor: int,
    max_count: int,
    payee_scope: str,
    valid_until: datetime | str,
    currency: str,
    policy_hash: str,
    width: int = DEFAULT_WIDTH,
) -> str:
    w = _width(width)
    if payee_scope != "existing_only":
        raise RenderError(f"bad payee_scope {payee_scope!r}")
    ph = str(policy_hash).lower()
    if len(ph) < 8 or any(c not in "0123456789abcdef" for c in ph):
        raise RenderError("bad policy_hash")
    count = _posint(max_count, "max_count")
    lines = [
        _title(f"AIRGAP MANDATE m:{_posint(mandate_no, 'mandate_no')} n:{_nonce(nonce)}", w),
        f"max/platba {format_amount(max_per_payment_minor, currency)}",
        f"max/celkem {format_amount(max_total_minor, currency)}",
        f"max {count} {_count_noun(count)}",
        "jen existujici prijemci",
        f"plati do {_to_dt(valid_until).strftime('%Y-%m-%d %H:%M')}",
        f"policy {ph[:8]}",
    ]
    return _finish(lines, w)


def render_change(
    *,
    change_no: int,
    nonce: str,
    exp: datetime | str,
    vendor_name: str,
    vendor_ico: str,
    old_iban: str,
    new_iban: str,
    facts: Sequence[Fact | Mapping[str, Any]],
    width: int = DEFAULT_WIDTH,
) -> str:
    w = _width(width)
    title = _title(
        f"AIRGAP CHG #{_posint(change_no, 'change_no')} n:{_nonce(nonce)} exp:{_hhmm(exp)}", w
    )
    ico_part = f" ICO {_ico(vendor_ico)}"
    vendor = _fit(sanitize(vendor_name), w - len(ico_part)) + ico_part
    head = [title, vendor]
    head += format_iban_lines("OLD", old_iban, w)
    head += format_iban_lines("NEW", new_iban, w)
    return _finish(head + _fact_lines(facts, MAX_LINES - len(head), w), w)


def render_pay(
    *,
    proposal_no: int,
    nonce: str,
    exp: datetime | str,
    payee_name: str,
    iban: str,
    amount_minor: int,
    currency: str,
    vs: str | None,
    facts: Sequence[Fact | Mapping[str, Any]],
    width: int = DEFAULT_WIDTH,
) -> str:
    w = _width(width)
    amount = format_amount(amount_minor, currency)
    if vs not in (None, ""):
        v = str(vs)
        if not (1 <= len(v) <= 10 and v.isdigit() and v.isascii()):
            raise RenderError(f"bad VS {vs!r}")
        amount += f" VS {v}"
    head = [
        _title(f"AIRGAP PAY #{_posint(proposal_no, 'proposal_no')} n:{_nonce(nonce)}", w),
        _fit(sanitize(payee_name), w),
        *format_iban_lines("", iban, w),
        _check_line(amount, w),
    ]
    tail = [f"exp {_hhmm(exp)}"]
    body = _fact_lines(facts, MAX_LINES - len(head) - len(tail), w)
    return _finish(head + body + tail, w)


def render_vendor_attest(
    *,
    vendor_name: str,
    ico: str,
    version: int,
    nonce: str,
    iban: str,
    valid_from: date | str,
    signer_role: str,
    role_basis: str,
    threshold: int,
    signer_count: int,
    width: int = DEFAULT_WIDTH,
) -> str:
    w = _width(width)
    t, n = _posint(threshold, "threshold"), _posint(signer_count, "signer_count")
    if not (1 <= t <= n):
        raise RenderError("threshold must be 1..signer_count")
    title_prefix = "VENDOR ATTEST "
    role_line = f"podepisuje: {sanitize(signer_role)}"
    basis = sanitize(role_basis)
    if basis:
        role_line += f" ({basis})"
    lines = [
        title_prefix + _fit(sanitize(vendor_name), w - len(title_prefix)),
        f"ICO {_ico(ico)} v:{_posint(version, 'version')} n:{_nonce(nonce)}",
        *format_iban_lines("UCET", iban, w),
        f"platne od {_to_date(valid_from).isoformat()}",
        _fit(role_line, w),
        f"kvorum {t}/{n}",
    ]
    return _finish(lines, w)


_DISPATCH = {
    "MANDATE": render_mandate,
    "CHG": render_change,
    "PAY": render_pay,
    "VENDOR_ATTEST": render_vendor_attest,
}


def render(template: str, params: Mapping[str, Any], width: int | None = None) -> str:
    """Re-render from stored challenge params (nonces.params). `width` overrides params['width']."""
    fn = _DISPATCH.get(template)
    if fn is None:
        raise RenderError(f"unknown template {template!r}")
    kwargs = dict(params)
    if width is not None:
        kwargs["width"] = width
    try:
        return fn(**kwargs)
    except TypeError as e:
        raise RenderError(f"bad params for {template}: {e}") from None


def lines(text: str) -> list[str]:
    return text.split("\n")


__all__ = [
    "DEFAULT_WIDTH",
    "MAX_LINES",
    "FACT_ORDER",
    "TEMPLATES",
    "Fact",
    "RenderError",
    "format_amount",
    "format_iban",
    "format_iban_lines",
    "lines",
    "order_facts",
    "render",
    "render_change",
    "render_mandate",
    "render_pay",
    "render_vendor_attest",
    "sanitize",
    "text_sha256",
]
