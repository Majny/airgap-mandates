"""Canonical display renderer (docs/CONTRACTS.md §5, docs/ARCHITECTURE.md §3.4).

Owner: WS-C. Shared by every workstream; the Python API in CONTRACTS §5.6 is frozen.

The executor renders the text a human signs on the Trezor Safe 5 from its own data (S2).
The text is exactly what the device shows: profile `safe5-mono-18x7` = 18 mono columns x
7 lines per page, at most 2 pages, ASCII 0x20-0x7E plus LF, line 1 starts `AG1/<DEPLOY>`.
Only executor-verified [F] content is ever rendered; [H] facts are dropped (D3) and any
BLOCK fact raises (R0: nothing to approve means nothing on the device).

Pagination is implicit: `render()` returns one LF-joined string; the device breaks pages
every 7 lines, so page 1 of a 2-page text is exactly 7 lines. `render_pages()` splits it.
Output is deterministic: same inputs -> byte-identical text.
"""

from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import dataclass, field, replace
from datetime import date, datetime
from itertools import combinations
from typing import Any, Iterable, Mapping, Sequence
from zoneinfo import ZoneInfo

from executor.canonical import canonical_json

# --------------------------------------------------------------------------- profiles

PROFILE_SAFE5 = "safe5-mono-18x7"
PROFILE_UI = "ui-preview-32"
DEFAULT_PROFILE = PROFILE_SAFE5


@dataclass(frozen=True)
class Profile:
    name: str
    width: int  # columns per line
    lines_per_page: int
    max_pages: int
    break_line_max: int  # max length of page-1 last line and page-2 first line (marker may eat columns)
    min_width: int
    exact_first_page: bool  # device pagination: page 1 of a 2-page text has exactly lines_per_page lines


PROFILES: dict[str, Profile] = {
    PROFILE_SAFE5: Profile(PROFILE_SAFE5, width=18, lines_per_page=7, max_pages=2, break_line_max=15,
                           min_width=18, exact_first_page=True),
    # UI preview only (never sent to a device): same layout, wider lines, no device pagination rule.
    PROFILE_UI: Profile(PROFILE_UI, width=32, lines_per_page=7, max_pages=2, break_line_max=32,
                        min_width=18, exact_first_page=False),
}

DEFAULT_WIDTH = PROFILES[DEFAULT_PROFILE].width  # 18
LINES_PER_PAGE = 7
MAX_PAGES = 2
MAX_LINES = LINES_PER_PAGE * MAX_PAGES  # 14
BREAK_LINE_MAX = 15  # until H0 measures the "..." page-break marker
MIN_WIDTH = {name: p.min_width for name, p in PROFILES.items()}
DEFAULT_DEPLOYMENT = "DEMO"
PROTOCOL_TAG = "AG1"
DISPLAY_TZ = "Europe/Prague"

TEMPLATES = ("MANDATE", "CHG", "PAY", "VENDOR_ATTEST", "ENROLL", "CHG_REJECT")

# CONTRACTS §2.1 / §5.4: display order of fact ids on the device. Unknown ids sort after, lexicographic.
FACT_ORDER = (
    "F-MANDATE",
    "F-ATTEST",
    "F-CALLBACK",
    "F-DOMAIN",
    "F-DKIM",
    "F-DOMAIN-AGE",
    "F-WARNLIST",
    "F-SANCTION",
    "F-VOP",
    "F-PSP",
    "F-VAT",
    "F-BANK",
    "F-FIRSTSEEN",
    "F-DUP",
    "F-SPLIT",
    "F-Z",
    "F-ANOM",
    "F-NAME-TRANSLIT",
)
_SEVERITIES = ("INFO", "WARN", "BLOCK")
_TRUNC = "~"

# Vendor signer role -> device label (ATTEST page 2).
ROLE_DISPLAY = {"director": "DIR", "accountant": "ACCT", "finance": "FIN"}

# Executor-owned transliteration table (its hash is part of policy_hash, CONTRACTS §8.1).
# Applied before NFKD; anything still non-ASCII afterwards raises RenderError("NON_ASCII").
TRANSLIT: dict[str, str] = {
    "á": "a", "č": "c", "ď": "d", "é": "e", "ě": "e", "í": "i", "ň": "n", "ó": "o", "ř": "r",
    "š": "s", "ť": "t", "ú": "u", "ů": "u", "ý": "y", "ž": "z", "ä": "a", "ö": "o", "ü": "u",
    "ľ": "l", "ĺ": "l", "ŕ": "r", "ô": "o",
    "Á": "A", "Č": "C", "Ď": "D", "É": "E", "Ě": "E", "Í": "I", "Ň": "N", "Ó": "O", "Ř": "R",
    "Š": "S", "Ť": "T", "Ú": "U", "Ů": "U", "Ý": "Y", "Ž": "Z", "Ä": "A", "Ö": "O", "Ü": "U",
    "Ľ": "L", "Ĺ": "L", "Ŕ": "R", "Ô": "O",
    "ß": "SS", "Æ": "AE", "æ": "ae", "Ø": "O", "ø": "o", "Ł": "L", "ł": "l", "Đ": "D", "đ": "d",
    "Œ": "OE", "œ": "oe", "Þ": "TH", "þ": "th", "ı": "i",
    "\u2013": "-", "\u2014": "-", "\u201e": '"', "\u201c": '"', "\u201d": '"', "\u201a": "'",
    "\u2018": "'", "\u2019": "'", "\u00a0": " ",
}

# IBAN country -> length of the bank identifier at the start of the BBAN (BANK line).
BANK_CODE_LEN = {
    "CZ": 4, "SK": 4, "LT": 5, "LV": 4, "EE": 2, "DE": 8, "AT": 5, "PL": 8, "FR": 5, "ES": 4,
    "NL": 4, "BE": 3, "GB": 4, "IE": 4, "MT": 4, "HU": 3, "SI": 5, "HR": 7, "LU": 3, "CH": 5,
    "LC": 4,
}


class RenderError(ValueError):
    """Raised when inputs cannot be rendered within the contract (fail closed)."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code


@dataclass(frozen=True)
class Fact:
    id: str
    kind: str
    severity: str
    label: str
    display_line: str
    evidence: Mapping[str, Any] | None = field(default=None, compare=False)
    prov: str | None = field(default=None, compare=False)

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
                    prov=f.get("prov"),
                )
            except KeyError as e:
                raise RenderError("PARAM", f"fact missing field {e}") from None
        if fact.kind not in ("F", "H"):
            raise RenderError("PARAM", f"bad fact kind {fact.kind!r}")
        if fact.severity not in _SEVERITIES:
            raise RenderError("PARAM", f"bad fact severity {fact.severity!r}")
        return fact


# --------------------------------------------------------------------------- helpers


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def translit_table_hash() -> str:
    """sha256(canonical_json(TRANSLIT)) - an input of policy_hash."""
    return hashlib.sha256(canonical_json(TRANSLIT)).hexdigest()


def _printable(s: str) -> bool:
    return all(" " <= c <= "~" for c in s)


def display_name(s: str) -> str:
    """Registry name -> uppercase ASCII via TRANSLIT, then NFKD; raises NON_ASCII if anything is left."""
    out = "".join(TRANSLIT.get(ch, ch) for ch in str(s))
    out = unicodedata.normalize("NFKD", out)
    out = "".join(ch for ch in out if not unicodedata.combining(ch))
    out = " ".join(out.replace("\t", " ").split())
    if not _printable(out):
        raise RenderError("NON_ASCII", f"cannot transliterate {s!r}")
    return out.upper()


def _fit(s: str, width: int) -> str:
    """Truncate free text to width, marking truncation with '~'."""
    if len(s) <= width:
        return s
    return s[: width - 1] + _TRUNC


def _check_line(line: str, width: int) -> str:
    if not _printable(line):
        raise RenderError("NON_ASCII", f"non-ASCII in line: {line!r}")
    if len(line) > width:
        raise RenderError("WIDTH", f"line exceeds width {width}: {line!r}")
    if not line.strip():
        raise RenderError("PARAM", "empty line")
    return line


def _norm_iban(iban: str) -> str:
    s = "".join(str(iban).split()).upper()
    if not (15 <= len(s) <= 34) or not s.isascii() or not s.isalnum():
        raise RenderError("PARAM", f"bad IBAN {iban!r}")
    if not (s[:2].isalpha() and s[2:4].isdigit()):
        raise RenderError("PARAM", f"bad IBAN {iban!r}")
    return s


def _iban_groups(iban: str) -> list[str]:
    s = _norm_iban(iban)
    return [s[i : i + 4] for i in range(0, len(s), 4)]


def format_iban(iban: str) -> str:
    """Full IBAN grouped by 4, e.g. 'CZ65 0800 0000 1920 0014 5399'."""
    return " ".join(_iban_groups(iban))


def format_iban_lines(label: str, iban: str, width: int) -> list[str]:
    """Full IBAN (never truncated) with optional label; balanced wrap, continuation indented to the IBAN column."""
    groups = _iban_groups(iban)
    prefix = f"{label} " if label else ""
    indent = len(prefix)
    one = prefix + " ".join(groups)
    if len(one) <= width:
        return [one]
    per_line = (width - indent + 1) // 5
    if per_line < 1:
        raise RenderError("WIDTH", "width too small for IBAN")
    n_lines = -(-len(groups) // per_line)
    base, extra = divmod(len(groups), n_lines)
    out, i = [], 0
    for li in range(n_lines):
        cnt = base + (1 if li < extra else 0)
        out.append((prefix if li == 0 else " " * indent) + " ".join(groups[i : i + cnt]))
        i += cnt
    return [_check_line(x, width) for x in out]


def iban_last4(iban: str) -> str:
    return _norm_iban(iban)[-4:]


def bank_line(iban: str) -> str | None:
    """'BANK <code> <CC>' from the IBAN itself, or None for countries not in BANK_CODE_LEN."""
    s = _norm_iban(iban)
    n = BANK_CODE_LEN.get(s[:2])
    if n is None:
        return None
    return f"BANK {s[4 : 4 + n]} {s[:2]}"


def _major(minor: int) -> str:
    if isinstance(minor, bool) or not isinstance(minor, int):
        raise RenderError("PARAM", "amount must be int minor units")
    if minor < 0:
        raise RenderError("PARAM", "negative amount")
    major, rest = divmod(minor, 100)
    return f"{major}" if rest == 0 else f"{major}.{rest:02d}"


def _currency(currency: str) -> str:
    if currency not in ("CZK", "EUR"):
        raise RenderError("PARAM", f"bad currency {currency!r}")
    return currency


def format_amount(minor: int, currency: str) -> str:
    """'125000 CZK' when whole, else '125000.50 CZK'. No thousands separators."""
    return f"{_major(minor)} {_currency(currency)}"


def _nonce(nonce: str) -> str:
    n = str(nonce)
    if len(n) != 8 or any(c not in "0123456789ABCDEF" for c in n):
        raise RenderError("PARAM", f"bad displayed nonce {nonce!r} (8 uppercase hex)")
    return n


def _hex16(h: str, name: str) -> str:
    s = str(h)
    if len(s) < 16 or any(c not in "0123456789abcdef" for c in s):
        raise RenderError("PARAM", f"bad {name} (lowercase hex, >= 16 chars)")
    return s[:16]


def _int(v: Any, name: str, minimum: int = 0) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or v < minimum:
        raise RenderError("PARAM", f"{name} must be an int >= {minimum}")
    return v


def _ico(ico: str) -> str:
    s = str(ico)
    if len(s) != 8 or not s.isdigit() or not s.isascii():
        raise RenderError("PARAM", f"bad ICO {ico!r}")
    return s


def _deployment(dep: str) -> str:
    d = str(dep)
    if not (1 <= len(d) <= 5) or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" for c in d):
        raise RenderError("PARAM", f"bad deployment {dep!r} (1-5 chars [A-Z0-9])")
    return d


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
            raise RenderError("PARAM", f"bad datetime {v!r}") from None
    else:
        raise RenderError("PARAM", f"bad datetime {v!r}")
    if dt.tzinfo is None:
        raise RenderError("PARAM", "datetime must be timezone-aware")
    return dt.astimezone(_tz())


def _to_date(v: date | str) -> date:
    if isinstance(v, datetime):
        raise RenderError("PARAM", "expected a date, got datetime")
    if isinstance(v, date):
        return v
    try:
        return date.fromisoformat(str(v))
    except ValueError:
        raise RenderError("PARAM", f"bad date {v!r}") from None


def _year_month(v: date | str) -> str:
    """'YYYY-MM' from a date, 'YYYY-MM-DD' or 'YYYY-MM'."""
    if isinstance(v, str) and len(v) == 7 and v[4] == "-" and v[:4].isdigit() and v[5:].isdigit():
        return v
    return _to_date(v).strftime("%Y-%m")


def _mmdd_hhmm(v: datetime | str) -> str:
    return _to_dt(v).strftime("%m-%d %H:%M")


def _fact_key(f: Fact):
    try:
        return (0, FACT_ORDER.index(f.id), "", f.display_line)
    except ValueError:
        return (1, 0, f.id, f.display_line)


def order_facts(facts: Iterable[Fact | Mapping[str, Any]]) -> list[Fact]:
    """Deterministic device display order (CONTRACTS §5.4): F facts only, by FACT_ORDER position."""
    fs = [Fact.from_any(f) for f in facts]
    return sorted((f for f in fs if f.kind == "F"), key=_fact_key)


def _device_facts(facts: Sequence[Fact | Mapping[str, Any]] | None) -> list[Fact]:
    fs = order_facts(facts or [])
    if any(f.severity == "BLOCK" for f in fs):
        raise RenderError("R0_BLOCK", "a BLOCK fact means no challenge (R0)")
    return fs


def _fact_line(f: Fact, width: int) -> str:
    body = " ".join(f.display_line.split())
    if not _printable(body):
        raise RenderError("NON_ASCII", f"fact {f.id} display_line is not ASCII")
    if not body:
        raise RenderError("PARAM", f"fact {f.id} has an empty display_line")
    return _fit(body.upper(), width)


def summary_line(facts: Sequence[Fact | Mapping[str, Any]] | None) -> str:
    fs = _device_facts(facts)
    return f"0 BLOCK {sum(1 for f in fs if f.severity == 'WARN')} WARN"


def _fact_lines(fs: list[Fact], slots: int, width: int) -> list[str]:
    if slots < 0:
        raise RenderError("PAGES", "template exceeds the 2-page budget")
    if len(fs) <= slots:
        return [_fact_line(f, width) for f in fs]
    if slots == 0:
        raise RenderError("PAGES", "no slot for facts")
    # Keep the most severe facts (WARN before INFO, then display order); show them in display order.
    keep_n = slots - 1
    by_priority = sorted(fs, key=lambda f: (0 if f.severity == "WARN" else 1, _fact_key(f)))
    kept = set(id(f) for f in by_priority[:keep_n])
    shown = [f for f in fs if id(f) in kept]
    overflow = f"+{len(fs) - keep_n} MORE 0 BLOCK"
    return [_fact_line(f, width) for f in shown] + [_check_line(overflow, width)]


def _title(deployment: str, kind: str, number: int | None, width: int) -> str:
    t = f"{PROTOCOL_TAG}/{_deployment(deployment)} {kind}"
    if number is not None:
        t += f" {_int(number, 'number', 1)}"
    if len(t) > width:
        raise RenderError("WIDTH", f"title does not fit: {t!r}")
    return t


def _role_line(role: str, sig_index: int, sig_total: int, width: int) -> str:
    i, n = _int(sig_index, "sig_index", 1), _int(sig_total, "sig_total", 1)
    if i > n:
        raise RenderError("PARAM", "sig_index > sig_total")
    r = str(role)
    if not r.isascii() or not r.isalpha():
        raise RenderError("PARAM", f"bad role {role!r}")
    return _check_line(f"ROLE {r.upper()} {i}/{n}", width)


def get_profile(profile: str | Profile | None = None, width: int | None = None) -> Profile:
    if isinstance(profile, Profile):
        p = profile
    else:
        name = DEFAULT_PROFILE if profile is None else profile
        if name not in PROFILES:
            raise RenderError("PARAM", f"unknown profile {profile!r}")
        p = PROFILES[name]
    if width is not None:
        if isinstance(width, bool) or not isinstance(width, int) or width < p.min_width:
            raise RenderError("WIDTH", f"width must be int >= {p.min_width} for {p.name}")
        p = replace(p, width=width, break_line_max=min(p.break_line_max, width))
    return p


# --------------------------------------------------------------------------- page assembly


@dataclass(frozen=True)
class _L:
    text: str
    prio: int = 0  # 0 = mandatory; >0 = optional, lower = higher priority
    carry: bool = False  # optional line moves to page 2 when it does not fit on page 1


def _page1(cands: list[_L], prof: Profile) -> tuple[list[str], list[str]]:
    """Choose page-1 lines (template order) and the optional lines carried to page 2."""
    mandatory = [c for c in cands if c.prio == 0]
    optional = sorted((c for c in cands if c.prio > 0), key=lambda c: c.prio)
    lpp = prof.lines_per_page
    if prof.exact_first_page:
        need = lpp - len(mandatory)
        if need < 0 or need > len(optional):
            raise RenderError("PAGE1", f"page 1 cannot be built with exactly {lpp} lines")
        chosen = None
        for combo in combinations(optional, need):  # lexicographic in priority order
            ids = {id(c) for c in combo}
            lines = [c for c in cands if c.prio == 0 or id(c) in ids]
            if len(lines[-1].text) <= prof.break_line_max:
                chosen = ids
                break
        if chosen is None:
            raise RenderError("PAGE_BREAK", "no page 1 whose last line fits the page-break rule")
    else:
        chosen = {id(c) for c in optional[: max(0, lpp - len(mandatory))]}
    page1 = [c.text for c in cands if c.prio == 0 or id(c) in chosen]
    carried = [c.text for c in cands if c.prio > 0 and id(c) not in chosen and c.carry]
    return page1, carried


def _page2(head: list[str], carried: list[str], fs: list[Fact] | None, tail: list[str], prof: Profile,
           *, summary_first: bool) -> list[str]:
    body: list[str] = []
    if fs is not None:
        body = _fact_lines(fs, prof.lines_per_page - len(head) - len(carried) - len(tail), prof.width)
    page = head + carried + body + tail
    if len(page) > prof.lines_per_page:
        raise RenderError("PAGES", "page 2 exceeds lines_per_page")
    if prof.exact_first_page and not summary_first and len(page[0]) > prof.break_line_max:
        # Page-break rule: move the first line that fits to the front (deterministic, nothing dropped).
        for i, line in enumerate(page):
            if len(line) <= prof.break_line_max:
                page = [line] + page[:i] + page[i + 1 :]
                break
        else:
            raise RenderError("PAGE_BREAK", "no page 2 line fits the page-break rule")
    return page


def _finish(lines: list[str], prof: Profile) -> str:
    for line in lines:
        _check_line(line, prof.width)
    text = "\n".join(lines)
    check_text(text, prof)
    return text


def check_text(text: str, profile: str | Profile | None = None) -> list[list[str]]:
    """Validate a display text against a profile (S11) and return its pages. Raises RenderError."""
    prof = get_profile(profile)
    if text.endswith("\n") or not text:
        raise RenderError("PARAM", "empty text or trailing newline")
    if not all(" " <= c <= "~" or c == "\n" for c in text):
        raise RenderError("NON_ASCII", "text must be ASCII 0x20-0x7E plus LF")
    ls = text.split("\n")
    for line in ls:
        _check_line(line, prof.width)
    if not ls[0].startswith(f"{PROTOCOL_TAG}/"):
        raise RenderError("PARAM", f"line 1 must start with {PROTOCOL_TAG}/<DEPLOY>")
    lpp = prof.lines_per_page
    pages = [ls[i : i + lpp] for i in range(0, len(ls), lpp)]
    if len(pages) > prof.max_pages:
        raise RenderError("PAGES", f"{len(pages)} pages > {prof.max_pages}")
    if prof.exact_first_page and len(pages) > 1:
        if len(pages[0][-1]) > prof.break_line_max or len(pages[1][0]) > prof.break_line_max:
            raise RenderError("PAGE_BREAK", f"lines adjacent to a page break must be <= {prof.break_line_max}")
    return pages


def render_pages(text: str, profile: str | Profile | None = None) -> list[list[str]]:
    """Split a rendered text into device pages (validates it first)."""
    return check_text(text, profile)


def lines(text: str) -> list[str]:
    return text.split("\n")


# --------------------------------------------------------------------------- subject hash


def subject_object(*, deployment: str, purpose: str, role: str, subject_id: str, nonce: str,
                   params: Mapping[str, Any], facts_digest: str | None, policy_hash: str) -> dict[str, Any]:
    """The object whose SHA-256(JCS) is `subject_hash` (CONTRACTS §2.3). `params` = render params minus
    subject_hash/deployment/nonce/profile/width."""
    drop = {"subject_hash", "deployment", "nonce", "profile", "width"}
    return {"v": 1, "deployment": deployment, "purpose": purpose, "role": role, "subject_id": subject_id,
            "nonce": nonce, "params": {k: v for k, v in params.items() if k not in drop},
            "facts_digest": facts_digest, "policy_hash": policy_hash}


def subject_hash(subject: Mapping[str, Any]) -> str:
    """sha256(canonical_json(subject_object)).hex() - 64 lowercase hex; the device shows the first 16."""
    return hashlib.sha256(canonical_json(dict(subject))).hexdigest()


# --------------------------------------------------------------------------- templates


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
    subject_hash: str,
    role: str = "clerk",
    sig_index: int = 1,
    sig_total: int = 1,
    deployment: str = DEFAULT_DEPLOYMENT,
    profile: str | Profile | None = None,
    width: int | None = None,
) -> str:
    p = get_profile(profile, width)
    w = p.width
    fs = _device_facts(facts)
    cands = [
        _L(_title(deployment, "PAY", proposal_no, w)),
        _L(_check_line(format_amount(amount_minor, currency), w)),
        *(_L(x) for x in format_iban_lines("", iban, w)),
        _L(_fit(display_name(payee_name), w)),
    ]
    if vs not in (None, ""):
        v = str(vs)
        if not (1 <= len(v) <= 10 and v.isdigit() and v.isascii()):
            raise RenderError("PARAM", f"bad VS {vs!r}")
        cands.append(_L(f"VS {v}", prio=1, carry=True))
    cands.append(_L(f"EXP {_mmdd_hhmm(exp)}", prio=2, carry=True))
    bl = bank_line(iban)
    if bl:
        cands.append(_L(bl, prio=3))
    page1, carried = _page1(cands, p)
    tail = [_role_line(role, sig_index, sig_total, w), f"N {_nonce(nonce)}", f"H {_hex16(subject_hash, 'subject_hash')}"]
    page2 = _page2([summary_line(fs)], carried, fs, tail, p, summary_first=True)
    return _finish(page1 + page2, p)


def render_mandate(
    *,
    mandate_no: int,
    nonce: str,
    max_per_payment_minor: int,
    max_total_minor: int,
    max_count: int,
    payee_scope: str,
    valid_from: datetime | str,
    valid_until: datetime | str,
    currency: str,
    require_vop: Sequence[str],
    payee_count: int,
    payee_registry_version: int,
    policy_hash: str,
    subject_hash: str,
    role: str = "clerk",
    sig_index: int = 1,
    sig_total: int = 1,
    deployment: str = DEFAULT_DEPLOYMENT,
    profile: str | Profile | None = None,
    width: int | None = None,
) -> str:
    p = get_profile(profile, width)
    w = p.width
    if payee_scope != "existing_only":
        raise RenderError("PARAM", f"bad payee_scope {payee_scope!r}")
    count = _int(max_count, "max_count", 1)
    vop = list(require_vop)
    if any(c not in ("MTCH", "CMTC", "NMTC", "NOAP") for c in vop):
        raise RenderError("PARAM", f"bad require_vop {require_vop!r}")
    cands = [
        _L(_title(deployment, "MANDATE", None, w)),
        _L(f"NO {_int(mandate_no, 'mandate_no', 1)} {_currency(currency)}"),
        _L(f"PER PAY {_major(max_per_payment_minor)}"),
        _L(f"TOTAL {_major(max_total_minor)}"),
        _L(f"MAX {count} {'PAYMENT' if count == 1 else 'PAYMENTS'}"),
        _L("EXISTING PAYEES"),
        _L(f"TO {_mmdd_hhmm(valid_until)}"),
    ]
    page1, carried = _page1([_L(_check_line(c.text, w)) for c in cands], p)
    page2 = _page2([], carried, None, [
        _role_line(role, sig_index, sig_total, w),
        f"FROM {_mmdd_hhmm(valid_from)}",
        _check_line(f"REQ VOP {'/'.join(vop) if vop else 'NONE'}", w),
        _check_line(f"PAYEES {_int(payee_count, 'payee_count')} REG V{_int(payee_registry_version, 'payee_registry_version')}", w),
        f"N {_nonce(nonce)}",
        f"P {_hex16(policy_hash, 'policy_hash')}",
        f"H {_hex16(subject_hash, 'subject_hash')}",
    ], p, summary_first=False)
    return _finish(page1 + page2, p)


def render_change(
    *,
    change_no: int,
    nonce: str,
    vendor_name: str,
    vendor_ico: str,
    old_iban: str,
    old_since: date | str,
    new_iban: str,
    facts: Sequence[Fact | Mapping[str, Any]],
    subject_hash: str,
    role: str = "clerk",
    sig_index: int = 1,
    sig_total: int = 2,
    deployment: str = DEFAULT_DEPLOYMENT,
    profile: str | Profile | None = None,
    width: int | None = None,
) -> str:
    p = get_profile(profile, width)
    w = p.width
    fs = _device_facts(facts)
    cands = [
        _L(_title(deployment, "CHG", change_no, w)),
        _L(_fit(display_name(vendor_name), w)),
        _L(f"ICO {_ico(vendor_ico)}"),
        _L(_check_line(f"OLD ..{iban_last4(old_iban)} {_year_month(old_since)}", w), prio=1, carry=True),
        *(_L(x) for x in format_iban_lines("NEW", new_iban, w)),
    ]
    bl = bank_line(new_iban)
    if bl:
        cands.append(_L(bl, prio=2))
    page1, carried = _page1(cands, p)
    tail = ["COOLOFF DONE", _role_line(role, sig_index, sig_total, w), f"N {_nonce(nonce)}",
            f"H {_hex16(subject_hash, 'subject_hash')}"]
    page2 = _page2([summary_line(fs)], carried, fs, tail, p, summary_first=True)
    return _finish(page1 + page2, p)


def render_vendor_attest(
    *,
    change_no: int,
    nonce: str,
    vendor_name: str,
    ico: str,
    iban: str,
    valid_from: date | str,
    signer_role: str,
    role_basis: str,
    threshold: int,
    signer_count: int,
    version: int,
    subject_hash: str,
    deployment: str = DEFAULT_DEPLOYMENT,
    profile: str | Profile | None = None,
    width: int | None = None,
) -> str:
    p = get_profile(profile, width)
    w = p.width
    t, n = _int(threshold, "threshold", 1), _int(signer_count, "signer_count", 1)
    if t > n:
        raise RenderError("PARAM", "threshold must be 1..signer_count")
    if role_basis not in ("OR", "POA"):
        raise RenderError("PARAM", f"bad role_basis {role_basis!r}")
    role = ROLE_DISPLAY.get(signer_role)
    if role is None:
        raise RenderError("PARAM", f"bad signer_role {signer_role!r}")
    cands = [
        _L(_title(deployment, "ATTEST", None, w)),
        _L(_fit(display_name(vendor_name), w)),
        _L(f"ICO {_ico(ico)}"),
        _L("PAY TO ACCOUNT"),
        *(_L(x) for x in format_iban_lines("", iban, w)),
        _L(f"FROM {_to_date(valid_from).isoformat()}", prio=1, carry=True),
    ]
    page1, carried = _page1(cands, p)
    head = [_check_line(f"SIGNER {role} ({role_basis})", w), _check_line(f"QUORUM {t}/{n} V{_int(version, 'version', 1)}", w),
            _check_line(f"CHANGE {_int(change_no, 'change_no', 1)}", w)]
    tail = [f"N {_nonce(nonce)}", f"H {_hex16(subject_hash, 'subject_hash')}"]
    page2 = _page2(head, carried, None, tail, p, summary_first=False)
    return _finish(page1 + page2, p)


def render_enroll(
    *,
    role: str,
    nonce: str,
    deployment: str = DEFAULT_DEPLOYMENT,
    profile: str | Profile | None = None,
    width: int | None = None,
) -> str:
    """Enrolment ceremony text (ARCHITECTURE §3.3), one page."""
    p = get_profile(profile, width)
    w = p.width
    r = str(role)
    if r not in ("clerk", "treasury"):
        raise RenderError("PARAM", f"bad role {role!r}")
    return _finish([_title(deployment, "ENROLL", None, w), f"ROLE {r.upper()}", f"N {_nonce(nonce)}"], p)


def render_chg_reject(
    *,
    change_no: int,
    nonce: str,
    vendor_name: str,
    vendor_ico: str,
    new_iban: str,
    subject_hash: str,
    role: str = "clerk",
    deployment: str = DEFAULT_DEPLOYMENT,
    profile: str | Profile | None = None,
    width: int | None = None,
) -> str:
    """Signed clerk rejection of a payee change (CONTRACTS §4.1 #9), one page."""
    p = get_profile(profile, width)
    w = p.width
    return _finish([
        _title(deployment, "REJECT", change_no, w),
        _fit(display_name(vendor_name), w),
        f"ICO {_ico(vendor_ico)}",
        f"NEW ..{iban_last4(new_iban)}",
        _check_line(f"ROLE {str(role).upper()}", w),
        f"N {_nonce(nonce)}",
        f"H {_hex16(subject_hash, 'subject_hash')}",
    ], p)


_DISPATCH = {
    "MANDATE": render_mandate,
    "CHG": render_change,
    "PAY": render_pay,
    "VENDOR_ATTEST": render_vendor_attest,
    "ENROLL": render_enroll,
    "CHG_REJECT": render_chg_reject,
}


def render(template: str, params: Mapping[str, Any], profile: str | Profile | None = None,
           width: int | None = None, deployment: str | None = None) -> str:
    """Re-render from stored challenge params (nonces.params). Keyword overrides win over params."""
    fn = _DISPATCH.get(template)
    if fn is None:
        raise RenderError("PARAM", f"unknown template {template!r}")
    kwargs = dict(params)
    if profile is not None:
        kwargs["profile"] = profile
    if width is not None:
        kwargs["width"] = width
    if deployment is not None:
        kwargs["deployment"] = deployment
    try:
        return fn(**kwargs)
    except TypeError as e:
        raise RenderError("PARAM", f"bad params for {template}: {e}") from None


__all__ = [
    "BREAK_LINE_MAX",
    "DEFAULT_DEPLOYMENT",
    "DEFAULT_PROFILE",
    "DEFAULT_WIDTH",
    "FACT_ORDER",
    "LINES_PER_PAGE",
    "MAX_LINES",
    "MAX_PAGES",
    "MIN_WIDTH",
    "PROFILES",
    "PROFILE_SAFE5",
    "PROFILE_UI",
    "ROLE_DISPLAY",
    "TEMPLATES",
    "TRANSLIT",
    "Fact",
    "Profile",
    "RenderError",
    "bank_line",
    "check_text",
    "display_name",
    "format_amount",
    "format_iban",
    "format_iban_lines",
    "get_profile",
    "lines",
    "order_facts",
    "render",
    "render_change",
    "render_chg_reject",
    "render_enroll",
    "render_mandate",
    "render_pages",
    "render_pay",
    "render_vendor_attest",
    "subject_hash",
    "subject_object",
    "summary_line",
    "text_sha256",
    "translit_table_hash",
]
