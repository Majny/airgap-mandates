"""MostlyRight snapshot access: read-only sqlite, snapshot sha (prov), normalisation and query helpers.

CONTRACTS.md v2 §2.1 (MostlyRight snapshot). The sqlite file is built by `tools/load_mostlyright.py`; the same
normalisation functions are used at load time and at query time. Used by F-PSP, F-WARNLIST, F-SANCTION and the
MostlyRight leg of F-DOMAIN (`warning_domain_hit`). A licence / payment-scheme match (which can only help a payee)
needs record_ok = 1; sanction and warning rows match even when malformed (record_ok = 0: a listed entity must never
come out CLEAR because its row did not line up), and `unclassified_rows` counts rows that could be anything, so
F-SANCTION / F-WARNLIST report N/A instead of CLEAR on such a snapshot. Owner: WS-D.
"""
from __future__ import annotations

import os
import re
import sqlite3
import unicodedata
from pathlib import Path
from typing import Any

from rapidfuzz import fuzz, process

from executor.facts import _util

WARN_NAME_RATIO = 95  # token_sort_ratio on legal-form-stripped names, plus the same first token
SANCTION_RATIO = 92  # token_sort_ratio, plus the length guard below
SANCTION_MIN_LEN = 5  # shortest normalised core name that may match a sanctions entry at all
SANCTION_FUZZY_MIN_LEN = 10  # shorter core names must match exactly ('ing bank' != 'ingo bank')
SANCTION_LEN_RATIO = 85  # shorter/longer length in percent

# Shared mailbox / hosting domains that appear in warning lists as e-mail contacts of scammers. A hit on one of these
# says nothing about a sender, so they never count as a warnlisted domain.
SHARED_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "yahoo.fr",
    "aol.com", "icloud.com", "me.com", "protonmail.com", "proton.me", "pm.me", "tutanota.com", "tuta.io",
    "mail.com", "europe.com", "consultant.com", "email.com", "usa.com", "post.com", "gmx.com", "gmx.de", "gmx.fr",
    "gmx.net", "web.de", "mail.fr", "orange.fr", "free.fr", "laposte.net", "sfr.fr", "wanadoo.fr", "yandex.ru",
    "mail.ru", "seznam.cz", "email.cz", "centrum.cz", "zoho.com", "qq.com", "163.com",
})

# Legal-form token sequences removed from the end (and the listed prefixes from the start) of a normalised name.
_LEGAL_SUFFIXES = sorted({
    "s r o", "sro", "spol s r o", "spol sro", "a s", "as", "v o s", "vos", "k s", "ks", "z s", "o p s", "se",
    "ltd", "limited", "llc", "inc", "corp", "corporation", "plc", "gmbh", "ag", "kg", "gmbh co kg", "ohg", "e k",
    "sa", "s a", "sas", "sarl", "s a r l", "spa", "s p a", "srl", "s r l", "bv", "b v", "nv", "n v", "oy", "ab",
    "jsc", "pjsc", "ojsc", "cjsc", "ooo", "oao", "zao", "pao", "ao", "uab", "sia", "kft", "zrt", "nyrt", "doo",
    "d o o", "ad", "ead", "eood", "ltda", "lda", "sp z o o", "sp zoo", "co", "company", "fze", "fzco", "fzc",
}, key=lambda s: -len(s))
_LEGAL_PREFIXES = ("jsc", "pjsc", "ojsc", "cjsc", "ooo", "oao", "zao", "pao", "ao", "uab", "llc", "tov")
_DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$")


RECORD_TYPES = ("licence", "warning", "sanction", "payment_scheme")
SANCTION_LISTS = ("eu_financial_sanctions",)
WARNING_LISTS = ("amf_blacklists", "esma_non_compliant_casps")


def _rows_of(kind: str, lists: tuple[str, ...], alias: str = "r") -> str:
    """SQL predicate: rows of record_type `kind`, ok or not, plus malformed rows whose source_list says `kind`."""
    names = ", ".join(f"'{x}'" for x in (*lists, kind))
    return (f"({alias}.record_type = '{kind}' OR ({alias}.record_ok = 0 AND {alias}.source_list IN ({names})))")


_SANCTION_ROWS = _rows_of("sanction", SANCTION_LISTS)
_WARNING_ROWS = _rows_of("warning", WARNING_LISTS)


# --- normalisation (load time and query time) ---------------------------------------------------------------------

def norm_text(s: str) -> str:
    """Lower-case, no diacritics, control characters dropped (lost letters of the mis-encoded source), punctuation
    -> space, whitespace collapsed."""
    s = unicodedata.normalize("NFKD", str(s or ""))
    s = "".join(c for c in s if not unicodedata.combining(c) and unicodedata.category(c) != "Cc")
    s = s.casefold()
    s = "".join(c if c.isalnum() else " " for c in s)
    return " ".join(s.split())


def core_name(s: str) -> str:
    """norm_text without legal forms (s.r.o., a.s., Ltd, JSC, ...); the full normalised name if nothing remains or
    the name is a host name ('coinhouse.ltd' keeps its 'ltd')."""
    full = norm_text(s)
    if norm_domain(s) and norm_domain(s) == str(s).strip().lower():
        return full
    core = f" {full} "
    changed = True
    while changed:
        changed = False
        for suf in _LEGAL_SUFFIXES:
            if core.endswith(f" {suf} ") and len(core.strip()) > len(suf):
                core = core[: -len(suf) - 1]
                changed = True
                break
        for pre in _LEGAL_PREFIXES:
            if core.startswith(f" {pre} ") and len(core.strip()) > len(pre):
                core = core[len(pre) + 1:]
                changed = True
                break
    core = " ".join(core.split())
    return core or full


def first_token(core: str) -> str:
    return core.split(" ", 1)[0] if core else ""


def split_names(name: str, other_names: str) -> list[str]:
    """Primary name plus the ' | '-separated aliases, de-duplicated, order kept."""
    out: list[str] = []
    for n in [name, *str(other_names or "").split("|")]:
        n = " ".join(str(n or "").split())
        if n and n not in out:
            out.append(n)
    return out


def norm_domain(s: str) -> str:
    """'https://www.Acme.cz/x' -> 'acme.cz'; '' if it is not a plausible host name."""
    s = str(s or "").strip().lower()
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    s = s.split("/", 1)[0].split("?", 1)[0].split("@")[-1].split(":", 1)[0].strip(".")
    if s.startswith("www."):
        s = s[4:]
    try:
        s = s.encode("idna").decode("ascii") if not s.isascii() else s
    except UnicodeError:
        return ""
    return s if _DOMAIN_RE.match(s) else ""


def split_domains(s: str) -> list[str]:
    """A raw website_domain / email_domain cell ('a.com|https', 'a.com, b.org') -> sorted unique host names."""
    parts = re.split(r"[|,;\s]+", str(s or ""))
    return sorted({d for d in (norm_domain(p) for p in parts) if d})


def norm_national_id(s: str) -> str:
    """Alphanumeric upper-case, leading zeros dropped ('00001350' == '1350'); '' if empty."""
    s = re.sub(r"[^0-9A-Za-z]", "", str(s or "")).upper()
    return s.lstrip("0") or ("0" if s else "")


# --- snapshot access ----------------------------------------------------------------------------------------------

_CONN: dict[tuple[str, int, int], sqlite3.Connection] = {}
_SANCTION_NAMES: dict[tuple[str, int, int], tuple[list[str], list[int]]] = {}


def _key(path: str | os.PathLike[str]) -> tuple[str, int, int]:
    p = Path(path).resolve()
    st = p.stat()
    return (str(p), st.st_mtime_ns, st.st_size)


def exists(path: str | os.PathLike[str] | None) -> bool:
    return path is not None and Path(path).is_file()


def connect(path: str | os.PathLike[str]) -> sqlite3.Connection:
    """Read-only connection (uri mode=ro), cached per (path, mtime, size)."""
    key = _key(path)
    conn = _CONN.get(key)
    if conn is None:
        for old in [k for k in _CONN if k[0] == key[0]]:
            _CONN.pop(old).close()
        conn = sqlite3.connect(f"{Path(key[0]).as_uri()}?mode=ro", uri=True, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        _CONN[key] = conn
    return conn


def snapshot_sha(path: str | os.PathLike[str]) -> str:
    """SHA-256 hex of the sqlite file (the facts' prov). The sibling snapshot.sha256 is only trusted when it agrees
    with the bytes actually read; the hash of the file always wins."""
    _, sha = _util.read_snapshot(path)
    return sha


def sidecar_sha(path: str | os.PathLike[str]) -> str | None:
    """First token of the sibling snapshot.sha256 (sha256sum format), or None."""
    side = Path(path).with_name("snapshot.sha256")
    if not side.is_file():
        return None
    tok = side.read_text(encoding="ascii", errors="replace").split()
    return tok[0].lower() if tok else None


def meta(path: str | os.PathLike[str]) -> dict[str, str]:
    return {r["key"]: r["value"] for r in connect(path).execute("SELECT key, value FROM meta ORDER BY key")}


def _row(r: sqlite3.Row) -> dict[str, Any]:
    return {k: r[k] for k in r.keys()}


# --- queries ------------------------------------------------------------------------------------------------------

def psp_rows(path: str | os.PathLike[str], *, bic: str | None, national_id: str | None) -> list[dict[str, Any]]:
    """record_ok payment_scheme / licence rows for a BIC (first 8 chars) or a national id, ordered by seq."""
    conds, args = [], []
    bic8 = str(bic or "").strip().upper()[:8]
    if len(bic8) == 8:
        conds.append("bic8 = ?")
        args.append(bic8)
    nid = norm_national_id(national_id or "")
    if len(nid) >= 4:
        conds.append("nid = ?")
        args.append(nid)
    if not conds:
        return []
    sql = (f"SELECT * FROM records WHERE record_ok = 1 AND record_type IN ('payment_scheme', 'licence') "
           f"AND ({' OR '.join(conds)}) ORDER BY seq")
    return [_row(r) for r in connect(path).execute(sql, args)]


def warning_name_hit(name: str, *, mr_path: str | os.PathLike[str]) -> dict[str, Any] | None:
    """Exact / near-exact match of a payee name against warning rows (malformed ones included): token_sort_ratio >= 95 on legal-form-stripped
    names AND the same first token. Returns the best hit (ties -> lowest seq) or None."""
    core = core_name(name)
    if not core:
        return None
    sql = ("SELECT n.name, n.core, r.seq, r.record_id, r.source_list, r.category, r.since FROM names n "
           f"JOIN records r ON r.seq = n.seq WHERE n.first_tok = ? AND {_WARNING_ROWS} "
           "ORDER BY r.seq, n.name")
    best: dict[str, Any] | None = None
    for r in connect(mr_path).execute(sql, (first_token(core),)):
        score = int(round(fuzz.token_sort_ratio(core, r["core"])))
        if score >= WARN_NAME_RATIO and (best is None or score > best["score"]):
            best = {"match": "name", "record_id": r["record_id"], "source_list": r["source_list"],
                    "listed_name": r["name"], "category": r["category"], "since": r["since"], "score": score}
    return best


def warning_domain_hit(domain: str, *, mr_path: str | os.PathLike[str]) -> dict[str, Any] | None:
    """The domain (or a parent of it) is listed as website_domain / email_domain of a warning row. Shared mailbox
    providers and domains that are also the website of a licensed firm in the snapshot never count."""
    d = norm_domain(domain)
    if not d or d in SHARED_DOMAINS:
        return None
    labels = d.split(".")
    cands = [".".join(labels[i:]) for i in range(len(labels) - 1)]
    cands = [c for c in cands if c not in SHARED_DOMAINS]
    if not cands:
        return None
    qs = ",".join("?" * len(cands))
    conn = connect(mr_path)
    sql = (f"SELECT d.domain, d.kind, r.seq, r.record_id, r.source_list, r.category, r.since FROM domains d "
           f"JOIN records r ON r.seq = d.seq WHERE d.domain IN ({qs}) AND {_WARNING_ROWS} "
           f"ORDER BY length(d.domain) DESC, r.seq LIMIT 1")
    r = conn.execute(sql, cands).fetchone()
    if r is None:
        return None
    licensed = conn.execute("SELECT 1 FROM domains d JOIN records r ON r.seq = d.seq WHERE d.domain = ? "
                            "AND r.record_type = 'licence' AND r.record_ok = 1 LIMIT 1", (r["domain"],)).fetchone()
    if licensed is not None:
        return None
    return {"match": "domain", "domain": r["domain"], "kind": r["kind"], "record_id": r["record_id"],
            "source_list": r["source_list"], "category": r["category"], "since": r["since"]}


_UNCLASSIFIED: dict[tuple[str, int, int], int] = {}


def unclassified_rows(path: str | os.PathLike[str]) -> int:
    """Malformed rows that are neither a known record_type nor a sanction / warning by source_list: one of them could
    be a lost sanctions or warning entry, so F-SANCTION / F-WARNLIST never report CLEAR while this is > 0."""
    key = _key(path)
    n = _UNCLASSIFIED.get(key)
    if n is None:
        types = ", ".join(f"'{t}'" for t in RECORD_TYPES)
        n = int(connect(path).execute(
            f"SELECT count(*) FROM records r WHERE r.record_ok = 0 AND r.record_type NOT IN ({types}) "
            f"AND NOT {_SANCTION_ROWS} AND NOT {_WARNING_ROWS}").fetchone()[0])
        _UNCLASSIFIED[key] = n
    return n


def _sanction_names(path: str | os.PathLike[str]) -> tuple[list[str], list[int]]:
    key = _key(path)
    hit = _SANCTION_NAMES.get(key)
    if hit is None:
        rows = connect(path).execute(
            f"SELECT n.core, n.seq FROM names n JOIN records r ON r.seq = n.seq WHERE {_SANCTION_ROWS} "
            "AND length(n.core) >= ? ORDER BY n.seq, n.core", (SANCTION_MIN_LEN,)).fetchall()
        hit = ([r["core"] for r in rows], [r["seq"] for r in rows])
        _SANCTION_NAMES[key] = hit
    return hit


def _len_ok(a: str, b: str) -> bool:
    if a == b:
        return len(a) >= SANCTION_MIN_LEN
    lo, hi = sorted((len(a), len(b)))
    return lo >= SANCTION_FUZZY_MIN_LEN and lo * 100 >= hi * SANCTION_LEN_RATIO


def sanction_hit(name: str, ico: str, *, mr_path: str | os.PathLike[str]) -> dict[str, Any] | None:
    """National id (ICO) equality, else name/alias match against sanction rows (malformed ones included): exact core name (>= 5
    chars), or token_sort_ratio >= 92 when both cores are >= 10 chars and lengths within 85 %. Best hit or None."""
    conn = connect(mr_path)
    nid = norm_national_id(ico)
    if len(nid) >= 6:
        r = conn.execute("SELECT seq, record_id, source_list, name, category, since FROM records r WHERE nid = ? "
                         f"AND {_SANCTION_ROWS} ORDER BY seq LIMIT 1", (nid,)).fetchone()
        if r is not None:
            return {"match": "national_id", "record_id": r["record_id"], "source_list": r["source_list"],
                    "listed_name": r["name"], "category": r["category"], "since": r["since"], "score": 100}
    core = core_name(name)
    if len(core) < SANCTION_MIN_LEN:
        return None
    cores, seqs = _sanction_names(mr_path)
    best: tuple[int, int, str] | None = None  # (score, -seq, listed core)
    for listed, score, idx in process.extract_iter(core, cores, scorer=fuzz.token_sort_ratio,
                                                   score_cutoff=SANCTION_RATIO):
        if not _len_ok(core, listed):
            continue
        cand = (int(round(score)), -seqs[idx], listed)
        if best is None or cand[:2] > best[:2]:
            best = cand
    if best is None:
        return None
    r = conn.execute("SELECT record_id, source_list, name, category, since FROM records WHERE seq = ?",
                     (-best[1],)).fetchone()
    return {"match": "name", "record_id": r["record_id"], "source_list": r["source_list"], "listed_name": r["name"],
            "matched_alias": best[2], "category": r["category"], "since": r["since"], "score": best[0]}
