"""Load the Mostly Right dataset into data/mostlyright/snapshot.sqlite (+ snapshot.sha256). CONTRACTS.md v2 §2.1.

Source: s3://ai-hackathon-datasets-422928733782/MostlyRIght/ (capital I is the real path): CNB + ESMA licence
registers, SEPA Instant and VoP participant lists, EU sanctions (entities), regulator warning lists.
Feeds F-PSP, F-WARNLIST, F-SANCTION and the website_domain leg of F-DOMAIN. Owner: WS-D.

The raw CSV is not clean UTF-8: most records carry the low byte of each code point (Latin-1 for U+0000..U+00FF,
control characters / stray quotes / line breaks for letters such as c-caron), a few are UTF-8. Parsing is done on
the Latin-1 view of the bytes (lossless), records split by a stray line break are re-joined, and each record is then
decoded on its own: UTF-8, else cp1250 when its 0x80-0x9F bytes are cp1250 letters, else Latin-1. The text is cut
into records at every line that starts with a record id and a record_type before csv parsing, so a stray quote never
swallows the records after it; a one-line record whose other_names holds stray quotes/commas is re-anchored on its
clean head and tail fields. Records that still do not line up are kept with record_ok = 0; sanction / warning rows
among them stay matchable by name and national id (fail closed), and the facts report N/A, never CLEAR, while the
snapshot holds a row that cannot be classified at all.

The build is deterministic (sorted rows, fixed schema, no timestamps, VACUUM, the writer-version header field pinned):
the same CSV gives the same file sha256, which is the `prov` of every MostlyRight-derived fact.

CLI: python -m tools.load_mostlyright load [--src PATH|s3://...] [--out DIR]
     python -m tools.load_mostlyright stats [--out DIR]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from executor.facts import mostlyright as mr

LOADER_VERSION = "mostlyright-loader/5"
DEFAULT_S3 = "s3://ai-hackathon-datasets-422928733782/MostlyRIght/"
ENV_SRC = "AIRGAP_MOSTLYRIGHT_CSV"
ENV_PROFILE = "AIRGAP_MOSTLYRIGHT_PROFILE"  # falls back to AWS_PROFILE

COLUMNS = (
    "record_id", "record_type", "source_list", "authority", "authority_country", "name", "other_names", "country",
    "national_id", "lei", "bic", "eu_reference_number", "un_id", "website", "website_domain", "email_domain",
    "address", "city", "category", "detail", "value_kind", "passported_to", "since", "until", "in_sct_inst",
    "sct_inst_ready_since", "sct_inst_leaving_date", "in_vop", "vop_status", "vop_role", "vop_ready_since",
    "vop_leaving_date", "name_count", "regulation_url",
)
NCOL = len(COLUMNS)
RECORD_TYPES = frozenset({"licence", "warning", "sanction", "payment_scheme"})
_I_OTHER = COLUMNS.index("other_names")
_ID_RE = re.compile(r"^[0-9a-f]{32}$")
# Start of a record: a line that begins with a record id and a known record_type. Records are split here BEFORE csv
# parsing, so a stray quote (the low byte of a lost Cyrillic letter) can never swallow the records that follow it.
_RECORD_START_RE = re.compile(r"(?m)^(?=[0-9a-f]{32},(?:licence|warning|sanction|payment_scheme),)")
_N_HEAD = COLUMNS.index("other_names")  # fields before other_names (clean in every malformed record seen)
_N_TAIL = NCOL - _N_HEAD - 1  # fields after it
_DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})?$")
_ASOF_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")
_HDR_VERSION_OFFSET = 96
_HDR_VERSION = 3_000_000

_SCHEMA = (
    "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE records (seq INTEGER PRIMARY KEY, record_ok INTEGER NOT NULL, repaired INTEGER NOT NULL, "
    "src_encoding TEXT NOT NULL, field_count INTEGER NOT NULL, "
    + ", ".join(f"{c} TEXT NOT NULL" for c in COLUMNS)
    + ", extra TEXT NOT NULL, bic8 TEXT NOT NULL, nid TEXT NOT NULL, name_norm TEXT NOT NULL)",
    "CREATE TABLE names (seq INTEGER NOT NULL, name TEXT NOT NULL, core TEXT NOT NULL, first_tok TEXT NOT NULL, "
    "is_primary INTEGER NOT NULL)",
    "CREATE TABLE domains (seq INTEGER NOT NULL, kind TEXT NOT NULL, domain TEXT NOT NULL)",
)
_INDEXES = (
    "CREATE INDEX ix_records_bic8 ON records (bic8)",
    "CREATE INDEX ix_records_national_id ON records (national_id)",
    "CREATE INDEX ix_records_nid ON records (nid)",
    "CREATE INDEX ix_records_name_norm ON records (name_norm)",
    "CREATE INDEX ix_records_website_domain ON records (website_domain)",
    "CREATE INDEX ix_records_email_domain ON records (email_domain)",
    "CREATE INDEX ix_records_type ON records (record_type, source_list)",
    "CREATE INDEX ix_names_seq ON names (seq)",
    "CREATE INDEX ix_names_core ON names (core)",
    "CREATE INDEX ix_names_first_tok ON names (first_tok)",
    "CREATE INDEX ix_domains_seq ON domains (seq)",
    "CREATE INDEX ix_domains_domain ON domains (domain)",
)


# --- source ---------------------------------------------------------------------------------------------------------

def _s3_bytes(uri: str) -> tuple[bytes, str]:
    import boto3

    profile = os.environ.get(ENV_PROFILE) or os.environ.get("AWS_PROFILE")
    s3 = boto3.Session(profile_name=profile).client("s3")
    bucket, _, key = uri[len("s3://"):].partition("/")
    if not key or key.endswith("/"):
        keys: list[str] = []
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=key):
            keys += [o["Key"] for o in page.get("Contents", []) if o["Key"].lower().endswith(".csv")]
        if not keys:
            raise FileNotFoundError(f"no .csv under {uri}")
        key = sorted(keys)[-1]
    return s3.get_object(Bucket=bucket, Key=key)["Body"].read(), key.rsplit("/", 1)[-1]


# Team copy of the dataset outside the repo (the raw CSV is never committed).
SHARED_DIR = Path.home() / "Desktop" / "MyProjects" / "mostlyright-dataset"


def resolve_src(src: str | None, out_dir: str | os.PathLike[str]) -> str:
    """--src, else $AIRGAP_MOSTLYRIGHT_CSV, else the newest *.csv in out_dir, then in the team copy, else S3."""
    if src:
        return str(src)
    if os.environ.get(ENV_SRC):
        return os.environ[ENV_SRC]
    for d in (Path(out_dir), SHARED_DIR):
        local = sorted(d.glob("*.csv"))
        if local:
            return str(local[-1])
    return DEFAULT_S3


def read_source(src: str) -> tuple[bytes, str]:
    """(raw bytes, source file name)."""
    if src.startswith("s3://"):
        return _s3_bytes(src)
    p = Path(src)
    return p.read_bytes(), p.name


# --- parsing ------------------------------------------------------------------------------------------------------

def _cp1250_letter_bytes() -> frozenset[int]:
    out = set()
    for b in range(0x80, 0xA0):
        try:
            if bytes([b]).decode("cp1250").isalpha():
                out.add(b)
        except UnicodeDecodeError:
            pass
    return frozenset(out)


_CP1250_LETTERS = _cp1250_letter_bytes()


def decode_record(fields: list[str]) -> tuple[list[str], str]:
    """Fields parsed from the Latin-1 view of the bytes -> (decoded fields, encoding used) for one record."""
    raw = [f.encode("latin-1") for f in fields]
    blob = b"".join(raw)
    if blob.isascii():
        return list(fields), "ascii"
    try:
        blob.decode("utf-8")
        return [b.decode("utf-8") for b in raw], "utf-8"
    except UnicodeDecodeError:
        pass
    c1 = {b for b in blob if 0x80 <= b < 0xA0}
    truncated = any(b < 0x20 and b not in (0x09, 0x0A, 0x0D) for b in blob)  # low-byte residue of a lost letter
    if c1 and c1 <= _CP1250_LETTERS and not truncated:
        return [b.decode("cp1250") for b in raw], "cp1250"
    return list(fields), "latin-1"


def _is_head(row: list[str]) -> bool:
    return bool(row) and bool(_ID_RE.match(row[0]))


def _sane(row: list[str]) -> bool:
    d = dict(zip(COLUMNS, row))
    return (d["record_type"] in RECORD_TYPES and bool(_DATE_RE.match(d["since"])) and bool(_DATE_RE.match(d["until"]))
            and (d["regulation_url"] == "" or d["regulation_url"].startswith("http")))


def _realign(row: list[str]) -> list[str] | None:
    """Too many fields: the surplus commas came from a stray quote inside other_names; re-join them there."""
    k = len(row) - NCOL
    fixed = row[:_I_OTHER] + [",".join(row[_I_OTHER:_I_OTHER + k + 1])] + row[_I_OTHER + k + 1:]
    return fixed if _sane(fixed) else None


def repair_rows(rows: list[list[str]]) -> list[tuple[list[str], int, int]]:
    """[(fields, repaired, original field count)]. A record split by stray line breaks (head + continuation
    fragments, the broken field re-joined) is merged; a record whose other_names picked up extra commas (stray
    quote) is re-aligned on its tail. Only results with 34 sane fields are accepted; anything else is kept as is."""
    out: list[tuple[list[str], int, int]] = []
    i = 0
    while i < len(rows):
        row, fixed, j = rows[i], None, i + 1
        if _is_head(row) and len(row) < NCOL:
            merged = list(row)
            while len(merged) < NCOL and j < len(rows) and not _is_head(rows[j]):
                nxt = rows[j]
                merged = merged[:-1] + [merged[-1] + "\n" + (nxt[0] if nxt else "")] + nxt[1:]
                j += 1
            fixed = merged if len(merged) == NCOL and _sane(merged) else None
            if fixed is None and len(merged) > NCOL:
                fixed = _realign(merged)
        elif _is_head(row) and len(row) > NCOL:
            fixed = _realign(row)
        if fixed is not None:
            out.append((fixed, 1, len(row)))
            i = j
        else:
            out.append((row, 0, len(row)))
            i += 1
    return out


def _take(s: str, n: int) -> tuple[list[str], int]:
    """Up to n CSV fields from the start of s (quotes as in the csv module, lenient: text after a closing quote is
    kept), and the index where the rest begins."""
    out: list[str] = []
    i = 0
    while len(out) < n and i <= len(s):
        if i < len(s) and s[i] == '"':
            j, buf = i + 1, []
            while j < len(s):
                if s[j] == '"':
                    if s[j + 1:j + 2] == '"':
                        buf.append('"')
                        j += 2
                        continue
                    j += 1
                    break
                buf.append(s[j])
                j += 1
            k = s.find(",", j)
            k = len(s) if k < 0 else k
            out.append("".join(buf) + s[j:k])
        else:
            k = s.find(",", i)
            k = len(s) if k < 0 else k
            out.append(s[i:k])
        i = k + 1
    return out, i


def _anchor(line: str) -> list[str] | None:
    """A one-line record whose other_names holds stray quotes / commas (lost letters): the fields before
    other_names are read from the left, the fields after it from the right (quoting is symmetric), and whatever lies
    between is other_names. Accepted only when the result has 34 sane fields."""
    head, start = _take(line, _N_HEAD)
    tail_rev, k = _take(line[::-1], _N_TAIL)
    end = len(line) - k
    if len(head) != _N_HEAD or len(tail_rev) != _N_TAIL or end < start - 1:
        return None
    other = line[start:max(start, end)]
    if len(other) >= 2 and other[0] == other[-1] == '"':
        other = other[1:-1]
    fields = head + [other] + [f[::-1] for f in reversed(tail_rev)]
    return fields if len(fields) == NCOL and _is_head(fields) and _sane(fields) else None


def split_records(body: str) -> list[str]:
    """CSV body (no header) -> one text chunk per record (a record plus any stray-line-break continuation lines)."""
    starts = [m.start() for m in _RECORD_START_RE.finditer(body)]
    bounds = ([0] if not starts or starts[0] != 0 else []) + starts + [len(body)]
    return [body[a:b] for a, b in zip(bounds, bounds[1:]) if body[a:b].strip()]


def _parse_chunk(chunk: str) -> list[tuple[list[str], int, int]]:
    rows = [r for r in csv.reader(io.StringIO(chunk, newline="")) if any(r)]
    out = repair_rows(rows)
    if len(out) == 1 and len(out[0][0]) == NCOL and _sane(out[0][0]):
        return out
    line = chunk.rstrip("\r\n")
    if _RECORD_START_RE.match(chunk) and "\n" not in line:
        fixed = _anchor(line)
        if fixed is not None:
            return [(fixed, 1, len(rows[0]) if rows else 0)]
    return out


def parse_csv(raw: bytes) -> list[dict[str, Any]]:
    """Raw CSV bytes -> record dicts (34 columns + record_ok, repaired, src_encoding, field_count, extra)."""
    text = raw.decode("latin-1")
    if text.startswith("\xef\xbb\xbf"):
        text = text[3:]
    header_line, _, body = text.partition("\n")
    header = next(csv.reader(io.StringIO(header_line, newline="")), None)
    if not header or [c.strip() for c in header] != list(COLUMNS):
        raise ValueError(f"unexpected header: {header}")
    parsed = [rec for chunk in split_records(body) for rec in _parse_chunk(chunk)]
    out = []
    for fields, repaired, count in parsed:
        dec, enc = decode_record(fields)
        vals = (dec + [""] * NCOL)[:NCOL]
        rec: dict[str, Any] = dict(zip(COLUMNS, vals))
        rec.update(record_ok=int(len(dec) == NCOL and rec["record_type"] in RECORD_TYPES), repaired=repaired,
                   src_encoding=enc, field_count=count, extra="\x1f".join(dec[NCOL:]))
        out.append(rec)
    return out


def _sort_key(rec: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(rec[c] for c in COLUMNS) + (rec["extra"], rec["record_ok"], rec["repaired"], rec["src_encoding"],
                                             rec["field_count"])


# --- build --------------------------------------------------------------------------------------------------------

def build_sqlite(records: list[dict[str, Any]], dest: Path, meta: dict[str, str]) -> None:
    if dest.exists():
        dest.unlink()
    conn = sqlite3.connect(dest)
    try:
        conn.execute("PRAGMA page_size = 4096")
        conn.execute("PRAGMA journal_mode = DELETE")
        for stmt in _SCHEMA:
            conn.execute(stmt)
        cols = ("seq", "record_ok", "repaired", "src_encoding", "field_count", *COLUMNS, "extra", "bic8", "nid",
                "name_norm")
        rec_sql = f"INSERT INTO records ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})"
        rec_rows, name_rows, dom_rows = [], [], []
        for seq, rec in enumerate(sorted(records, key=_sort_key), start=1):
            bic = rec["bic"].strip().upper()
            extra = {"seq": seq, "bic8": bic[:8] if len(bic) >= 8 else "", "nid": mr.norm_national_id(rec["national_id"]),
                     "name_norm": mr.norm_text(rec["name"])}
            rec_rows.append(tuple({**rec, **extra}[c] for c in cols))
            for k, n in enumerate(mr.split_names(rec["name"], rec["other_names"])):
                core = mr.core_name(n)
                if core:
                    name_rows.append((seq, n, core, mr.first_token(core), int(k == 0 and n == rec["name"].strip())))
            for kind, col in (("website", "website_domain"), ("email", "email_domain"), ("website", "website")):
                for d in mr.split_domains(rec[col]):
                    dom_rows.append((seq, kind, d))
        conn.executemany(rec_sql, rec_rows)
        conn.executemany("INSERT INTO names VALUES (?, ?, ?, ?, ?)", sorted(set(name_rows)))
        conn.executemany("INSERT INTO domains VALUES (?, ?, ?)", sorted(set(dom_rows)))
        conn.executemany("INSERT INTO meta VALUES (?, ?)", sorted(meta.items()))
        for stmt in _INDEXES:
            conn.execute(stmt)
        conn.commit()
        conn.execute("VACUUM")
    finally:
        conn.close()


def pin_header(path: Path) -> None:
    """Overwrite the informational 'SQLITE_VERSION_NUMBER of the last writer' header field (offset 96) with a constant,
    so the file sha256 (the facts' prov) does not depend on the sqlite library that built it. SQLite never reads it."""
    with open(path, "r+b") as f:
        f.seek(_HDR_VERSION_OFFSET)
        f.write(_HDR_VERSION.to_bytes(4, "big"))


def counts(records: list[dict[str, Any]]) -> dict[str, Any]:
    ok = [r for r in records if r["record_ok"]]
    return {
        "rows_total": len(records),
        "rows_ok": len(ok),
        "rows_not_ok": len(records) - len(ok),
        "rows_repaired": sum(r["repaired"] for r in records),
        "by_record_type": dict(sorted(Counter(r["record_type"] for r in ok).items())),
        "by_source_list": dict(sorted(Counter(f"{r['record_type']}/{r['source_list']}" for r in ok).items())),
        "by_encoding": dict(sorted(Counter(r["src_encoding"] for r in records).items())),
    }


def load(src: str | None = None, out_dir: str = "data/mostlyright") -> str:
    """Build the sqlite snapshot; return its sha256 hex (the facts' `prov`)."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    raw, src_name = read_source(resolve_src(src, out))
    records = parse_csv(raw)
    m = _ASOF_RE.search(src_name)
    meta = {
        "loader_version": LOADER_VERSION,
        "raw_csv_sha256": hashlib.sha256(raw).hexdigest(),
        "source_name": src_name,
        "as_of": m.group(1) if m else "",
        "counts": json.dumps(counts(records), sort_keys=True, separators=(",", ":")),
    }
    tmp = out / "snapshot.sqlite.tmp"
    build_sqlite(records, tmp, meta)
    pin_header(tmp)
    sha = hashlib.sha256(tmp.read_bytes()).hexdigest()
    os.replace(tmp, out / "snapshot.sqlite")
    (out / "snapshot.sha256").write_text(f"{sha}  snapshot.sqlite\n", encoding="ascii")
    return sha


class SnapshotMismatch(RuntimeError):
    """The rebuilt snapshot does not match the committed snapshot.sha256 (dataset or loader changed)."""


def ensure(src: str | None = None, out_dir: str = "data/mostlyright") -> str:
    """Make sure snapshot.sqlite exists and matches the committed snapshot.sha256 (the facts' prov).

    Without the snapshot the MostlyRight facts fail safe to WARN, so every payment steps up: build it instead.
    A rebuild that yields a different SHA leaves the committed sidecar untouched and raises SnapshotMismatch."""
    out = Path(out_dir)
    side = out / "snapshot.sha256"
    expected = side.read_text(encoding="ascii").split()[0] if side.exists() else None
    db = out / "snapshot.sqlite"
    if db.exists() and expected and hashlib.sha256(db.read_bytes()).hexdigest() == expected:
        return expected
    sha = load(src, out_dir)
    if expected and sha != expected:
        side.write_text(f"{expected}  snapshot.sqlite\n", encoding="ascii")
        raise SnapshotMismatch(f"rebuilt snapshot {sha} != committed {expected}; update snapshot.sha256 on purpose")
    return sha


def stats(out_dir: str = "data/mostlyright") -> dict[str, Any]:
    path = Path(out_dir) / "snapshot.sqlite"
    meta = mr.meta(path)
    return {"snapshot": str(path), "sha256": mr.snapshot_sha(path), "sidecar_sha256": mr.sidecar_sha(path),
            **{k: v for k, v in meta.items() if k != "counts"}, "counts": json.loads(meta.get("counts", "{}"))}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m tools.load_mostlyright", description=__doc__.split("\n", 1)[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_load = sub.add_parser("load", help="build snapshot.sqlite + snapshot.sha256")
    p_load.add_argument("--src", default=None, help=f"CSV path or s3:// URI (default ${ENV_SRC}, local CSV, S3)")
    p_load.add_argument("--out", default="data/mostlyright")
    p_ens = sub.add_parser("ensure", help="build the snapshot only if missing or stale; check the committed sha")
    p_ens.add_argument("--src", default=None)
    p_ens.add_argument("--out", default="data/mostlyright")
    p_stats = sub.add_parser("stats", help="print snapshot meta and row counts")
    p_stats.add_argument("--out", default="data/mostlyright")
    args = ap.parse_args(argv)
    if args.cmd == "ensure":
        try:
            print(ensure(args.src, args.out))
        except (FileNotFoundError, SnapshotMismatch) as e:
            print(f"MostlyRight snapshot: {e}. Set ${ENV_SRC} to the CSV path or AWS_PROFILE=hackathon for S3.",
                  file=sys.stderr)
            return 1
        return 0
    if args.cmd == "load":
        sha = load(args.src, args.out)
        print(sha)
        return 0
    json.dump(stats(args.out), sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
