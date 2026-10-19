"""Helpers that compute the Cedar context from snapshots/ledger (pure). CONTRACTS.md v2 §8.1.

The rules themselves are Cedar policies (executor/policy/cedar/). Owner: WS-A.
No I/O, no clock: every time comes from the arguments (ISO strings with Z, dates YYYY-MM-DD, or datetimes).
Integer / Fraction math only, so tools/verify_audit.py replays bit-identically (S12).
"""
from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone
from fractions import Fraction
from typing import Any

from executor.policy.rules import PARAMS

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
DUP_STATUSES = frozenset({"EXECUTED", "PENDING_SIG"})


# ---------------------------------------------------------------- time

def to_datetime(v: Any) -> datetime:
    """datetime | ISO string (Z or offset; date-only = 00:00Z) -> aware UTC datetime."""
    if isinstance(v, datetime):
        dt = v
    elif isinstance(v, date):
        dt = datetime(v.year, v.month, v.day)
    else:
        s = str(v)
        dt = datetime.fromisoformat(s[:-1] + "+00:00" if s.endswith("Z") else s)
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def epoch(v: Any) -> int:
    """Epoch seconds (int) of a datetime / ISO string; None -> 0."""
    if v is None:
        return 0
    return (to_datetime(v) - _EPOCH) // timedelta(seconds=1)


def _day(v: Any) -> date:
    return v if isinstance(v, date) and not isinstance(v, datetime) else date.fromisoformat(str(v)[:10])


# ---------------------------------------------------------------- I-DUP

def normalize_invoice_no(invoice_no: str) -> str:
    """Uppercase, strip leading zeros of numeric runs ("000" -> "0"), strip non-alphanumerics.

    Zeros are stripped per run *before* separators are removed, so "FV-2026-0412" == "FV2026412".
    """
    s = re.sub(r"[0-9]+", lambda m: m.group().lstrip("0") or "0", str(invoice_no).upper())
    return re.sub(r"[^A-Z0-9]", "", s)


def _vendor(p: dict[str, Any]) -> Any:
    return (p.get("invoice") or {}).get("vendor_id", p.get("vendor_id"))


def find_duplicate(invoice: dict[str, Any], proposals: list[dict[str, Any]], *,
                   proposal_id: str | None = None) -> str | None:
    """proposal_id of the first prior EXECUTED/PENDING_SIG proposal of the vendor that duplicates `invoice`, or None."""
    prm = PARAMS["I-DUP"]
    norm = normalize_invoice_no(invoice["invoice_no"])
    amount, day, vendor = int(invoice["amount_minor"]), _day(invoice["issue_date"]), invoice["vendor_id"]
    for p in proposals:
        if p.get("status") not in DUP_STATUSES or (proposal_id is not None and p.get("proposal_id") == proposal_id):
            continue
        if _vendor(p) != vendor:
            continue
        inv = p.get("invoice") or {}
        if normalize_invoice_no(inv.get("invoice_no", "")) == norm:
            return p.get("proposal_id")
        prior = int(inv.get("amount_minor", 0))
        if (abs(amount - prior) * 10000 <= prm["dup_amount_bp"] * prior and inv.get("issue_date")
                and abs((day - _day(inv["issue_date"])).days) <= prm["dup_days"]):
            return p.get("proposal_id")
    return None


def is_duplicate(invoice: dict[str, Any], proposals: list[dict[str, Any]], *, proposal_id: str | None = None) -> bool:
    """I-DUP: same normalized invoice no, or (vendor, amount +-50 bp, issue_date +-3 d), EXECUTED/PENDING_SIG."""
    return find_duplicate(invoice, proposals, proposal_id=proposal_id) is not None


# ---------------------------------------------------------------- I-SPLIT / I-Z

def split_sum(invoice: dict[str, Any], history: list[dict[str, Any]], *, now: Any) -> int:
    """I-SPLIT: executed sum for the vendor with executed_at in (now - 24 h, now] (minor units)."""
    end = to_datetime(now)
    start = end - timedelta(hours=PARAMS["I-SPLIT"]["split_window_hours"])
    return sum(int(r["amount_minor"]) for r in history
               if r.get("vendor_id") == invoice["vendor_id"] and start < to_datetime(r["executed_at"]) <= end)


def _median(xs: list[int] | list[Fraction]) -> Fraction:
    s = sorted(xs)
    n = len(s)
    return Fraction(s[n // 2]) if n % 2 else (Fraction(s[n // 2 - 1]) + Fraction(s[n // 2])) / 2


def z_hit(invoice: dict[str, Any], history: list[dict[str, Any]]) -> bool:
    """I-Z: robust z = 0.6745 * |x - median| / MAD > 3.5 over the vendor's history (>= 5 amounts; MAD 0 -> False)."""
    xs = [int(r["amount_minor"]) for r in history if r.get("vendor_id", invoice["vendor_id"]) == invoice["vendor_id"]]
    if len(xs) < 5:
        return False
    med = _median(xs)
    mad = _median([abs(x - med) for x in xs])
    if mad == 0:
        return False
    z = Fraction(6745, 10000) * abs(int(invoice["amount_minor"]) - med) / mad
    return z > Fraction(PARAMS["I-Z"]["z_threshold_milli"], 1000)


# ---------------------------------------------------------------- Cedar context

def f_facts(facts: dict[str, Any] | list[dict[str, Any]]) -> list[dict[str, Any]]:
    """F facts only (H facts are ignored entirely, S3). Accepts a FactSet or a fact list."""
    lst = facts["facts"] if isinstance(facts, dict) else facts
    return [f for f in lst if f.get("kind") == "F"]


def _vop(ff: list[dict[str, Any]]) -> str:
    for f in ff:
        if f["id"] == "F-VOP":
            code = (f.get("evidence") or {}).get("code")
            if isinstance(code, str) and code:
                return code
            m = re.match(r"VOP\s+([A-Z]{4})", str(f.get("display_line", "")).upper())
            if m:
                return m.group(1)
    return "NOAP"


def _anom(ff: list[dict[str, Any]]) -> int:
    for f in ff:
        if f["id"] == "F-ANOM":
            score = (f.get("evidence") or {}).get("score")
            if isinstance(score, int) and not isinstance(score, bool):
                return score
    return 0


def cedar_context(subject: dict[str, Any], facts: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """Context for action `pay` per cedar schema: amount_minor, vop, reg_hit, warn_hit, block_hit, warn_count,
    anom, dup, split_sum, z_hit, now (epoch s), attest_count. [F] only."""
    inv = subject["invoice"]
    ff = f_facts(facts)
    warn = [f for f in ff if f["severity"] == "WARN"]
    reg_hit = state["reg_hit"] if state.get("reg_hit") is not None else state.get("payee") is not None
    return {
        "amount_minor": int(inv["amount_minor"]),
        "vop": _vop(ff),
        "reg_hit": bool(reg_hit),
        "warn_hit": bool(warn),
        "block_hit": any(f["severity"] == "BLOCK" for f in ff),
        "warn_count": len(warn),
        "anom": _anom(ff),
        "dup": is_duplicate(inv, state.get("proposals") or [], proposal_id=subject.get("proposal_id")),
        "split_sum": split_sum(inv, state.get("history") or [], now=state["now"]),
        "z_hit": z_hit(inv, state.get("history") or []),
        "now": epoch(state["now"]),
        "attest_count": 0,
    }
