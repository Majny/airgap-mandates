"""SIMULATED malware on the clerk's PC for the demo/test only (attacker level H4, docs/ARCHITECTURE.md §11).

This module is NOT real malware. It is a stand-in that models a Bybit-style signing swap (Feb 2025: the signers' screen
showed a normal transaction while their hardware wallets were asked to sign a different one). While the bank console
still shows the legitimate payment, an "armed" implant rewrites the IBAN lines of the text that is actually sent to the
Trezor, so the physical device shows — and would sign — the attacker's account instead.

The whole point of the demo is that this fails. The human reads the wrong IBAN on the device; even if they confirm, the
host POSTs the tampered text as `displayed_text`, the executor re-renders its own text and answers 403 render_mismatch
(the nonce is never consumed; nothing is paid). Either way the attacker receives 0.00 CZK.

State lives under AIRGAP_IMPLANT_DIR (default <repo>/.local/implant, which is git-ignored via .local/). The implant is
ONE-SHOT: after a single armed sign attempt the host consumes it — it records the outcome in last.json and removes
clerk-pc.json. Owner: WS-F.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from executor import render as R

# The attacker IBAN money-to-attacker is measured against (attacker/attacks.py). Imported once, never duplicated with a
# different value; the fallback only covers an import-order edge case.
try:
    from attacker.attacks import FRAUD_IBAN as ATTACKER_IBAN
except Exception:  # noqa: BLE001 - keep host importable even if the attacker package is unavailable
    ATTACKER_IBAN = "LT483999000000001234"

_REPO = Path(__file__).resolve().parents[1]
_ARMED = "clerk-pc.json"
_LAST = "last.json"
OUTCOMES = ("rejected_on_device", "refused_by_executor", "paid", "timeout", "error")


def _dir() -> Path:
    return Path(os.environ.get("AIRGAP_IMPLANT_DIR") or (_REPO / ".local" / "implant"))


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _read(name: str) -> dict | None:
    try:
        return json.loads((_dir() / name).read_text())
    except (OSError, ValueError):
        return None


def _write(name: str, payload: dict) -> None:
    d = _dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps(payload, sort_keys=True, indent=1))


def _remove(name: str) -> None:
    try:
        (_dir() / name).unlink()
    except OSError:
        pass


def arm(iban: str | None = None) -> dict:
    """Drop the implant on the clerk's PC (simulated C2): the next armed PAY signature is swapped to `iban`."""
    rec = {"armed": True, "iban": "".join(str(iban or ATTACKER_IBAN).split()).upper(), "armed_at": _iso(),
           "by": "attacker console"}
    _remove(_LAST)  # clear any prior verdict so a fresh run shows "waiting", not last time's outcome
    _write(_ARMED, rec)
    return rec


def disarm() -> None:
    """Remove the implant (no outcome recorded) and clear any stale outcome."""
    _remove(_ARMED)
    _remove(_LAST)


def armed() -> dict | None:
    """The armed state, or None. The bank console must NEVER surface this (the malware is invisible to the operator)."""
    rec = _read(_ARMED)
    return rec if rec and rec.get("armed") else None


def _is_group_line(s: str) -> bool:
    """A line that looks like IBAN groups: space-separated chunks of 2-4 [0-9A-Z], at least one full group of 4."""
    parts = s.split(" ")
    return bool(parts) and all(2 <= len(p) <= 4 and all(c.isdigit() or ("A" <= c <= "Z") for c in p) for p in parts) \
        and any(len(p) == 4 for p in parts)


def _valid_iban(compact: str) -> bool:
    try:
        R.format_iban(compact)  # normalises + validates shape (CC + 2 check digits, length, alnum)
        return True
    except R.RenderError:
        return False


def tamper(text: str, iban: str | None = None) -> str:
    """Rewrite ONLY a PAY device text: replace its IBAN lines with `iban` in the same 4-char grouping/line layout,
    leaving every other line unchanged. Non-PAY texts are returned untouched. Output stays printable ASCII + LF."""
    iban = "".join(str(iban or ATTACKER_IBAN).split()).upper()
    lines = text.split("\n")
    toks = lines[0].split() if lines else []
    if not (toks and toks[0].startswith(f"{R.PROTOCOL_TAG}/") and "PAY" in toks):
        return text  # only the PAY template carries a payee IBAN to swap
    i = 0
    while i < len(lines):
        if not _is_group_line(lines[i]):
            i += 1
            continue
        j = i
        while j < len(lines) and _is_group_line(lines[j]):
            j += 1
        # the IBAN is the longest contiguous subspan of this run whose groups form a valid IBAN
        for a in range(i, j):
            for b in range(j, a, -1):
                if _valid_iban("".join(lines[a:b]).replace(" ", "")):
                    new = R.format_iban_lines("", iban, R.DEFAULT_WIDTH)
                    return "\n".join(lines[:a] + new + lines[b:])
        i = j
    return text  # no IBAN line found (nothing to swap)


def record(outcome: str, *, error: str | None = None, proposal_id: str | None = None,
           device_text_iban: str | None = None) -> dict:
    """Write last.json and remove the armed state (one-shot): the implant fires once, then disarms itself."""
    rec = {"outcome": outcome if outcome in OUTCOMES else "error", "error": error, "proposal_id": proposal_id,
           "device_text_iban": device_text_iban, "at": _iso()}
    _write(_LAST, rec)
    _remove(_ARMED)
    return rec


def last() -> dict | None:
    """The outcome of the last armed sign attempt, or None."""
    return _read(_LAST)
