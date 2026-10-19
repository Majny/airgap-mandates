"""W1 witness: C2SP tlog-witness add-checkpoint, timestamped Ed25519 cosignature (type 0x04).

Refuses forks (409 stale / 422 bad proof), 403 bad signature, 404 unknown origin; size check + persistence in one
conditional write on witness_state. W1 never writes the audit log (S7): the checkpointer/relay records refusals.
Trusted log keys are pinned via AIRGAP_W1_LOG_VKEY. CONTRACTS.md v2 §7.3, §9. Owner: WS-B.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
from typing import Any

from executor.audit import checkpoint as cp
from executor.audit import kms, merkle

TEXT = "text/plain; charset=utf-8"
SIZE = "text/x.tlog.size"
MAX_PROOF_LINES = 63
LOG_IDS = ("audit", "attest")


class _Reject(Exception):
    def __init__(self, status: int, message: str, content_type: str = TEXT) -> None:
        super().__init__(message)
        self.status, self.message, self.content_type = status, message, content_type


def trusted_logs(settings: Any, env: dict[str, str] | None = None) -> dict[str, list[str]]:
    """{origin: [log vkey]} this witness accepts. AIRGAP_W1_LOG_VKEY = comma-separated pinned log vkeys (origin = key
    name). Unset off AWS (dev/CI): derived from the local log key; unset on AWS: trust nothing (every origin 404)."""
    pinned = (os.environ if env is None else env).get("AIRGAP_W1_LOG_VKEY", "")
    out: dict[str, list[str]] = {}
    if pinned.strip():
        for vk in (v.strip() for v in pinned.split(",") if v.strip()):
            out.setdefault(cp.parse_vkey(vk)["name"], []).append(vk)
        return out
    if settings.backend == "aws":
        return out
    pub = kms.public_key(settings=settings, key="log")
    for log_id in LOG_IDS:
        o = cp.origin(log_id, settings)
        out[o] = [cp.verifier_key(o, pub)]
    return out


def _parse_request(body: bytes) -> tuple[int, list[bytes], str]:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _Reject(400, "request is not UTF-8") from exc
    if "\n\n" not in text:
        raise _Reject(400, "missing empty line before checkpoint")
    head, note = text.split("\n\n", 1)
    lines = head.split("\n")
    old_line, proof_lines = lines[0], lines[1:]
    old_s = old_line[4:] if old_line.startswith("old ") else ""
    if not re.fullmatch(r"0|[1-9][0-9]*", old_s):
        raise _Reject(400, "bad old size line")
    if len(proof_lines) > MAX_PROOF_LINES:
        raise _Reject(400, "too many consistency proof lines")
    proof = []
    for p in proof_lines:
        try:
            h = cp._unb64(p)  # canonical base64 only (C2SP)
        except (cp.NoteError, ValueError) as exc:
            raise _Reject(400, "bad consistency proof line") from exc
        if len(h) != 32:
            raise _Reject(400, "bad consistency proof hash length")
        proof.append(h)
    return int(old_s), proof, note


def _check(body: bytes, *, store: Any, settings: Any, ctx: dict[str, Any]) -> tuple[int, str, bytes]:
    old_size, proof, note = _parse_request(body)
    ctx["old_size"] = old_size
    try:
        parsed = cp.parse_note(note)
    except cp.NoteError as exc:
        raise _Reject(400, f"malformed checkpoint: {exc}") from exc
    ctx["size"] = parsed["size"]
    vkeys = trusted_logs(settings).get(parsed["origin"])
    if vkeys is None:
        raise _Reject(404, "unknown origin")
    ctx["origin"] = parsed["origin"]
    try:
        cp.verify_note(note, vkeys)
    except cp.NoteError as exc:
        raise _Reject(403, str(exc)) from exc
    size, new_root = parsed["size"], bytes.fromhex(parsed["root_hash"])
    if old_size > size:
        raise _Reject(400, "old size is larger than checkpoint size")

    state = store.get("witness_state", {"origin": parsed["origin"]})
    stored_size = int(state["size"]) if state else 0
    if old_size != stored_size:
        raise _Reject(409, f"{stored_size}\n", SIZE)
    if size == 0 and new_root != hashlib.sha256(b"").digest():
        raise _Reject(422, "size 0 checkpoint must have the empty-tree root")
    if old_size == 0:
        if proof:
            raise _Reject(422, "consistency proof must be empty for old size 0")
    elif not merkle.verify_consistency(old_size, size, bytes.fromhex(state["root_hash"]), new_root, proof):
        raise _Reject(422, "consistency proof does not verify")

    cosig = cp.cosign(parsed["body"], name=cp.witness_name(settings), settings=settings)
    item = {"origin": parsed["origin"], "size": size, "root_hash": new_root.hex(), "note": note + cosig}
    if state is None:
        won = store.put_if_absent("witness_state", item, "origin")
    else:
        won = store.update_if("witness_state", {"origin": parsed["origin"]},
                              {k: v for k, v in item.items() if k != "origin"}, {"size": stored_size})
    if not won:  # lost the race against a concurrent add-checkpoint: report the size that won
        current = store.get("witness_state", {"origin": parsed["origin"]})
        raise _Reject(409, f"{int(current['size']) if current else 0}\n", SIZE)
    return 200, TEXT, cosig.encode()


def add_checkpoint(body: bytes, *, store: Any, settings: Any) -> tuple[int, str, bytes]:
    """Return (http_status, content_type, body): 200 text/plain cosignature line(s) | 400 | 403 | 404 |
    409 text/x.tlog.size | 422. Refusals are returned only; the caller logs them (W1 has no audit-log access)."""
    try:
        return _check(body, store=store, settings=settings, ctx={})
    except _Reject as r:
        return r.status, r.content_type, r.message.encode() if r.message.endswith("\n") else (r.message + "\n").encode()
    except (ValueError, UnicodeError) as exc:  # anything unparseable that slipped past the checks above
        return 400, TEXT, f"malformed request: {type(exc).__name__}\n".encode()


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """W1 λ entry point (own role, own KMS key, own table)."""
    from executor.config import Settings
    from executor.store import get_store

    settings = Settings.from_env()
    raw = event.get("body") or ""
    body = base64.b64decode(raw) if event.get("isBase64Encoded") else raw.encode("utf-8")
    status, ctype, out = add_checkpoint(body, store=get_store(settings), settings=settings)
    return {"statusCode": status, "headers": {"Content-Type": ctype}, "body": out.decode("utf-8")}
