"""C2SP tlog-checkpoint in a signed-note (Ed25519), cosigned by W1/W2. CONTRACTS.md v2 §7.3. Owner: WS-B."""
from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import os
import re
import struct
import time
from pathlib import Path
from typing import Any

from executor.audit import kms, log, merkle

SIG_ED25519 = 0x01
SIG_COSIGNATURE = 0x04
DASH = "—"
MAX_SIGNATURES = 16
REFUSAL_STATUSES = (403, 404, 409, 422)  # witness_refusal.status enum (CONTRACTS §7.2)


class NoteError(ValueError):
    """Malformed note, or a signature from a known key that does not verify."""


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:  # ValueError: non-ASCII input
        raise NoteError(f"bad base64: {text!r}") from exc
    if _b64(raw) != text:
        raise NoteError(f"non-canonical base64: {text!r}")
    return raw


def checkpoint_body(origin: str, size: int, root_hash_hex: str, *, policy_hash: str, code_sha256: str) -> str:
    """'<origin>\\n<size>\\n<b64 root>\\npolicy sha256:<hex>\\ncode sha256:<hex> pcr0 -\\n'."""
    return (f"{origin}\n{size}\n{_b64(bytes.fromhex(root_hash_hex))}\n"
            f"policy sha256:{policy_hash}\ncode sha256:{code_sha256} pcr0 -\n")


def key_id(name: str, pubkey: bytes, sig_type: int = SIG_ED25519) -> bytes:
    """SHA-256(name || 0x0A || sig_type || pubkey)[:4] (0x01 Ed25519 note sig, 0x04 timestamped cosignature)."""
    return hashlib.sha256(name.encode() + b"\n" + bytes([sig_type]) + pubkey).digest()[:4]


def verifier_key(name: str, pubkey: bytes, sig_type: int = SIG_ED25519) -> str:
    """Go sumdb/note verifier key 'name+<keyid hex>+<b64(type||pubkey)>'; type 0x04 for cosigners (torchwood)."""
    return f"{name}+{key_id(name, pubkey, sig_type).hex()}+{_b64(bytes([sig_type]) + pubkey)}"


def parse_vkey(vkey: str) -> dict[str, Any]:
    """{name, key_id (4 bytes), sig_type, pubkey}; checks the key id."""
    try:
        name, kid_hex, b64 = vkey.split("+", 2)
    except ValueError as exc:
        raise NoteError(f"bad vkey: {vkey!r}") from exc
    raw = _unb64(b64)
    if len(raw) != 33 or raw[0] not in (SIG_ED25519, SIG_COSIGNATURE):
        raise NoteError(f"unsupported vkey type: {vkey!r}")
    kid = key_id(name, raw[1:], raw[0])
    if kid.hex() != kid_hex:
        raise NoteError(f"vkey key id mismatch: {vkey!r}")
    return {"name": name, "key_id": kid, "sig_type": raw[0], "pubkey": raw[1:]}


def cosignature_message(body: str, timestamp: int) -> bytes:
    """tlog-cosignature Ed25519 signed message: 'cosignature/v1\\ntime <t>\\n' + checkpoint body (incl. extensions)."""
    return f"cosignature/v1\ntime {timestamp}\n".encode() + body.encode()


def signature_line(name: str, sig_bytes: bytes) -> str:
    return f"{DASH} {name} {_b64(sig_bytes)}\n"


def sign_note(body: str, *, name: str, settings: Any, key: str = "log") -> str:
    """Body + blank line + '— <name> <b64(keyid||sig)>' (KMS Ed25519 or local fallback)."""
    sig = kms.sign_ed25519(body.encode(), settings=settings, key=key)
    kid = key_id(name, kms.public_key(settings=settings, key=key), SIG_ED25519)
    return body + "\n" + signature_line(name, kid + sig)


def cosign(body: str, *, name: str, settings: Any, key: str = "w1", timestamp: int | None = None) -> str:
    """One timestamped Ed25519 cosignature line (type 0x04) for a checkpoint body."""
    t = int(time.time()) if timestamp is None else timestamp
    sig = kms.sign_ed25519(cosignature_message(body, t), settings=settings, key=key)
    kid = key_id(name, kms.public_key(settings=settings, key=key), SIG_COSIGNATURE)
    return signature_line(name, kid + struct.pack(">Q", t) + sig)


def parse_note(note: str) -> dict[str, Any]:
    """{origin, size, root_hash, extensions[], signatures[{name, key_id, sig, timestamp?}]}."""
    if "\n\n" not in note or not note.endswith("\n"):
        raise NoteError("note must be body + blank line + signature lines, LF-terminated")
    if any(ord(c) < 0x20 and c != "\n" for c in note):
        raise NoteError("control character in note")
    split = note.rindex("\n\n")  # signed-note: signatures follow the LAST blank line
    body, sig_text = note[:split + 1], note[split + 2:]
    lines = body[:-1].split("\n")
    if len(lines) < 3:
        raise NoteError("checkpoint body needs origin, size and root hash")
    origin, size_s, root_b64, *extensions = lines
    if not origin or not re.fullmatch(r"0|[1-9][0-9]*", size_s):
        raise NoteError(f"bad checkpoint header: {origin!r} {size_s!r}")
    root_hash = _unb64(root_b64)
    if len(root_hash) != 32:
        raise NoteError("root hash must be 32 bytes")
    if any(not e for e in extensions):
        raise NoteError("empty extension line")
    signatures = []
    for line in sig_text[:-1].split("\n") if sig_text else []:
        parts = line.split(" ")
        if len(parts) != 3 or parts[0] != DASH or not parts[1] or "+" in parts[1]:
            raise NoteError(f"bad signature line: {line!r}")
        raw = _unb64(parts[2])
        if len(raw) < 5:
            raise NoteError(f"signature too short: {line!r}")
        if any(x["name"] == parts[1] and x["key_id"] == raw[:4] for x in signatures):
            raise NoteError(f"duplicate signature from {parts[1]}")
        signatures.append({"name": parts[1], "key_id": raw[:4], "sig": raw[4:]})
    if not signatures:
        raise NoteError("note has no signatures")
    if len(signatures) > MAX_SIGNATURES:
        raise NoteError("too many signatures")
    return {"origin": origin, "size": int(size_s), "root_hash": root_hash.hex(), "extensions": extensions,
            "body": body, "signatures": signatures}


def verify_note(note: str, vkeys: list[str]) -> dict[str, Any]:
    """Parse and verify against known vkeys (signed-note rules: unknown keys ignored, a known key that fails rejects
    the whole note). Returns the parsed note plus `verified` = {name: timestamp or None}. Raises NoteError."""
    parsed = parse_note(note)
    known = {}
    for vk in vkeys:
        k = parse_vkey(vk)
        known[(k["name"], k["key_id"])] = k
    verified: dict[str, int | None] = {}
    for s in parsed["signatures"]:
        k = known.get((s["name"], s["key_id"]))
        if k is None:
            continue
        if k["sig_type"] == SIG_COSIGNATURE:
            if len(s["sig"]) != 72:
                raise NoteError(f"bad cosignature length from {s['name']}")
            (t,) = struct.unpack(">Q", s["sig"][:8])
            ok = kms.verify_ed25519(cosignature_message(parsed["body"], t), s["sig"][8:], k["pubkey"])
            s["timestamp"] = t
        else:
            t = None
            ok = len(s["sig"]) == 64 and kms.verify_ed25519(parsed["body"].encode(), s["sig"], k["pubkey"])
        if not ok:
            raise NoteError(f"signature from known key {s['name']} does not verify")
        verified[s["name"]] = t
    if not verified:
        raise NoteError("no signature from a known key")
    parsed["verified"] = verified
    return parsed


def origin(log_id: str, settings: Any) -> str:
    return f"{settings.log_origin}/{log_id}"


def witness_name(settings: Any, witness: str = "w1") -> str:
    return f"{settings.log_origin}/{witness}"


def vkeys(settings: Any) -> dict[str, str]:
    """{log, w1} verifier keys for this deployment (w2 is configured out of band)."""
    return {"log": verifier_key(origin("audit", settings), kms.public_key(settings=settings, key="log")),
            "w1": verifier_key(witness_name(settings), kms.public_key(settings=settings, key="w1"), SIG_COSIGNATURE)}


@functools.lru_cache(maxsize=1)
def code_sha256() -> str:
    """AIRGAP_CODE_SHA256 (Lambda CodeSha256, set at deploy) or, locally, sha256 over the executor/*.py sources."""
    env = os.environ.get("AIRGAP_CODE_SHA256")
    if env:
        return base64.b64decode(env).hex() if len(env) == 44 else env
    h = hashlib.sha256()
    root_dir = Path(__file__).resolve().parents[1]
    for p in sorted(root_dir.rglob("*.py")):
        h.update(str(p.relative_to(root_dir)).encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()


def latest(log_id: str, *, store: Any) -> dict[str, Any] | None:
    """Latest stored checkpoint row {note, root_hash, size, created_at} or None."""
    rows = store.query("checkpoints", log.checkpoint_pk(log_id), reverse=True, limit=1)
    return rows[0] if rows else None


def _submit_w1(request_body: bytes, *, store: Any, settings: Any) -> tuple[int, str, bytes]:
    if settings.witness_url == "inproc":
        from witness import witness

        return witness.add_checkpoint(request_body, store=store, settings=settings)
    import urllib.error
    import urllib.request

    req = urllib.request.Request(settings.witness_url.rstrip("/") + "/add-checkpoint", data=request_body,
                                 method="POST", headers={"Content-Type": "text/plain"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - configured witness URL
            return resp.status, resp.headers.get("Content-Type", ""), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type", ""), exc.read()


def add_cosignature(log_id: str, size: int, body: bytes, *, store: Any, settings: Any,
                    env: dict[str, str] | None = None) -> tuple[int, str, bytes]:
    """Row 22b: append W2 cosignature line(s) to the stored checkpoint note of `size` after verifying each against the
    pinned AIRGAP_W2_VKEY. Returns (status, content_type, body): 200 updated note | 403 bad/unknown | 404 unknown size.
    The checkpoint leaf's note_sha256 stays the hash of the note as first stored (lines added here are extra)."""
    text = "text/plain; charset=utf-8"
    row = store.get("checkpoints", log.checkpoint_key(log_id, size))
    if row is None:
        return 404, text, b"unknown checkpoint size\n"
    w2_vkey = (os.environ if env is None else env).get("AIRGAP_W2_VKEY", "").strip()
    if not w2_vkey:
        return 403, text, b"no W2 key configured (AIRGAP_W2_VKEY)\n"
    try:
        w2_name = parse_vkey(w2_vkey)["name"]
        lines = body.decode("utf-8").splitlines()
        cp_body = parse_note(row["note"])["body"]
    except (NoteError, UnicodeDecodeError) as exc:
        return 403, text, f"{exc}\n".encode()
    note, added = row["note"], 0
    for line in lines:
        if not line.startswith(f"{DASH} {w2_name} "):
            return 403, text, b"not a cosignature line from the pinned W2 key\n"
        try:
            ok = w2_name in verify_note(cp_body + "\n" + line + "\n", [w2_vkey])["verified"]
        except NoteError:
            ok = False
        if not ok:
            return 403, text, b"cosignature does not verify against AIRGAP_W2_VKEY\n"
        if line + "\n" not in note:
            note, added = note + line + "\n", added + 1
    if not lines:
        return 403, text, b"no cosignature lines\n"
    if added:
        store.put("checkpoints", {**row, "note": note})
    return 200, text, note.encode()


def add_checkpoint_request(old_size: int, proof: list[bytes], note: str) -> bytes:
    """C2SP tlog-witness add-checkpoint body."""
    return (f"old {old_size}\n" + "".join(_b64(p) + "\n" for p in proof) + "\n" + note).encode()


def maybe_checkpoint(log_id: str = "audit", *, store: Any, settings: Any) -> str | None:
    """Checkpoint if due (N leaves or max seconds with uncovered leaves). Called after every append and by WS-A's
    tx_execute after it commits an execution leaf. Returns the new note or None."""
    size = log.next_size(log_id, store=store)
    if not log.checkpoint_due(log_id, size, store=store, settings=settings):
        return None
    return make_checkpoint(log_id, store=store, settings=settings)


def make_checkpoint(log_id: str, *, store: Any, settings: Any) -> str:
    """Compute root, sign, send to W1 (and W2 relay), store the cosigned note in `checkpoints`, S3 Object Lock copy,
    checkpoint leaf. Returns the cosigned note text."""
    from executor.policy.rules import policy_hash

    hashes = log.leaf_hashes(log_id, store=store)
    size, root_hash = len(hashes), merkle.root(hashes)
    body = checkpoint_body(origin(log_id, settings), size, root_hash.hex(), policy_hash=policy_hash(),
                           code_sha256=code_sha256())
    note = sign_note(body, name=origin(log_id, settings), settings=settings)

    prev = latest(log_id, store=store)
    old_size = int(prev["size"]) if prev else 0
    cosigners: list[str] = []
    for _ in range(2):  # second round only after a 409 told us the witness's real size
        proof = merkle.consistency_proof(old_size, hashes) if old_size <= size else []
        status, _ctype, resp = _submit_w1(add_checkpoint_request(old_size, proof, note), store=store,
                                          settings=settings)
        witness_size = resp.strip().decode("ascii", "replace")
        if status == 409 and re.fullmatch(r"0|[1-9][0-9]*", witness_size) and int(witness_size) != old_size:
            old_size = int(witness_size)
            if old_size > size:  # the witness has seen a larger tree than ours: rollback/fork evidence
                break
            continue
        break
    if status == 200:
        note += resp.decode()
        cosigners.append(witness_name(settings))

    store.put("checkpoints", {**log.checkpoint_key(log_id, size), "note": note, "root_hash": root_hash.hex(),
                              "size": size, "created_at": log.now_iso(settings)})
    if status in REFUSAL_STATUSES:  # W1 never writes the log (S7); the checkpointer records its refusal
        log.append(log.make_event("witness_refusal", {"witness": witness_name(settings), "status": status,
                                                      "old_size": old_size, "size": size},
                                  subject_id=origin(log_id, settings), actor="checkpointer", log_id=log_id),
                   store=store, settings=settings, checkpoint=False)
    log.append(log.make_event("checkpoint", {"origin": origin(log_id, settings), "size": size,
                                             "root_hash": root_hash.hex(),
                                             "note_sha256": hashlib.sha256(note.encode()).hexdigest(),
                                             "cosigners": cosigners}, subject_id=None, actor="checkpointer",
                              log_id=log_id), store=store, settings=settings, checkpoint=False)
    return note
