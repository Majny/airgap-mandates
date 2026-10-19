"""Self-contained receipt (tlog-proof style), shown as QR. CONTRACTS.md v2 §7.4. Owner: WS-B."""
from __future__ import annotations

import base64
import io
import json
import re
import zlib
from typing import Any

from executor.audit import checkpoint as cp
from executor.audit import log, merkle
from executor.canonical import canonical_json

QUORUM: tuple[tuple[str, ...], ...] = (("log",), ("w1",))  # a receipt needs the log signature AND W1
TX_FIELDS = ("tx_id", "proposal_id", "vendor_id", "iban", "amount_minor", "currency", "authorization")
_SIG_TYPES = {"log": cp.SIG_ED25519, "w1": cp.SIG_COSIGNATURE, "w2": cp.SIG_COSIGNATURE}


def _execution_seq(tx_id: str, log_id: str, *, store: Any) -> tuple[int, dict[str, Any], dict[str, Any] | None]:
    """(seq, execution event, ledger row or None): the ledger row's 'seq' if that leaf is the execution of tx_id,
    else scan the leaves (a stale/wrong row seq never yields another leaf). LookupError when no such leaf."""
    row = None
    try:
        row = store.get("ledger", {"tx_id": tx_id})
    except KeyError:  # store without a ledger table (WS-B tests)
        row = None
    if row is not None and row.get("seq") is not None:
        item = store.get("audit", log.leaf_key(log_id, int(row["seq"])))
        ev = json.loads(item["event"]) if item is not None else {}
        if ev.get("type") == "execution" and (ev.get("data") or {}).get("tx_id") == tx_id:
            return int(row["seq"]), ev, row
    for item in log.leaves(log_id, store=store):
        ev = json.loads(item["event"])
        if ev.get("type") == "execution" and (ev.get("data") or {}).get("tx_id") == tx_id:
            return int(item["seq"]), ev, row
    raise LookupError(f"no execution leaf for {tx_id}")


def receipt(tx_id: str, *, store: Any, settings: Any, log_id: str = "audit") -> dict[str, Any]:
    """{tx, entry, seq, leaf_hash, tree_size, inclusion_proof, checkpoint_note, key_ids, vkeys}.

    Uses the latest checkpoint whose size covers seq, preferring one cosigned by W1 (raises LookupError when none
    covers it yet: retry after the next checkpoint / log.tick). `tx` is the ledger row; when the store has
    no ledger row it is rebuilt from the execution leaf (+ seq, executed_at = leaf ts)."""
    seq, entry, row = _execution_seq(tx_id, log_id, store=store)
    rows = [c for c in store.query("checkpoints", log.checkpoint_pk(log_id), reverse=True) if int(c["size"]) > seq]
    if not rows:
        raise LookupError(f"{tx_id} (seq {seq}) is not covered by a checkpoint yet")
    w1 = f"\n{cp.DASH} {cp.witness_name(settings)} "
    latest = next((c for c in rows if w1 in c["note"]), rows[0])  # prefer the latest W1-cosigned checkpoint
    size = int(latest["size"])
    hashes = log.leaf_hashes(log_id, store=store)[:size]
    vkeys = cp.vkeys(settings)
    if getattr(settings, "w2_vkey", None):
        vkeys["w2"] = settings.w2_vkey
    tx = row if row is not None else {**entry["data"], "seq": seq, "executed_at": entry.get("ts")}
    return {"tx": tx, "entry": entry, "seq": seq, "leaf_hash": hashes[seq].hex(), "tree_size": size,
            "inclusion_proof": [h.hex() for h in merkle.inclusion_proof(seq, hashes)],
            "checkpoint_note": latest["note"], "key_ids": {k: v.split("+")[1] for k, v in vkeys.items()},
            "vkeys": vkeys}


def _label(p: dict[str, Any]) -> str:
    return f"{p['name']}+{p['key_id'].hex()}"


def receipt_keys(r: Any, *, trusted_vkeys: dict[str, str] | None = None) -> dict[str, str]:
    """role -> 'name+keyid' of the keys receipt_problems verifies with (pinned ones, or the receipt's own)."""
    src = trusted_vkeys if trusted_vkeys is not None else (r.get("vkeys") if isinstance(r, dict) else None)
    out = {}
    for role, vk in (src or {}).items() if isinstance(src, dict) else ():
        try:
            out[role] = _label(cp.parse_vkey(vk))
        except (cp.NoteError, AttributeError, TypeError, ValueError):
            out[role] = "(unparseable)"
    return out


def receipt_problems(r: Any, *, quorum: tuple[tuple[str, ...], ...] = QUORUM,
                     trusted_vkeys: dict[str, str] | None = None) -> list[str]:
    """Human-readable reasons the receipt does not verify (empty list = valid). Offline.

    Keys: with `trusted_vkeys` ({log, w1, w2?}, pinned out of band) only those verify the note and each receipt vkey
    for a pinned role must equal its pin; otherwise the receipt's own vkeys are used (self-asserted). `tx`, when
    present, must agree with the logged execution on TX_FIELDS; when absent only `entry.data` is vouched for."""
    if not isinstance(r, dict):
        return ["malformed receipt (not a JSON object)"]
    try:
        entry, seq, size = r["entry"], int(r["seq"]), int(r["tree_size"])
        proof = [bytes.fromhex(h) for h in r["inclusion_proof"]]
        note, vkeys, key_ids = r["checkpoint_note"], dict(r["vkeys"]), dict(r["key_ids"])
        if not isinstance(entry, dict) or not isinstance(note, str):
            raise TypeError("entry must be an object and checkpoint_note a string")
        if r.get("tx") is not None and not isinstance(r["tx"], dict):
            raise TypeError("tx must be an object or null")
    except (KeyError, TypeError, ValueError) as exc:
        return [f"malformed receipt ({type(exc).__name__}: {exc})"]
    problems = []
    if entry.get("seq") != seq:
        problems.append(f"seq {seq}: entry carries seq {entry.get('seq')!r}")
    if entry.get("type") != "execution":
        problems.append(f"seq {seq}: entry is a {entry.get('type')!r} leaf, not an execution")
    data = entry.get("data") if isinstance(entry.get("data"), dict) else {}
    tx = r.get("tx")
    if tx is not None:
        diff = [k for k in TX_FIELDS if tx.get(k) != data.get(k)]
        if diff or tx.get("seq", seq) != seq:
            problems.append(f"seq {seq}: tx {tx.get('tx_id')} does not match the logged execution "
                            f"({', '.join(diff + (['seq'] if tx.get('seq', seq) != seq else []))})")
    try:
        lh = log.leaf_hash(entry)
    except TypeError as exc:
        return problems + [f"seq {seq}: entry is not canonical JSON ({exc})"]
    if lh != r.get("leaf_hash"):
        problems.append(f"seq {seq}: leaf hash mismatch (entry bytes differ from leaf_hash)")

    parsed_keys = {}
    for role, vk in vkeys.items():
        if not vk:
            continue
        try:
            p = cp.parse_vkey(vk)
        except (cp.NoteError, AttributeError, TypeError) as exc:
            problems.append(f"vkeys.{role}: {exc}")
            continue
        if role in _SIG_TYPES and p["sig_type"] != _SIG_TYPES[role]:
            problems.append(f"vkeys.{role}: wrong signature type 0x{p['sig_type']:02x}")
        if key_ids.get(role) != p["key_id"].hex():
            problems.append(f"key_ids.{role} {key_ids.get(role)!r} does not match vkeys.{role}")
        parsed_keys[role] = p
    if set(key_ids) - set(parsed_keys):
        problems.append(f"key_ids without vkeys: {sorted(set(key_ids) - set(parsed_keys))}")
    use = vkeys
    if trusted_vkeys is not None:
        for role, vk in vkeys.items():
            if vk and role in trusted_vkeys and vk != trusted_vkeys[role]:
                shown = _label(parsed_keys[role]) if role in parsed_keys else repr(vk)[:40]
                problems.append(f"vkeys.{role}: receipt key {shown} is not the pinned key")
        use, parsed_keys = {}, {}
        for role, vk in trusted_vkeys.items():
            try:
                parsed_keys[role], use[role] = cp.parse_vkey(vk), vk
            except (cp.NoteError, AttributeError, TypeError) as exc:
                problems.append(f"trusted.{role}: {exc}")
    if "log" not in parsed_keys:
        return problems + ["no usable log verifier key"]

    try:
        v = cp.verify_note(note, [use[k] for k in parsed_keys])
    except cp.NoteError as exc:
        return problems + [f"checkpoint note: {exc}"]
    roles = {role for role, p in parsed_keys.items() if p["name"] in v["verified"]}
    unmet = [g for g in quorum if not roles & set(g)]
    if unmet:
        problems.append(f"checkpoint note: signature quorum not met (valid: {', '.join(sorted(roles)) or 'none'})")
    if v["origin"] != parsed_keys["log"]["name"]:
        problems.append(f"checkpoint note: origin {v['origin']!r} is not the log key's name")
    if v["size"] != size:
        problems.append(f"tree_size {size} differs from the checkpoint size {v['size']}")
    if not merkle.verify_inclusion(seq, v["size"], bytes.fromhex(lh), proof, bytes.fromhex(v["root_hash"])):
        problems.append(f"seq {seq}: inclusion proof does not lead to the checkpoint root")
    return problems


def verify_receipt(receipt: Any, trusted_vkeys: dict[str, str] | None = None) -> bool:
    """Offline: leaf hash, inclusion proof against the note root, note signatures (log AND w1), key ids, tx fields;
    keys pinned via `trusted_vkeys` when given (otherwise the receipt's own, self-asserted)."""
    return not receipt_problems(receipt, trusted_vkeys=trusted_vkeys)


def bundle_problems(r: dict[str, Any], bundle: dict[str, Any]) -> list[str]:
    """Cross-check a receipt against an export: same leaf at seq, checkpoint note present in the bundle."""
    problems = []
    leaf = next((le for le in bundle.get("leaves") or [] if le.get("seq") == r.get("seq")), None)
    if leaf is None or leaf.get("event") != r.get("entry"):
        problems.append(f"seq {r.get('seq')}: receipt entry is not the bundle's leaf")
    if r.get("checkpoint_note") not in (bundle.get("checkpoints") or []):
        problems.append("receipt checkpoint note is not among the bundle's checkpoints")
    return problems


# --- QR transport (UI) -------------------------------------------------------------------------------------------
QR_PREFIX = "AGR1:"
QR_MAX_JSON = 64 * 1024  # decompressed cap (zip-bomb guard); real receipts are ~2-4 KB
_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


def qr_payload(r: dict[str, Any]) -> str:
    """'AGR1:' + base64url-no-padding(zlib.compress(canonical_json(r), 9)): lossless, ASCII, one string per receipt.

    Why compressed: a full receipt is ~2-3 KB of JSON (entry, tx, a 1-14 hash inclusion proof as hex, a checkpoint
    note with 2-3 signatures, vkeys), while a QR code tops out at 2953 bytes (version 40, EC level L, byte mode).
    zlib + base64url saves ~30% (hex digests and repeated keys compress; signatures do not). Synthetic sizes
    (FakeStore log, demo execution leaf + ledger row
    in the middle of the tree, log + W1 note, no W2): tree size 10 -> proof 4, JSON 2116 B, payload 1436 chars,
    QR v31-M; 100 -> 7, 2322, 1609, v33-M; 1000 -> 10, 2528, 1777, v35-M; 10000 -> 14, 2801, 1993, v38-M.
    Each extra proof hash adds ~55 chars; a W2 cosignature ~100. Real executor receipts are ~300 chars larger (a
    30-leaf S1 run: 1745 chars, v35-M), so they reach the version-40 / M limit around 10^4 leaves (sooner with W2)
    and then fall back to L. Dense codes: show them large; the AGR1 text is a fallback input to verify_audit."""
    return QR_PREFIX + base64.urlsafe_b64encode(zlib.compress(canonical_json(r), 9)).decode("ascii").rstrip("=")


def _no_float(text: str) -> Any:
    raise ValueError(f"non-integer number {text!r}")


def parse_qr_payload(text: str) -> dict[str, Any]:
    """Inverse of qr_payload (whitespace around it is ignored). Strict: ValueError unless it is 'AGR1:' + canonical
    base64url (no padding) of a complete zlib stream of at most QR_MAX_JSON bytes of canonical JSON for an object.
    The receipt itself is NOT verified here: run verify_receipt / receipt_problems on the result."""
    if not isinstance(text, str):
        raise ValueError("QR payload must be text")
    text = text.strip()
    if not text.startswith(QR_PREFIX):
        raise ValueError(f"not an {QR_PREFIX[:-1]} receipt payload")
    b64 = text[len(QR_PREFIX):]
    if not b64 or not _B64URL.match(b64) or len(b64) % 4 == 1:
        raise ValueError("payload is not unpadded base64url")
    raw = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != b64:
        raise ValueError("payload is not canonical base64url")
    d = zlib.decompressobj()
    try:
        data = d.decompress(raw, QR_MAX_JSON + 1)
    except zlib.error as exc:
        raise ValueError(f"payload is not zlib data ({exc})") from None
    if len(data) > QR_MAX_JSON or d.unconsumed_tail:
        raise ValueError(f"payload decompresses to more than {QR_MAX_JSON} bytes")
    if not d.eof or d.unused_data:
        raise ValueError("payload is not exactly one complete zlib stream")
    try:
        obj = json.loads(data.decode("utf-8"), parse_float=_no_float, parse_constant=_no_float)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"payload is not JSON ({exc})") from None
    except RecursionError:
        raise ValueError("payload JSON is nested too deeply") from None
    if not isinstance(obj, dict):
        raise ValueError("payload JSON is not an object")
    try:
        canonical = canonical_json(obj)
    except (RecursionError, TypeError):
        raise ValueError("payload JSON is nested too deeply or not canonical-encodable") from None
    if canonical != data:
        raise ValueError("payload JSON is not canonical")
    return obj


def _qr(r: dict[str, Any]) -> Any:
    try:
        import segno
    except ImportError:
        raise RuntimeError("receipt QR codes need segno: pip install segno") from None
    payload = qr_payload(r)
    for level in ("M", "L"):  # boost_error raises M to Q/H when that fits the same version
        try:
            return segno.make(payload, error=level, mode="byte", micro=False, boost_error=True)
        except segno.DataOverflowError:
            continue
    raise ValueError(f"receipt payload ({len(payload)} chars) does not fit a version 40 QR code")


def receipt_qr(r: dict[str, Any]) -> tuple[int, str]:
    """(QR version, error correction level) the receipt's payload is encoded with (needs segno)."""
    q = _qr(r)
    return int(q.version), str(q.error)


def receipt_qr_png(r: dict[str, Any], *, scale: int = 4, border: int = 4) -> bytes:
    """PNG of the receipt's QR code (payload: qr_payload). EC level M (boosted when it fits), else L. Needs segno."""
    buf = io.BytesIO()
    _qr(r).save(buf, kind="png", scale=scale, border=border)
    return buf.getvalue()


def receipt_qr_svg(r: dict[str, Any], *, scale: int = 4, border: int = 4) -> str:
    """SVG (UTF-8 text, ASCII content) of the receipt's QR code; same encoding as receipt_qr_png. Needs segno."""
    buf = io.BytesIO()
    _qr(r).save(buf, kind="svg", scale=scale, border=border)
    return buf.getvalue().decode("utf-8")
