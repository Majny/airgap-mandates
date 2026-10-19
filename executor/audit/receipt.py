"""Self-contained receipt (tlog-proof style), shown as QR. CONTRACTS.md v2 §7.4. Owner: WS-B."""
from __future__ import annotations

import json
from typing import Any

from executor.audit import checkpoint as cp
from executor.audit import log, merkle

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
