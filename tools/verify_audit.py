"""Offline audit verifier (`python -m tools.verify_audit bundle.json [--no-replay] [--receipt r.json]
[--trust-keys keys.json] [--quorum log,w1|w2] [--allow-uncovered-tail]`).

Needs no network and no AWS: everything is recomputed from the exported bundle (CONTRACTS.md v2 §7.4) with the
bundle's own verifier keys. Problems name the leaf (`seq N`) or checkpoint (`checkpoint size N`) they concern.
Checks that need code owned by other workstreams (EIP-191 recovery in executor/sig.py, decide() in
executor/policy/decide.py) run when that code is implemented and are reported as SKIPPED, not failed, otherwise.

CONTRACTS.md v2 §7.5. Owner: WS-B.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from executor.audit import checkpoint as cp
from executor.audit import log, merkle
from executor.canonical import canonical_json
from executor.models import BANK_ROLES, DECISION_RELEVANT_EVENTS

DEFAULT_QUORUM: tuple[tuple[str, ...], ...] = (("log",), ("w1", "w2"))  # log AND (w1 OR w2), CONTRACTS §7.3
ROLES = ("log", "w1", "w2")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RELEVANT = {e.value for e in DECISION_RELEVANT_EVENTS}
_BANK_ROLES = {r.value for r in BANK_ROLES}
_SKIP_UPSTREAM = "SKIPPED (not yet implemented upstream: {})"


@dataclass
class Report:
    ok: bool
    problems: list[str] = field(default_factory=list)
    checked: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)  # SKIPPED / informational lines (never make the bundle fail)
    keys: dict[str, str] = field(default_factory=dict)  # role -> "name+keyid" actually used for note verification
    pinned: bool = False  # True when keys came from trusted_vkeys, False when taken from the bundle itself


class _Ctx:
    def __init__(self) -> None:
        self.problems: list[str] = []
        self.checked: dict[str, int] = {}
        self.notes: list[str] = []
        self.bad_leaf_seqs: set[int] = set()
        self.keys: dict[str, str] = {}

    def bad(self, msg: str, seq: int | None = None) -> None:
        self.problems.append(msg)
        if seq is not None:
            self.bad_leaf_seqs.add(seq)

    def count(self, key: str, n: int = 1) -> None:
        self.checked[key] = self.checked.get(key, 0) + n

    def note(self, msg: str) -> None:
        if msg not in self.notes:
            self.notes.append(msg)


def parse_quorum(text: str) -> tuple[tuple[str, ...], ...]:
    """'log,w1|w2' -> (('log',), ('w1', 'w2')): comma = AND, pipe = OR."""
    groups = tuple(tuple(r.strip() for r in g.split("|") if r.strip()) for g in text.split(","))
    if not groups or any(not g or set(g) - set(ROLES) for g in groups):
        raise ValueError(f"bad quorum {text!r}: use roles {ROLES}, ',' for AND, '|' for OR")
    return groups


def format_quorum(quorum: tuple[tuple[str, ...], ...]) -> str:
    return " AND ".join(g[0] if len(g) == 1 else "(" + " OR ".join(g) + ")" for g in quorum)


def _int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _ts(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _ranges(nums: list[int]) -> list[str]:
    spans: list[tuple[int, int]] = []
    for n in sorted(nums):
        if spans and spans[-1][1] == n - 1:
            spans[-1] = (spans[-1][0], n)
        else:
            spans.append((n, n))
    return [f"seq {a}" if a == b else f"seq {a}..{b}" for a, b in spans]


# 1. leaves: canonical JSON -> leaf hash, contiguous seq from 0, event.seq == seq
def _check_leaves(bundle: dict[str, Any], ctx: _Ctx) -> tuple[list[tuple[int, dict[str, Any]]], list[bytes]]:
    leaves = bundle.get("leaves")
    if not isinstance(leaves, list):
        ctx.bad("bundle has no 'leaves' list")
        return [], []
    events: list[tuple[int, dict[str, Any]]] = []
    hashes: list[bytes] = []
    seqs: list[int] = []
    for pos, le in enumerate(leaves):
        seq = le.get("seq") if isinstance(le, dict) else None
        if not isinstance(seq, int) or isinstance(seq, bool):
            ctx.bad(f"leaf at position {pos}: missing or non-integer seq")
            seq = pos
        ev = le.get("event") if isinstance(le, dict) else None
        if not isinstance(ev, dict):
            ctx.bad(f"seq {seq}: event missing", seq)
            ev = {}
        elif ev.get("seq") != seq:
            ctx.bad(f"seq {seq}: event carries seq {ev.get('seq')!r}", seq)
        try:
            h = merkle.leaf_hash(canonical_json(ev))
        except TypeError as exc:
            ctx.bad(f"seq {seq}: event is not canonical JSON ({exc})", seq)
            h = b"\0" * 32
        if h.hex() != (le.get("leaf_hash") if isinstance(le, dict) else None):
            ctx.bad(f"seq {seq}: leaf hash mismatch (event bytes differ from the recorded leaf_hash)", seq)
        else:
            ctx.count("leaf_hashes")
        seqs.append(seq)
        events.append((seq, ev))
        hashes.append(h)
    ctx.count("leaves", len(leaves))
    present = set(seqs)
    missing = [s for s in range(max(seqs, default=-1) + 1) if s not in present]
    for r in _ranges(missing):
        ctx.bad(f"{r}: missing (seq must be contiguous from 0)")
    seen: set[int] = set()
    for s in seqs:
        if s in seen:
            ctx.bad(f"seq {s}: duplicated", s)
        seen.add(s)
    for pos, s in enumerate(seqs):
        if s != pos and s in present and not missing and len(seen) == len(seqs):
            ctx.bad(f"seq {s}: out of order (found at position {pos})", s)
    return events, hashes


# 2. checkpoints: note signatures + quorum, roots, consistency, checkpoint leaves
def key_label(vkey: str) -> str:
    """'name+keyid' of a note verifier key (for reports); the raw string if it does not parse."""
    try:
        p = cp.parse_vkey(vkey)
        return f"{p['name']}+{p['key_id'].hex()}"
    except (cp.NoteError, AttributeError, TypeError, ValueError):
        return str(vkey)[:80]


def _vkeys(bundle: dict[str, Any], ctx: _Ctx,
           trusted: dict[str, str] | None = None) -> dict[str, tuple[str, dict[str, Any]]]:
    """Verifier keys per role. With `trusted` (pinned, out of band), only the pinned keys are used and every bundle
    key for a pinned role must equal its pin; without it the bundle's own keys are used (self-asserted)."""
    pub = bundle.get("pubkeys") or {}
    if not isinstance(pub, dict):
        ctx.bad("pubkeys is not an object")
        pub = {}
    src = pub
    if trusted is not None:
        for role, pinned in trusted.items():
            if role not in ROLES:
                ctx.bad(f"trusted key for unknown role {role!r} (use {', '.join(ROLES)})")
            elif pub.get(role) and pub[role] != pinned:
                ctx.bad(f"pubkeys.{role}: bundle key {key_label(pub[role])} is not the pinned key "
                        f"{key_label(pinned)}")
        src = trusted
    out = {}
    for role in ROLES:
        v = src.get(role)
        if not v:
            continue
        try:
            out[role] = (v, cp.parse_vkey(v))
            ctx.keys[role] = key_label(v)
        except (cp.NoteError, AttributeError, TypeError, ValueError) as exc:
            ctx.bad(f"{'trusted' if trusted is not None else 'pubkeys'}.{role}: {exc}")
    return out


def _check_checkpoints(bundle: dict[str, Any], events: list[tuple[int, dict[str, Any]]], hashes: list[bytes],
                       quorum: tuple[tuple[str, ...], ...], ctx: _Ctx, *, trusted: dict[str, str] | None = None,
                       allow_uncovered_tail: bool = False) -> None:
    vkeys = _vkeys(bundle, ctx, trusted)
    if "log" not in vkeys:
        ctx.bad("pubkeys.log missing: cannot verify any checkpoint")
        return
    name_role = {p["name"]: role for role, (_, p) in vkeys.items()}
    notes = bundle.get("checkpoints") or []
    if not notes:
        ctx.bad("bundle has no checkpoints: nothing signs the leaves")
    parsed: list[dict[str, Any]] = []
    note_by_size: dict[int, list[str]] = {}
    covered = 0
    for i, note in enumerate(notes):
        label = f"checkpoint #{i}"
        try:
            p = cp.parse_note(note)
        except (cp.NoteError, TypeError, AttributeError) as exc:
            ctx.bad(f"{label}: malformed note ({exc})")
            continue
        label = f"checkpoint size {p['size']}"
        note_by_size.setdefault(p["size"], []).append(note)
        try:
            v = cp.verify_note(note, [vk for vk, _ in vkeys.values()])
        except cp.NoteError as exc:
            ctx.bad(f"{label}: signature check failed ({exc})")
            continue
        if p["origin"] != vkeys["log"][1]["name"]:
            ctx.bad(f"{label}: origin {p['origin']!r} is not the log key's name {vkeys['log'][1]['name']!r}")
        roles = {name_role[n] for n in v["verified"] if n in name_role}
        unmet = [g for g in quorum if not roles & set(g)]
        if unmet:
            ctx.bad(f"{label}: signature quorum not met (valid: {', '.join(sorted(roles)) or 'none'}; "
                    f"need {format_quorum(quorum)})")
        else:
            ctx.count("checkpoint_quorum")
        for role in roles:
            ctx.count(f"checkpoint_sig_{role}")
        size = p["size"]
        if size > len(hashes):
            ctx.bad(f"{label}: covers {size} leaves but the bundle has only {len(hashes)}")
            continue
        p["root_ok"] = merkle.root(hashes[:size]).hex() == p["root_hash"]
        if not p["root_ok"]:
            first = min((s for s in ctx.bad_leaf_seqs if s < size), default=None)
            hint = f" (first bad leaf: seq {first})" if first is not None else ""
            ctx.bad(f"{label}: root mismatch, leaves 0..{size - 1} do not hash to the signed root{hint}")
        else:
            ctx.count("checkpoint_roots")
            if not unmet:
                covered = max(covered, size)
        parsed.append(p)

    sizes = [p["size"] for p in parsed]
    if sizes != sorted(sizes):
        ctx.bad("checkpoints are not in increasing size order")
    parsed.sort(key=lambda p: p["size"])
    for a, b in zip(parsed, parsed[1:]):
        if a["size"] == b["size"]:
            if a["root_hash"] != b["root_hash"]:
                ctx.bad(f"checkpoint size {a['size']}: two different signed roots (fork)")
            continue
        if b["size"] > len(hashes) or not (a["root_ok"] and b["root_ok"]):
            continue  # already reported (root mismatch / too few leaves)
        proof = merkle.consistency_proof(a["size"], hashes[:b["size"]])
        if merkle.verify_consistency(a["size"], b["size"], bytes.fromhex(a["root_hash"]),
                                     bytes.fromhex(b["root_hash"]), proof):
            ctx.count("consistency")
        else:
            ctx.bad(f"checkpoint size {a['size']} -> {b['size']}: not consistent (append-only violated)")
    ctx.count("checkpoints", len(notes))
    ctx.checked["covered_leaves"] = covered
    _check_uncovered_tail(notes, events, covered, ctx, allow=allow_uncovered_tail)

    # every checkpoint leaf points at a note in the bundle (a deleted/replaced checkpoint is detected)
    for seq, ev in events:
        if ev.get("type") != "checkpoint":
            continue
        d = ev.get("data") or {}
        cands = note_by_size.get(d.get("size"), [])
        if not cands:
            ctx.bad(f"seq {seq}: checkpoint leaf for size {d.get('size')} has no matching checkpoint in the bundle",
                    seq)
        elif d.get("note_sha256") not in {_logged_note_sha256(n, d) for n in cands}:
            ctx.bad(f"seq {seq}: checkpoint leaf note_sha256 does not match the exported checkpoint of size "
                    f"{d.get('size')}", seq)
        else:
            ctx.count("checkpoint_leaves")


def _logged_note_sha256(note: str, leaf_data: dict[str, Any]) -> str:
    """sha256 of the note as stored at checkpoint time: the exported note minus signature lines added later (row 22b,
    e.g. a W2 relay cosignature), i.e. keep only lines named by the log origin or listed in data.cosigners. The dropped
    lines were already verified (and count toward quorum) in the note signature check."""
    keep = {leaf_data.get("origin")} | {c for c in (leaf_data.get("cosigners") or []) if isinstance(c, str)}
    if "\n\n" not in note:
        return hashlib.sha256(note.encode()).hexdigest()
    split = note.rindex("\n\n") + 2
    lines = note[split:].splitlines(keepends=True)
    kept = [ln for ln in lines if len(ln.split(" ")) >= 3 and ln.split(" ")[1] in keep]
    return hashlib.sha256((note[:split] + "".join(kept)).encode()).hexdigest()


def _check_uncovered_tail(notes: list[Any], events: list[tuple[int, dict[str, Any]]], covered: int, ctx: _Ctx, *,
                          allow: bool) -> None:
    """Every leaf must sit under a quorum-valid checkpoint. The one exception is the trailing `checkpoint` leaf that
    records the last exported note (it can only be covered by the next checkpoint)."""
    exempt = None
    if notes and isinstance(notes[-1], str) and events:
        seq, ev = events[-1]
        d = ev.get("data") if isinstance(ev.get("data"), dict) else {}
        try:
            last_size = cp.parse_note(notes[-1])["size"]
        except (cp.NoteError, TypeError, AttributeError):
            last_size = None
        if (ev.get("type") == "checkpoint" and last_size is not None and d.get("size") == last_size
                and d.get("note_sha256") == _logged_note_sha256(notes[-1], d)):
            exempt = len(events) - 1
    uncovered = [seq for pos, (seq, _) in enumerate(events) if pos >= covered and pos != exempt]
    ctx.checked["uncovered_leaves"] = len(uncovered)
    if not uncovered:
        return
    if allow:
        ctx.note(f"WARNING: {len(uncovered)} leaves NOT covered by a witnessed checkpoint "
                 f"({', '.join(_ranges(uncovered))}); accepted only because of --allow-uncovered-tail")
    else:
        for seq in uncovered:
            ctx.bad(f"seq {seq}: not covered by a witnessed checkpoint")


# 3. digests and policies
def _check_digests(bundle: dict[str, Any], events: list[tuple[int, dict[str, Any]]], ctx: _Ctx) -> None:
    policies = bundle.get("policies") or {}
    for seq, ev in events:
        if ev.get("type") not in _RELEVANT:
            continue
        missing = [k for k in log.DIGESTS if not _HEX64.match(str(ev.get(k) or ""))]
        if missing:
            ctx.bad(f"seq {seq}: {ev.get('type')} event lacks {', '.join(missing)}", seq)
            continue
        ctx.count("digests")
        if ev["policy_hash"] not in policies:
            ctx.count("policy_not_in_bundle")
    if ctx.checked.get("policy_not_in_bundle"):
        ctx.note(f"{ctx.checked['policy_not_in_bundle']} decision-relevant leaves reference a policy_hash that "
                 "bundle.policies does not carry")
    for ph, material in policies.items():
        if hashlib.sha256(canonical_json(material)).hexdigest() == ph:
            ctx.count("policy_material")
        elif "params" not in material:
            ctx.note(f"policy {ph[:12]}: material has no 'params', so policy_hash cannot be recomputed offline")
        else:
            ctx.bad(f"policy {ph[:12]}: exported material does not hash to its policy_hash")


# 4. signatures: enrolment, challenge binding, re-render + EIP-191 recovery, 2/2 distinctness
def _recover(text: str, sig: str) -> str | None:
    """Recovered address, or None if executor/sig.py is not implemented yet."""
    from executor import sig as sigmod

    try:
        return sigmod.verify_eip191(text, sig).lower()
    except NotImplementedError:
        return None


def _signed_text(d: dict[str, Any], challenge: dict[str, Any] | None) -> str | None:
    """Signed text if the bundle carries it (signature data 'text', or challenge 'template' + 'params')."""
    if isinstance(d.get("text"), str):
        return d["text"]
    if challenge and challenge.get("template") and isinstance(challenge.get("params"), dict):
        from executor import render

        return render.render(challenge["template"], challenge["params"], profile=challenge.get("profile"),
                             deployment=challenge.get("deployment"))
    return None


def _check_signatures(bundle: dict[str, Any], events: list[tuple[int, dict[str, Any]]], ctx: _Ctx) -> None:
    enrolled: dict[str, tuple[str, int]] = {}  # address -> latest (role, seq) so far: a re-enrolment supersedes
    enroll_leaves: set[tuple[str, Any, int]] = set()  # every (address, role, seq): an address may be enrolled twice
    challenges: dict[str, tuple[int, dict[str, Any]]] = {}
    used: dict[str, int] = {}
    chg_signers: dict[str, dict[str, int]] = {}
    accepted: dict[Any, tuple[int, dict[str, Any], Any]] = {}  # nonce -> (seq, data, subject_id)
    for seq, ev in events:
        t, d = ev.get("type"), ev.get("data") or {}
        if t == "enroll":
            enrolled[str(d.get("address", "")).lower()] = (d.get("role"), seq)
            enroll_leaves.add((str(d.get("address", "")).lower(), d.get("role"), seq))
        elif t == "challenge":
            challenges[d.get("nonce")] = (seq, d)
        elif t == "signature" and d.get("accepted"):
            nonce, purpose = d.get("nonce"), d.get("purpose")
            accepted.setdefault(nonce, (seq, d, ev.get("subject_id")))
            if purpose == "ENROLL":
                continue
            addr = str(d.get("signer_address") or "").lower()
            if nonce in used:
                ctx.bad(f"seq {seq}: nonce {nonce} accepted twice (first at seq {used[nonce]})", seq)
            used[nonce] = seq
            if d.get("role") in _BANK_ROLES:
                e = enrolled.get(addr)
                if e is None:
                    ctx.bad(f"seq {seq}: accepted signature from {addr or 'no address'}, not enrolled before it", seq)
                elif e[0] != d.get("role"):
                    ctx.bad(f"seq {seq}: signer {addr} enrolled as {e[0]} (seq {e[1]}) but signed as {d.get('role')}",
                            seq)
                else:
                    ctx.count("signers_enrolled")
            ch = challenges.get(nonce)
            if ch is None:
                ctx.bad(f"seq {seq}: accepted signature for nonce {nonce} with no earlier challenge leaf", seq)
            elif ch[1].get("text_sha256") != d.get("text_sha256"):
                ctx.bad(f"seq {seq}: signed text_sha256 differs from challenge at seq {ch[0]}", seq)
            else:
                ctx.count("signature_challenge_binding")
            text = _signed_text(d, ch[1] if ch else None)
            if text is None:
                ctx.count("rerender_unavailable")
            else:
                if hashlib.sha256(text.encode()).hexdigest() != d.get("text_sha256"):
                    ctx.bad(f"seq {seq}: re-rendered text does not match text_sha256", seq)
                rec: str | None = ""
                if not d.get("sig"):
                    ctx.bad(f"seq {seq}: accepted signature leaf carries no sig, EIP-191 cannot be checked", seq)
                else:
                    try:
                        rec = _recover(text, str(d["sig"]))
                    except ValueError as exc:
                        ctx.bad(f"seq {seq}: signature does not recover ({exc})", seq)
                if rec is None:
                    ctx.count("eip191_unavailable")
                    ctx.note("EIP-191 signer recovery " + _SKIP_UPSTREAM.format("executor/sig.py"))
                elif rec and rec != addr:
                    ctx.bad(f"seq {seq}: signature recovers to {rec}, leaf says {addr}", seq)
                elif rec:
                    ctx.count("signer_recovered")
            if purpose == "CHG":
                by_addr = chg_signers.setdefault(ev.get("subject_id") or "", {})
                if addr in by_addr:
                    ctx.bad(f"seq {seq}: change {ev.get('subject_id')} signed twice by {addr} (seq {by_addr[addr]}); "
                            "2/2 needs distinct keys", seq)
                by_addr[addr] = seq
    if ctx.checked.get("rerender_unavailable"):
        ctx.note(f"re-render + signer recovery SKIPPED for {ctx.checked['rerender_unavailable']} signatures: the "
                 "bundle does not carry the signed text or challenge params")

    for a in bundle.get("approvers") or []:
        if (str(a.get("address", "")).lower(), a.get("role"), a.get("enroll_seq")) not in enroll_leaves:
            ctx.bad(f"approver {a.get('address')}: does not match an enroll leaf (role/enroll_seq)")
        else:
            ctx.count("approvers")

    mandates: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for seq, ev in events:
        if ev.get("type") == "mandate_signed":
            d = ev.get("data") or {}
            mandates.setdefault(d.get("mandate_id"), []).append((seq, d))
    for mid, sigs in mandates.items():
        multi = max(_int(d.get("sig_total"), 1) for _, d in sigs) >= 2
        first: dict[str, int] = {}
        signers: set[str] = set()  # distinct addresses backed by an accepted MANDATE signature on the same nonce
        for seq, d in sigs:
            addr = str(d.get("signer_address", "")).lower()
            if multi and addr in first:
                ctx.bad(f"seq {seq}: mandate {mid} signature {d.get('sig_index')}/{d.get('sig_total')} reuses signer "
                        f"{addr} (seq {first[addr]})", seq)
            first.setdefault(addr, seq)
            s = accepted.get(d.get("nonce"))
            if s and s[1].get("purpose") == "MANDATE" and s[2] == mid \
                    and str(s[1].get("signer_address") or "").lower() == addr:
                signers.add(addr)
            if d.get("status") == "ACTIVE":
                need = _int(d.get("sig_total"), 1)
                if len(signers) < need:
                    ctx.bad(f"seq {seq}: mandate {mid} ACTIVE with {len(signers)} distinct accepted signer(s), "
                            f"needs {need}", seq)
                else:
                    ctx.count("mandates_active_quorum")
        if multi:
            ctx.count("mandates_2of2")


# 5. payee changes: transition chain and cooling-off ordering
def _check_changes(events: list[tuple[int, dict[str, Any]]], ctx: _Ctx) -> None:
    state: dict[str, str] = {}
    visited: dict[str, set[str]] = {}
    not_before: dict[str, str] = {}
    cooled: dict[str, int] = {}
    scheduled: set[str] = set()
    chg_sigs: dict[str, dict[str, set[str]]] = {}  # change_id -> role -> accepted CHG signer addresses
    for seq, ev in events:
        t, d = ev.get("type"), ev.get("data") or {}
        if t == "change_event" and d.get("event") == "cooling_scheduled":
            scheduled.add(d.get("change_id"))
            if isinstance(d.get("detail"), dict) and d["detail"].get("not_before"):
                not_before[d.get("change_id")] = d["detail"]["not_before"]
        elif t == "state_transition":
            cid, frm, to = d.get("change_id"), d.get("from"), d.get("to")
            if cid in state and frm != state[cid]:
                ctx.bad(f"seq {seq}: change {cid} transition {frm}->{to} does not follow state {state[cid]}", seq)
            state[cid] = to
            visited.setdefault(cid, set()).update({s for s in (frm, to) if s})
            if frm == "COOLING":
                if cid not in scheduled:
                    ctx.bad(f"seq {seq}: change {cid} left COOLING without an earlier cooling_scheduled event", seq)
                nb, ts = _ts(not_before.get(cid)), _ts(ev.get("ts"))
                if nb and ts and ts < nb:
                    ctx.bad(f"seq {seq}: change {cid} left COOLING at {ev.get('ts')}, before not_before "
                            f"{not_before[cid]}", seq)
                cooled[cid] = seq
            if to == "ACTIVE":
                if "COOLING" not in visited[cid]:
                    ctx.bad(f"seq {seq}: change {cid} reached ACTIVE without a cooling-off period", seq)
                else:
                    ctx.count("changes_cooled")
                sigs = chg_sigs.get(cid, {})
                if not any(c != tr for c in sigs.get("clerk", ()) for tr in sigs.get("treasury", ())):
                    ctx.bad(f"seq {seq}: change {cid} reached ACTIVE without accepted CHG signatures from a clerk and "
                            "a treasury (distinct keys)", seq)
                else:
                    ctx.count("changes_signed_2of2")
        elif t == "signature" and d.get("accepted") and d.get("purpose") == "CHG":
            cid = ev.get("subject_id")
            chg_sigs.setdefault(cid, {}).setdefault(d.get("role"), set()).add(
                str(d.get("signer_address") or "").lower())
            if cid in state and cid not in cooled:
                ctx.bad(f"seq {seq}: change {cid} signature accepted before cooling-off ended", seq)


# 6. executions <-> decisions, rail, ledger
def _check_executions(bundle: dict[str, Any], events: list[tuple[int, dict[str, Any]]], ctx: _Ctx) -> None:
    decisions: dict[str, tuple[int, str]] = {}
    executed: dict[str, tuple[int, dict[str, Any]]] = {}
    pay_sigs: dict[str, list[int]] = {}  # proposal_id -> seqs of accepted PAY signatures
    for seq, ev in events:
        t, d = ev.get("type"), ev.get("data") or {}
        if t == "signature" and d.get("accepted") and d.get("purpose") == "PAY":
            pay_sigs.setdefault(ev.get("subject_id"), []).append(seq)
        elif t == "decision":
            decisions[d.get("subject_id") or ev.get("subject_id")] = (seq, d.get("decision"))
        elif t == "execution":
            tx = d.get("tx_id")
            if tx in executed:
                ctx.bad(f"seq {seq}: tx {tx} executed twice (first at seq {executed[tx][0]})", seq)
            executed[tx] = (seq, d)
            dec = decisions.get(d.get("proposal_id"))
            if dec is None:
                ctx.bad(f"seq {seq}: execution of {d.get('proposal_id')} without an earlier decision leaf", seq)
            elif dec[1] == "deny":
                ctx.bad(f"seq {seq}: execution of {d.get('proposal_id')} after a deny decision (seq {dec[0]})", seq)
            elif dec[1] == "challenge" and not any(dec[0] < s < seq for s in pay_sigs.get(d.get("proposal_id"), ())):
                ctx.bad(f"seq {seq}: execution of {d.get('proposal_id')} after a challenge decision (seq {dec[0]}) "
                        "without an accepted PAY signature in between", seq)
            else:
                ctx.count("executions")
        elif t == "rail_submitted" and d.get("tx_id") not in executed:
            ctx.bad(f"seq {seq}: rail_submitted for tx {d.get('tx_id')} with no earlier execution leaf", seq)
    ledger = bundle.get("ledger")
    if ledger is None:
        if executed:
            ctx.note("ledger <-> execution check limited to the leaves: the bundle carries no ledger rows")
        return
    by_seq = dict(events)
    rows = {r.get("tx_id"): r for r in ledger}
    for tx, r in rows.items():
        ev = by_seq.get(r.get("seq"))
        d = (ev or {}).get("data") or {}
        if not ev or ev.get("type") != "execution" or any(
                d.get(k) != r.get(k) for k in ("tx_id", "proposal_id", "vendor_id", "iban", "amount_minor",
                                               "currency")):
            ctx.bad(f"seq {r.get('seq')}: ledger row {tx} does not match an execution leaf")
        else:
            ctx.count("ledger_rows")
    for tx, (seq, _) in executed.items():
        if tx not in rows:
            ctx.bad(f"seq {seq}: execution {tx} has no ledger row", seq)


# 7. decide() replay at the logged policy_hash (S12): WS-A's replay_decision on every decision leaf (incl. rechecks)
def _check_replay(bundle: dict[str, Any], events: list[tuple[int, dict[str, Any]]], ctx: _Ctx) -> None:
    from executor.policy.decide import replay_decision

    policies = bundle.get("policies") or {}
    for seq, ev in events:
        if ev.get("type") != "decision":
            continue
        if not isinstance((ev.get("data") or {}).get("inputs"), dict):
            ctx.bad(f"seq {seq}: decision leaf carries no data.inputs, cannot replay", seq)
            continue
        material = policies.get(ev.get("policy_hash"))
        if material is None:
            ctx.bad(f"seq {seq}: cannot replay, policy {str(ev.get('policy_hash'))[:12]} not in bundle", seq)
            continue
        try:
            match, got = replay_decision(ev, material)
        except Exception as exc:  # noqa: BLE001 - any failure to replay is a finding
            ctx.bad(f"seq {seq}: decide() replay failed: {type(exc).__name__}: {exc}", seq)
            continue
        if not match:
            d = ev["data"]
            detail = got.get("error") or (f"replay gives {got.get('decision')} {got.get('rule_ids')}, leaf says "
                                          f"{d.get('decision')} {d.get('rule_ids')}")
            ctx.bad(f"seq {seq}: {detail}", seq)
        else:
            ctx.count("replayed")


def verify(bundle: dict[str, Any], *, replay: bool = True,
           quorum: tuple[tuple[str, ...], ...] = DEFAULT_QUORUM, trusted_vkeys: dict[str, str] | None = None,
           allow_uncovered_tail: bool = False) -> Report:
    """Verify an audit export offline (CONTRACTS §7.5).

    Integrity: leaf hashes, contiguous seq, every checkpoint root recomputed from the bundle's own leaves, log/W1/W2
    note signatures against `quorum`, checkpoint leaves <-> exported notes (extra cosignature lines added after the
    fact, row 22b, are stripped before hashing), and every leaf covered by a quorum-valid checkpoint (only the
    trailing `checkpoint` leaf of the last exported note may be uncovered; `allow_uncovered_tail=True` downgrades
    the rest to a loud note, counted in checked['uncovered_leaves']).

    Consistency between checkpoints: because every root is recomputed from the same leaf list, two checkpoints that
    both match their roots are consistent by construction; the RFC 9162 consistency proof is recomputed only as a
    cross-check. This detects a bundle edited after export, NOT a log that shows different histories to different
    parties: real fork detection is the witnesses' job (S8, they keep the last size/root they cosigned).

    Keys: with `trusted_vkeys` ({"log", "w1", "w2"?}, obtained out of band) only those keys verify notes and every
    bundle key for a pinned role must equal its pin. Without it the bundle's own keys are used (self-asserted: an
    attacker who rewrites the whole bundle can re-sign it), and Report.pinned is False.

    Semantics (kept simple): digests on decision-relevant leaves; policy material hashes; accepted signers enrolled
    with the right role, bound to an earlier challenge (re-render + EIP-191 recovery when the text is available);
    nonces accepted once; a `mandate_signed` leaf with status ACTIVE needs sig_total distinct signer addresses among
    that mandate's mandate_signed leaves, each backed by an accepted MANDATE signature on the same nonce; a payee
    change reaching ACTIVE needs accepted CHG signatures from a clerk and a treasury with distinct addresses, a
    COOLING period, and a cooling_scheduled change_event before it leaves COOLING (not before not_before); an
    execution needs an earlier decision for its proposal: the latest one must not be deny, and if it is challenge
    an accepted PAY signature for that proposal must lie between that decision and the execution; ledger rows match
    execution leaves; decide() replay at the logged policy_hash (S12) unless replay=False."""
    ctx = _Ctx()
    if not isinstance(bundle, dict):
        return Report(False, ["bundle is not a JSON object"])
    events, hashes = _check_leaves(bundle, ctx)
    _check_checkpoints(bundle, events, hashes, quorum, ctx, trusted=trusted_vkeys,
                       allow_uncovered_tail=allow_uncovered_tail)
    _check_digests(bundle, events, ctx)
    _check_signatures(bundle, events, ctx)
    _check_changes(events, ctx)
    _check_executions(bundle, events, ctx)
    if replay:
        _check_replay(bundle, events, ctx)
    else:
        ctx.note("decide() replay SKIPPED (--no-replay)")
    return Report(not ctx.problems, ctx.problems, ctx.checked, ctx.notes, ctx.keys, trusted_vkeys is not None)


def _ascii(s: str) -> str:
    return s.encode("ascii", "replace").decode("ascii")


def _quorum_arg(text: str) -> tuple[tuple[str, ...], ...]:
    try:
        return parse_quorum(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _load_trust_keys(path: str) -> dict[str, str]:
    """--trust-keys FILE: JSON {"log": vkey, "w1": vkey, "w2": vkey?} (raises ValueError / OSError)."""
    with open(path, encoding="utf-8") as f:
        keys = json.load(f)
    if not isinstance(keys, dict) or not keys.get("log") or not keys.get("w1"):
        raise ValueError('expected a JSON object {"log": vkey, "w1": vkey, "w2": vkey?}')
    bad = set(keys) - set(ROLES)
    if bad:
        raise ValueError(f"unknown roles {sorted(bad)} (use {', '.join(ROLES)})")
    out = {}
    for role, vk in keys.items():
        if vk is None:
            continue
        cp.parse_vkey(str(vk))  # NoteError is a ValueError
        out[role] = str(vk)
    return out


def _key_lines(keys: dict[str, str], pinned: bool, what: str) -> list[str]:
    used = ", ".join(f"{r} {k}" for r, k in keys.items()) or "none"
    if pinned:
        return [f"  keys (pinned via --trust-keys): {used}"]
    note = ("self-asserted keys (taken from the receipt, not pinned)" if what == "receipt"
            else "keys taken from the bundle (not pinned)")
    return [f"  keys in use: {used}", f"  NOTE: {note}; whoever can rewrite it can re-sign it, pin with --trust-keys"]


def main(argv: list[str] | None = None) -> int:
    """CLI; exit 1 on any problem, 2 on bad arguments."""
    from executor.audit import receipt as rc

    ap = argparse.ArgumentParser(prog="python -m tools.verify_audit", description="Offline AirGap audit verifier")
    ap.add_argument("bundle", nargs="?", help="audit export JSON (GET /audit/export response)")
    ap.add_argument("--no-replay", action="store_true", help="skip decide() replay")
    ap.add_argument("--receipt", help="receipt JSON (GET /receipts/{tx_id} response) or a text file holding its "
                                      "AGR1: QR payload, to verify")
    ap.add_argument("--quorum", default="log,w1|w2", type=_quorum_arg,
                    help="checkpoint quorum: ',' = AND, '|' = OR (default log,w1|w2)")
    ap.add_argument("--trust-keys", metavar="FILE",
                    help='pinned verifier keys, JSON {"log": vkey, "w1": vkey, "w2": vkey?}')
    ap.add_argument("--allow-uncovered-tail", action="store_true",
                    help="report leaves after the last witnessed checkpoint as a warning instead of a failure")
    args = ap.parse_args(argv)
    if not args.bundle and not args.receipt:
        ap.error("give a bundle, --receipt, or both")
    trusted = None
    if args.trust_keys:
        try:
            trusted = _load_trust_keys(args.trust_keys)
        except (OSError, ValueError) as exc:
            ap.error(f"--trust-keys {args.trust_keys}: {exc}")
    quorum_text = format_quorum(args.quorum)
    color = sys.stdout.isatty()
    green, red, off = ("\033[32m", "\033[31m", "\033[0m") if color else ("", "", "")
    problems: list[str] = []
    out = ["AirGap audit verifier (offline)"]

    bundle = None
    if args.bundle:
        try:
            with open(args.bundle, encoding="utf-8") as f:
                bundle = json.load(f)
        except (OSError, ValueError) as exc:
            problems.append(f"bundle {args.bundle}: cannot read JSON ({exc})")
        if isinstance(bundle, dict) and "response" in bundle and "leaves" not in bundle:
            bundle = bundle["response"]  # accept a contracts fixture envelope too
        if bundle is not None:
            try:
                rep = verify(bundle, replay=not args.no_replay, quorum=args.quorum, trusted_vkeys=trusted,
                             allow_uncovered_tail=args.allow_uncovered_tail)
            except Exception as exc:  # noqa: BLE001 - malformed input must give a red report, not a traceback
                rep = Report(False, [f"bundle {args.bundle}: malformed bundle ({type(exc).__name__}: {exc})"])
            c = rep.checked
            out.append(f"bundle: {args.bundle}  log {bundle.get('log_id') if isinstance(bundle, dict) else '?'}  "
                       f"leaves {c.get('leaves', 0)}  checkpoints {c.get('checkpoints', 0)}")
            out.append(f"  leaf hashes ok {c.get('leaf_hashes', 0)}/{c.get('leaves', 0)}, checkpoint roots ok "
                       f"{c.get('checkpoint_roots', 0)}, quorum ok {c.get('checkpoint_quorum', 0)} "
                       f"({quorum_text}), consistency ok {c.get('consistency', 0)}, covered leaves "
                       f"{c.get('covered_leaves', 0)}, uncovered {c.get('uncovered_leaves', 0)}")
            out += _key_lines(rep.keys, rep.pinned, "bundle")
            out.append("  checked: " + ", ".join(f"{k}={v}" for k, v in sorted(c.items())))
            out += [f"  {n}" for n in rep.notes]
            problems += rep.problems
    if args.receipt:
        r = None
        try:
            with open(args.receipt, encoding="utf-8") as f:
                text = f.read()
            if text.strip().startswith((rc.SHORT_PREFIX, rc.SHORT_URL)):  # short QR pointer: needs the bundle
                r = None
                try:
                    short = rc.parse_short_qr(text)
                    if not isinstance(bundle, dict):
                        raise ValueError("an AGR2 short receipt needs the bundle: verify_audit bundle.json --receipt ...")
                    sp = rc.short_qr_problems(short, bundle)
                except ValueError as exc:
                    short, sp = None, [str(exc)]
                out.append(f"receipt: {args.receipt} (AGR2 short QR)  tx {short['tx_id'] if short else '?'}  seq "
                           f"{short['seq'] if short else '?'}  tree size {short['tree_size'] if short else '?'}: "
                           f"{'ok' if not sp else 'FAILED'}")
                if short and not sp:
                    out.append("  vouched for: the execution leaf at seq in the verified bundle (pointer; the full "
                               "receipt is a separate file)")
                problems += [f"receipt: {p}" for p in sp]
            elif text.strip().startswith(rc.QR_PREFIX):  # what a phone QR scanner yields (receipt.qr_payload)
                try:
                    r = rc.parse_qr_payload(text)
                except ValueError as exc:
                    out.append(f"receipt: {args.receipt} (QR payload): FAILED")
                    problems.append(f"receipt: malformed receipt (QR payload: {exc})")
            else:
                r = json.loads(text)
        except (OSError, ValueError) as exc:
            problems.append(f"receipt {args.receipt}: cannot read JSON ({exc})")
        if r is not None:
            if isinstance(r, dict) and "response" in r and "entry" not in r:
                r = r["response"]
            try:
                rp = rc.receipt_problems(r, trusted_vkeys=trusted)
                if isinstance(bundle, dict) and not rp:
                    rp = rc.bundle_problems(r, bundle)
            except Exception as exc:  # noqa: BLE001
                rp = [f"malformed receipt ({type(exc).__name__}: {exc})"]
            if isinstance(r, dict):
                tx = r.get("tx") if isinstance(r.get("tx"), dict) else None
                entry = r.get("entry") if isinstance(r.get("entry"), dict) else {}
                tx_id = (tx or {}).get("tx_id") or (entry.get("data") or {}).get("tx_id")
                out.append(f"receipt: {args.receipt}  tx {tx_id}  seq {r.get('seq')}  "
                           f"tree size {r.get('tree_size')}: {'ok' if not rp else 'FAILED'}")
                out += _key_lines(rc.receipt_keys(r, trusted_vkeys=trusted), trusted is not None, "receipt")
                if tx is None:
                    out.append("  NOTE: receipt has no tx: only the execution leaf (entry.data) is vouched for")
                else:
                    out.append(f"  vouched for: entry.data and tx fields {', '.join(rc.TX_FIELDS)} (other tx fields "
                               "are not covered by the log)")
            else:
                out.append(f"receipt: {args.receipt}: FAILED")
            problems += [f"receipt: {p}" for p in rp]
    if problems:
        out.append(f"{red}RESULT: FAIL - {len(problems)} problem(s){off}")
        out += [f"  - {p}" for p in problems[:50]]
        if len(problems) > 50:
            out.append(f"  ... and {len(problems) - 50} more")
    else:
        out.append(f"{green}RESULT: OK{off}")
    print(_ascii("\n".join(out)))
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
