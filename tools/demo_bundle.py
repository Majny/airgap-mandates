"""Pre-sealed offline demo bundle (`python -m tools.demo_bundle [--out docs/audit/demo] [--allow-red]`).

Runs demo beat S1 (executor/e2e.py) in-process on the memory backend with a fixed clock, ticks the log so every
leaf is covered by a cosigned checkpoint, exports the audit bundle and writes, into --out:
  bundle.json      audit export (CONTRACTS §7.4), pretty, sorted keys
  trust-keys.json  {log, w1} verifier keys (public only), for --trust-keys
  receipt.json     receipt of the last executed payment (the over-cap step-up)
  checkpoint.txt   latest cosigned checkpoint note, for tools/noteverify (stock Go sumdb/note)
It refuses to seal (exit 1, nothing written) unless verify_audit (replay on, pinned keys) and the receipt check are
both green; --allow-red writes the files anyway plus RED-BUNDLE.txt listing what is still red (exit 0).

SIMULATED: memory backend, throwaway software signers, throwaway Ed25519 log/W1 keys in a temp dir that is deleted
after the run (no private key ever reaches --out), fictitious vendors. Not the AWS demo path.

`python -m tools.demo_bundle --tamper SRC DST` copies a bundle.json flipping ONE digit of amount_minor in the last
execution leaf and prints `seq N amount_minor OLD -> NEW` (used by tools/offline_demo.sh). Owner: WS-B.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

FAKE_NOW = "2026-10-19T12:00:00Z"
DEFAULT_OUT = "docs/audit/demo"
FILES = ("bundle.json", "trust-keys.json", "receipt.json", "checkpoint.txt")
RED = "RED-BUNDLE.txt"


@dataclass
class Sealed:
    bundle: dict[str, Any]
    trust_keys: dict[str, str]
    receipt: dict[str, Any]
    checkpoint_note: str
    summary: dict[str, Any]
    problems: list[str] = field(default_factory=list)
    secrets: list[bytes] = field(default_factory=list)  # local seeds of the run, kept only to prove none leaks

    @property
    def ok(self) -> bool:
        return not self.problems


def _dump(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def texts(sealed: Sealed) -> dict[str, str]:
    """File name -> content written to the out dir (RED-BUNDLE.txt only when red)."""
    out = {"bundle.json": _dump(sealed.bundle), "trust-keys.json": _dump(sealed.trust_keys),
           "receipt.json": _dump(sealed.receipt), "checkpoint.txt": sealed.checkpoint_note}
    if sealed.problems:
        out[RED] = "\n".join([
            "RED BUNDLE - NOT SEALED", "",
            "Written with --allow-red: the verifier does NOT accept this bundle yet.",
            "Do not present it as green. Remaining problems:", "",
            *(f"- {p}" for p in sealed.problems), ""])
    return out


def check(bundle: dict[str, Any], trust_keys: dict[str, str], receipt: dict[str, Any]) -> list[str]:
    """Problems of the bundle (replay on, keys pinned) and of the receipt (pinned, cross-checked with the bundle)."""
    from executor.audit import receipt as rc
    from tools import verify_audit as va

    problems = list(va.verify(bundle, replay=True, trusted_vkeys=trust_keys).problems)
    rp = rc.receipt_problems(receipt, trusted_vkeys=trust_keys) or rc.bundle_problems(receipt, bundle)
    return problems + [f"receipt: {p}" for p in rp]


def _leaks(content: str, secrets: list[bytes]) -> list[str]:
    raw = content.encode("utf-8", "surrogateescape")
    found = []
    for s in secrets:
        forms = (s, s.hex().encode(), base64.b64encode(s), base64.b64encode(s).rstrip(b"="))
        if any(f in raw for f in forms):
            found.append("local seed")
    if "PRIVATE" in content:
        found.append("the word PRIVATE")
    return found


def build(*, fake_now: str = FAKE_NOW, key_dir: str | None = None) -> Sealed:
    """Run the beat and collect the artifacts. key_dir None = fresh temp dir, deleted before returning."""
    if key_dir is None:
        with tempfile.TemporaryDirectory(prefix="airgap-demo-keys-") as tmp:
            return build(fake_now=fake_now, key_dir=tmp)
    from eth_account import Account

    from executor import e2e, handler
    from executor.audit import checkpoint as cp
    from executor.audit import kms, log
    from executor.audit import receipt as rc
    from executor.config import Settings
    from executor.store import seed
    from executor.store.memory import MemoryStore

    # Same context as executor.e2e.in_process(), but with our own local_key_dir (throwaway log/W1 keys).
    s = Settings(backend="memory", fake_now=fake_now, local_key_dir=key_dir, data_dir=seed.dev_data_dir())
    ctx = handler.Context(s, MemoryStore(s))
    seed.seed_registry(ctx.store)
    clerk, treasury = Account.create(), Account.create()
    seed.enroll_signer(ctx.store, clerk.address, "clerk", device="GENUINE", label="clerk (software key, demo bundle)",
                       settings=s)
    seed.enroll_signer(ctx.store, treasury.address, "treasury", label="treasury (software key, demo bundle)", settings=s)

    def call(m: str, p: str, b: Any, who: str) -> tuple[int, Any]:
        return handler.dispatch(m, p, None, b, principal=who, ctx=ctx)

    now = datetime.fromisoformat(fake_now.replace("Z", "+00:00"))
    summary = e2e.run(call, clerk, treasury, now=now, log=lambda _: None)
    log.tick("audit", store=ctx.store, settings=s)
    bundle = log.export("audit", store=ctx.store, settings=s)
    trust = cp.vkeys(s)
    latest = cp.latest("audit", store=ctx.store)
    receipt = rc.receipt(summary["tx_ids"][-1], store=ctx.store, settings=s)
    secrets = [p.read_bytes() for p in sorted(Path(key_dir).glob("*.ed25519"))]
    kms._local_key.cache_clear()  # drop the throwaway private keys from this process too
    sealed = Sealed(bundle, trust, receipt, latest["note"] if latest else "", summary, secrets=secrets)
    sealed.problems = check(bundle, trust, receipt)
    return sealed


def write(sealed: Sealed, out: str | Path, *, allow_red: bool = False) -> int:
    """Write the artifacts; 1 (nothing written) when red and not allow_red. Refuses if any secret would leak."""
    files = texts(sealed)
    for name, content in files.items():
        if leak := _leaks(content, sealed.secrets):
            raise RuntimeError(f"refusing to write {name}: contains {', '.join(leak)}")
    if sealed.problems and not allow_red:
        return 1
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (out / name).write_text(content, encoding="utf-8")  # the note dash is U+2014
    if not sealed.problems:
        (out / RED).unlink(missing_ok=True)
    return 0


def tamper(text: str) -> tuple[str, int, str, str]:
    """Flip the last digit of amount_minor inside the last execution leaf's event of a bundle.json text, touching
    exactly one byte. Returns (new_text, seq, old_amount, new_amount)."""
    bundle = json.loads(text)
    leaf = [le for le in bundle["leaves"] if le["event"]["type"] == "execution"][-1]
    marker = f'"leaf_hash": "{leaf["leaf_hash"]}"'
    if text.count(marker) != 1:
        raise ValueError(f"seq {leaf['seq']}: leaf_hash not unique in the text")
    end = text.index(marker)
    start = text.rfind('"leaf_hash": "', 0, end)  # end of the previous leaf (sorted keys: event < leaf_hash)
    key = '"amount_minor": '
    i = text.rfind(key, 0, end)
    if i < 0 or i < start:
        raise ValueError(f"seq {leaf['seq']}: no amount_minor in the execution event")
    j = k = i + len(key)
    while text[k].isdigit():
        k += 1
    if k == j:
        raise ValueError(f"seq {leaf['seq']}: amount_minor is not a number")
    new_digit = "1" if text[k - 1] != "1" else "2"
    new = text[:k - 1] + new_digit + text[k:]
    return new, int(leaf["seq"]), text[j:k], text[j:k - 1] + new_digit


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m tools.demo_bundle", description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=DEFAULT_OUT, help=f"output directory (default {DEFAULT_OUT})")
    ap.add_argument("--allow-red", action="store_true",
                    help="write the files even if they do not verify, plus RED-BUNDLE.txt listing the problems")
    ap.add_argument("--tamper", nargs=2, metavar=("SRC", "DST"),
                    help="copy SRC to DST flipping one digit of amount_minor in the last execution leaf")
    a = ap.parse_args(argv)
    if a.tamper:
        src, dst = a.tamper
        new, seq, old_amt, new_amt = tamper(Path(src).read_text(encoding="utf-8"))
        Path(dst).write_text(new, encoding="utf-8")
        print(f"seq {seq} amount_minor {old_amt} -> {new_amt}")
        return 0
    print("LOCAL memory backend, throwaway keys (simulated; the demo runs on AWS)", file=sys.stderr)
    sealed = build()
    rc = write(sealed, a.out, allow_red=a.allow_red)
    n = len(sealed.bundle["leaves"])
    if sealed.ok:
        print(f"SEALED {a.out}: {n} leaves, {len(sealed.bundle['checkpoints'])} checkpoints, receipt for "
              f"{sealed.summary['tx_ids'][-1]} - verifies green")
        return 0
    head = f"WROTE RED BUNDLE (see {RED})" if rc == 0 else "REFUSED TO SEAL (nothing written; --allow-red writes anyway)"
    print(f"{head}: {a.out}: {len(sealed.problems)} problem(s)")
    for p in sealed.problems:
        print(f"  - {p}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
