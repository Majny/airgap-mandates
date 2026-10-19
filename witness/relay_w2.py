"""W2 relay: pull checkpoint + leaves from the executor API, POST to an unmodified litewitness (C2SP tlog-witness).

W2 = "independent supervisor witness (simulated operator)": stock filippo.io/torchwood/cmd/litewitness v0.10.0 run by
us on the operator's behalf (witness/w2/README.md). Standard library HTTP only. CONTRACTS.md v2 §7.3. Owner: WS-B.

Contract gap: the executor has no endpoint to store W2's cosignature in its checkpoint note, so the cosignature
line(s) are returned/printed, not uploaded (proposal: `POST /checkpoint/cosignature?log_id=` in the WS-B report).
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from executor.audit import merkle

SIZE_CT = "text/x.tlog.size"
DASH = "—"

# Last size W2 accepted, per (w2_url, origin); a fresh process starts at 0 and learns the real size from a 409.
_known_size: dict[tuple[str, str], int] = {}


@dataclass
class RelayResult:
    status: int
    origin: str
    old_size: int
    size: int
    body: str
    cosignatures: list[str] = field(default_factory=list)


def _get(url: str, timeout: float) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - configured executor URL
        return resp.read()


def _post(url: str, data: bytes, timeout: float) -> tuple[int, str, bytes]:
    req = urllib.request.Request(url, data=data, method="POST", headers={"Content-Type": "text/plain"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - configured W2 URL
            return resp.status, resp.headers.get("Content-Type", ""), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type", ""), exc.read()


def _log_signed(note: str) -> tuple[str, int, bytes, str]:
    """(origin, size, root, note reduced to body + the log's own signature lines; W1 cosignatures are dropped)."""
    body, sigs = note.split("\n\n", 1)
    origin, size_s, root_b64 = body.split("\n")[:3]
    own = [line for line in sigs.splitlines() if line.startswith(f"{DASH} {origin} ")]
    if not own:
        raise ValueError(f"checkpoint has no signature from its origin {origin!r}")
    return origin, int(size_s), base64.b64decode(root_b64), body + "\n\n" + "".join(x + "\n" for x in own)


def _request(old: int, proof: list[bytes], note: str) -> bytes:
    return (f"old {old}\n" + "".join(base64.b64encode(p).decode() + "\n" for p in proof) + "\n" + note).encode()


def relay(*, executor_url: str, w2_url: str, log_id: str = "audit", old_size: int | None = None,
          timeout: float = 10.0) -> RelayResult:
    """One relay round with details (status, cosignature lines)."""
    base = executor_url.rstrip("/")
    q = urllib.parse.urlencode({"log_id": log_id})
    note = _get(f"{base}/checkpoint?{q}", timeout).decode("utf-8")
    origin, size, root, note = _log_signed(note)
    export = json.loads(_get(f"{base}/audit/export?{q}&from_seq=0&redact=0", timeout))
    hashes = [bytes.fromhex(le["leaf_hash"]) for le in sorted(export["leaves"], key=lambda le: le["seq"])][:size]
    if len(hashes) != size or merkle.root(hashes) != root:
        raise ValueError(f"export leaves do not reproduce the {origin} checkpoint root at size {size}")

    url = w2_url.rstrip("/") + "/add-checkpoint"
    old = _known_size.get((w2_url, origin), 0) if old_size is None else old_size
    for _ in range(2):  # second round only after a 409 told us W2's real size
        proof = merkle.consistency_proof(old, hashes) if 0 < old <= size else []
        status, ctype, resp = _post(url, _request(old, proof, note), timeout)
        text = resp.decode("utf-8", "replace")
        if status == 409 and ctype.startswith(SIZE_CT) and text.strip().isdigit() and int(text) != old:
            old = int(text)
            _known_size[(w2_url, origin)] = old
            continue
        break
    cosigs = []
    if status == 200:
        _known_size[(w2_url, origin)] = size
        cosigs = [line for line in text.splitlines() if line.startswith(DASH + " ")]
    return RelayResult(status, origin, old, size, text, cosigs)


def relay_once(*, executor_url: str, w2_url: str) -> int:
    """One relay round; returns the HTTP status from W2 and prints W2's cosignature line(s) (see the contract gap)."""
    result = relay(executor_url=executor_url, w2_url=w2_url)
    for line in result.cosignatures:
        print(line)
    return result.status


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Relay the executor's latest checkpoint to W2 (litewitness).")
    ap.add_argument("--executor-url", default="http://127.0.0.1:8000")
    ap.add_argument("--w2-url", default="http://127.0.0.1:7380")
    ap.add_argument("--log-id", default="audit")
    ap.add_argument("--old-size", type=int, default=None)
    a = ap.parse_args(argv)
    r = relay(executor_url=a.executor_url, w2_url=a.w2_url, log_id=a.log_id, old_size=a.old_size)
    print(f"W2 {r.status} origin={r.origin} old={r.old_size} size={r.size}", file=sys.stderr)
    sys.stdout.write("".join(c + "\n" for c in r.cosignatures) if r.status == 200 else r.body)
    return 0 if r.status == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main())
