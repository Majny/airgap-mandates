"""W2 relay: pull checkpoint + leaves from the executor API, POST to an unmodified litewitness (C2SP tlog-witness).

W2 = "independent supervisor witness (simulated operator)": stock filippo.io/torchwood/cmd/litewitness v0.10.0 run by
us on the operator's behalf (witness/w2/README.md). Standard library HTTP only. CONTRACTS.md v2 §7.3. Owner: WS-B.

Verified W2 cosignature line(s) are posted back to the executor (row 22b `POST /checkpoint/cosignature`), which checks
them against AIRGAP_W2_VKEY and appends them to the stored note. The relay has no audit access: W2 refusals are
reported on stdout/stderr and in the exit code only.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from executor.audit import checkpoint as cp
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
    rollback_suspected: bool = False  # W2 already cosigned a larger tree than the executor now serves
    unverified: list[str] = field(default_factory=list)  # 200 lines that did not verify against w2_vkey
    upload_status: int | None = None  # row 22b response status (None = nothing uploaded)


Get = Callable[[str, float], bytes]
Post = Callable[[str, bytes, float], tuple[int, str, bytes]]


def _get(url: str, timeout: float, headers: dict[str, str] | None = None) -> bytes:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - configured executor URL
        return resp.read()


def _post(url: str, data: bytes, timeout: float, headers: dict[str, str] | None = None) -> tuple[int, str, bytes]:
    req = urllib.request.Request(url, data=data, method="POST", headers={"Content-Type": "text/plain", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - configured W2 URL
            return resp.status, resp.headers.get("Content-Type", ""), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type", ""), exc.read()


def sigv4(role: str, region: str) -> tuple[Get, Post]:
    """Executor GET/POST signed (SigV4, execute-api) as the assumed role (AWS: airgap-relay; credentials from
    AWS_PROFILE). HTTP errors surface as urllib HTTPError, as with the unsigned transport."""
    import boto3
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    sts = boto3.client("sts", region_name=region)
    account = sts.get_caller_identity()["Account"]
    c = sts.assume_role(RoleArn=f"arn:aws:iam::{account}:role/{role}", RoleSessionName="ws-b-relay-w2")["Credentials"]
    creds = boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"],
                          aws_session_token=c["SessionToken"], region_name=region).get_credentials()

    def signed(method: str, url: str, data: bytes | None) -> dict[str, str]:
        req = AWSRequest(method=method, url=url, data=data,
                         headers={"Content-Type": "text/plain"} if data is not None else {})
        SigV4Auth(creds, "execute-api", region).add_auth(req)
        return dict(req.headers)

    def get(url: str, timeout: float) -> bytes:
        return _get(url, timeout, signed("GET", url, None))

    def post(url: str, data: bytes, timeout: float) -> tuple[int, str, bytes]:
        return _post(url, data, timeout, signed("POST", url, data))

    return get, post


def parse_http_response(raw: bytes) -> tuple[int, str, bytes]:
    """(status, content type, body) from `curl -i` output (last header block wins, e.g. after 100 Continue)."""
    status, ctype, rest = 0, "", raw
    while rest.startswith(b"HTTP/"):
        ends = [(i, len(sep)) for sep in (b"\r\n\r\n", b"\n\n") if (i := rest.find(sep)) >= 0]
        if not ends:
            raise ValueError("unterminated HTTP header block")
        i, n = min(ends)
        lines = rest[:i].decode("latin-1").replace("\r\n", "\n").split("\n")
        rest = rest[i + n:]
        status, ctype = int(lines[0].split()[1]), ""
        for h in lines[1:]:
            k, _, v = h.partition(":")
            if k.strip().lower() == "content-type":
                ctype = v.strip()
    if not status:
        raise ValueError(f"not an HTTP response: {raw[:80]!r}")
    return status, ctype, rest


def ssm_post(instance_id: str, region: str, *, port: int = 7380, poll: float = 1.0) -> Post:
    """W2 transport over SSM RunCommand: curl to 127.0.0.1:<port> on the W2 instance (no inbound port, no session
    plugin). Uses the caller's own credentials (operator; needs ssm:SendCommand on the instance). Only the URL path
    is used; the request body travels base64-encoded inside the command."""
    import boto3

    ssm = boto3.client("ssm", region_name=region)

    def post(url: str, data: bytes, timeout: float) -> tuple[int, str, bytes]:
        path = urllib.parse.urlsplit(url).path or "/"
        if not all(ch.isalnum() or ch in "/-_." for ch in path):
            raise ValueError(f"unexpected W2 path {path!r}")
        cmd = (f"echo {base64.b64encode(data).decode()} | base64 -d | curl -sS -i --max-time {int(timeout)} "
               f"-H 'Content-Type: text/plain' --data-binary @- http://127.0.0.1:{port}{path} | base64 -w0")
        cid = ssm.send_command(InstanceIds=[instance_id], DocumentName="AWS-RunShellScript",
                               Parameters={"commands": [cmd]}, TimeoutSeconds=max(30, int(timeout) + 30),
                               )["Command"]["CommandId"]
        deadline = time.monotonic() + timeout + 60
        while True:
            time.sleep(poll)
            try:
                inv = ssm.get_command_invocation(CommandId=cid, InstanceId=instance_id)
            except ssm.exceptions.InvocationDoesNotExist:
                continue
            if inv["Status"] not in ("Pending", "InProgress", "Delayed"):
                break
            if time.monotonic() > deadline:
                raise TimeoutError(f"SSM command {cid} still {inv['Status']}")
        if inv["Status"] != "Success":
            raise OSError(f"SSM {cid} {inv['Status']}: {inv.get('StandardErrorContent', '')[:300]}")
        return parse_http_response(base64.b64decode(inv["StandardOutputContent"].strip()))

    return post


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
          timeout: float = 10.0, w2_vkey: str | None = None, upload: bool = True, get: Get = _get,
          post: Post = _post, w2_post: Post = _post) -> RelayResult:
    """One relay round with details (status, cosignature lines). With w2_vkey (default AIRGAP_W2_VKEY) only lines
    that verify as W2 cosignatures over this checkpoint are returned. get/post reach the executor (default unsigned;
    AWS: sigv4()), w2_post reaches W2 (default HTTP; AWS: ssm_post())."""
    w2_vkey = w2_vkey if w2_vkey is not None else os.environ.get("AIRGAP_W2_VKEY") or None
    base = executor_url.rstrip("/")
    q = urllib.parse.urlencode({"log_id": log_id})
    note = get(f"{base}/checkpoint?{q}", timeout).decode("utf-8")
    origin, size, root, note = _log_signed(note)
    export = json.loads(get(f"{base}/audit/export?{q}&from_seq=0&redact=0", timeout))
    hashes = [bytes.fromhex(le["leaf_hash"]) for le in sorted(export["leaves"], key=lambda le: le["seq"])][:size]
    if len(hashes) != size or merkle.root(hashes) != root:
        raise ValueError(f"export leaves do not reproduce the {origin} checkpoint root at size {size}")

    url = w2_url.rstrip("/") + "/add-checkpoint"
    old = _known_size.get((w2_url, origin), 0) if old_size is None else old_size
    for _ in range(2):  # second round only after a 409 told us W2's real size
        proof = merkle.consistency_proof(old, hashes) if 0 < old <= size else []
        status, ctype, resp = w2_post(url, _request(old, proof, note), timeout)
        text = resp.decode("utf-8", "replace")
        if status == 409 and ctype.startswith(SIZE_CT) and text.strip().isdigit() and int(text) != old:
            if int(text) > size:  # W2 has seen a larger tree: rollback/fork evidence, do not resubmit
                return RelayResult(status, origin, int(text), size, text, rollback_suspected=True)
            old = int(text)
            _known_size[(w2_url, origin)] = old
            continue
        break
    cosigs, unverified = [], []
    if status == 200:
        _known_size[(w2_url, origin)] = size
        for line in (x for x in text.splitlines() if x.startswith(DASH + " ")):
            try:
                ok = w2_vkey is None or bool(cp.verify_note(note + line + "\n", [w2_vkey])["verified"])
            except cp.NoteError:
                ok = False
            (cosigs if ok else unverified).append(line)
    result = RelayResult(status, origin, old, size, text, cosigs, unverified=unverified)
    if upload and cosigs:
        q22 = urllib.parse.urlencode({"log_id": log_id, "size": size})
        result.upload_status = post(f"{base}/checkpoint/cosignature?{q22}",
                                     "".join(c + "\n" for c in cosigs).encode(), timeout)[0]
    return result


def _w2_lines(note: str, w2_vkey: str) -> list[str]:
    """Lines of `note` that verify as W2 cosignatures over its body."""
    name = cp.parse_vkey(w2_vkey)["name"]
    body = note.split("\n\n", 1)[0] + "\n"
    out = []
    for line in (x for x in note.splitlines() if x.startswith(f"{DASH} {name} ")):
        try:
            if name in cp.verify_note(body + "\n" + line + "\n", [w2_vkey])["verified"]:
                out.append(line)
        except cp.NoteError:
            pass
    return out


def relay_store(log_id: str = "audit", *, store: Any, settings: Any, w2_post: Post, w2_vkey: str,
                w2_url: str = "http://w2", timeout: float = 30.0, limit: int = 5) -> dict[str, Any]:
    """Catch-up relay next to the log (checkpointer λ, after each tick): send every stored checkpoint W2 has not
    cosigned yet to W2, oldest first (W2 only moves forward, so a skipped size can never be cosigned later), and append
    W2's verified lines to the stored note (checkpoint.add_cosignature, the same check as row 22b). At most `limit`
    checkpoints per call. Returns {"cosigned": [sizes], "skipped": [sizes], "w2_size": n, "error": str | None}."""
    from executor.audit import log as auditlog

    rows = sorted(store.query("checkpoints", auditlog.checkpoint_pk(log_id)), key=lambda r: int(r["size"]))
    done = [int(r["size"]) for r in rows if _w2_lines(r["note"], w2_vkey)]
    old = max(done, default=0)
    todo = [r for r in rows if int(r["size"]) > old and int(r["size"]) not in done][:limit]
    out: dict[str, Any] = {"cosigned": [], "skipped": [], "w2_size": old, "error": None}
    if not todo:
        return out
    hashes = auditlog.leaf_hashes(log_id, store=store)
    for row in todo:
        size = int(row["size"])
        _, _, root, note = _log_signed(row["note"])
        if size > len(hashes) or merkle.root(hashes[:size]) != root:
            out["error"] = f"stored leaves do not reproduce the checkpoint root at size {size}"
            break
        for _ in range(2):
            proof = merkle.consistency_proof(old, hashes[:size]) if 0 < old <= size else []
            status, ctype, resp = w2_post(w2_url.rstrip("/") + "/add-checkpoint", _request(old, proof, note), timeout)
            text = resp.decode("utf-8", "replace")
            if status == 409 and ctype.startswith(SIZE_CT) and text.strip().isdigit() and int(text) != old:
                old = int(text)
                if old > size:
                    break
                continue  # old == size is fine: W2 re-cosigns the same tree (empty proof)
            break
        out["w2_size"] = max(old, out["w2_size"])
        if status == 409 and old > size:  # W2 is already past this size: it can never cosign it
            out["skipped"].append(size)
            continue
        if status != 200:
            out["error"] = f"W2 {status} at size {size}: {text.strip()[:200]}"
            break
        lines = _w2_lines(note + text, w2_vkey)
        st, _, msg = cp.add_cosignature(log_id, size, "".join(x + "\n" for x in lines).encode(), store=store,
                                        settings=settings, env={"AIRGAP_W2_VKEY": w2_vkey})
        if st != 200:
            out["error"] = f"W2 line(s) at size {size} rejected: {st} {msg.decode('utf-8', 'replace').strip()}"
            break
        out["cosigned"].append(size)
        old = out["w2_size"] = size
    return out


def after_tick(log_id: str = "audit", *, store: Any, settings: Any, env: dict[str, str] | None = None
               ) -> dict[str, Any] | None:
    """Hook for the checkpointer λ right after log.tick: relay pending checkpoints to W2 over SSM. Off (None) unless
    AIRGAP_W2_INSTANCE_ID and AIRGAP_W2_VKEY are set. Never raises: a W2 outage must not stop checkpointing (the
    checkpoints stay log + W1 and are caught up on the next tick)."""
    env = os.environ if env is None else env
    instance, w2_vkey = env.get("AIRGAP_W2_INSTANCE_ID", "").strip(), env.get("AIRGAP_W2_VKEY", "").strip()
    if not instance or not w2_vkey:
        return None
    try:
        return relay_store(log_id, store=store, settings=settings, w2_vkey=w2_vkey,
                           w2_post=ssm_post(instance, getattr(settings, "aws_region", None) or "eu-central-1"))
    except Exception as exc:  # noqa: BLE001 - reported, never fatal for the tick
        return {"cosigned": [], "skipped": [], "w2_size": None, "error": f"{type(exc).__name__}: {exc}"}


def relay_once(*, executor_url: str, w2_url: str) -> int:
    """One relay round; returns the HTTP status from W2 and prints W2's cosignature line(s) (see the contract gap)."""
    try:
        result = relay(executor_url=executor_url, w2_url=w2_url)
    except urllib.error.HTTPError as exc:  # executor side (e.g. 404 no checkpoint yet)
        return exc.code
    for line in result.cosignatures:
        print(line)
    return result.status


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Relay the executor's latest checkpoint to W2 (litewitness).")
    ap.add_argument("--executor-url", default="http://127.0.0.1:8000")
    ap.add_argument("--w2-url", default="http://127.0.0.1:7380")
    ap.add_argument("--log-id", default="audit")
    ap.add_argument("--old-size", type=int, default=None)
    ap.add_argument("--aws-role", help="sign the cosignature upload (SigV4) as this assumed role, e.g. airgap-relay")
    ap.add_argument("--read-role", help="sign the executor reads as this role (default: --aws-role), e.g. "
                    "airgap-auditor: the executor lets only auditor/host read /audit/export")
    ap.add_argument("--w2-ssm", metavar="INSTANCE_ID", help="reach W2 on 127.0.0.1:7380 of this EC2 instance via SSM")
    ap.add_argument("--region", default=os.environ.get("AWS_REGION", "eu-central-1"))
    a = ap.parse_args(argv)
    kw: dict = {}
    if a.aws_role:
        kw["get"], kw["post"] = sigv4(a.aws_role, a.region)
    if a.read_role:
        kw["get"] = sigv4(a.read_role, a.region)[0]
    if a.w2_ssm:
        kw["w2_post"], kw["timeout"] = ssm_post(a.w2_ssm, a.region), 30.0
    r = relay(executor_url=a.executor_url, w2_url=a.w2_url, log_id=a.log_id, old_size=a.old_size, **kw)
    print(f"W2 {r.status} origin={r.origin} old={r.old_size} size={r.size} upload={r.upload_status}", file=sys.stderr)
    if r.rollback_suspected:
        print(f"ALERT: W2 already cosigned size {r.old_size} > executor size {r.size} (rollback/fork?)", file=sys.stderr)
        return 3
    if r.unverified:
        print(f"ALERT: {len(r.unverified)} W2 line(s) do not verify against AIRGAP_W2_VKEY", file=sys.stderr)
    sys.stdout.write("".join(c + "\n" for c in r.cosignatures) if r.status == 200 else r.body)
    return 0 if r.status == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main())
