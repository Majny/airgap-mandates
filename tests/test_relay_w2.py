"""W2 relay tests against local http.server fakes of the executor API and of W2. CONTRACTS.md v2 §7.3. Owner: WS-B.

The W2 fake is a STAND-IN: our own W1 code (witness.add_checkpoint) with its own key dir and store, not litewitness.
test_real_litewitness runs the unmodified upstream litewitness (opt-in: AIRGAP_TEST_LITEWITNESS=1, needs go + ssh-agent).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from executor.audit import checkpoint as cp
from executor.audit import kms, log
from tests.ws_b_store import FakeStore, make_settings
from witness import relay_w2, witness

ORIGIN = "airgap.example/demo/audit"


@contextmanager
def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def _executor_handler(store, settings, tamper=None, w2_env=None):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, status, ctype, body: bytes):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):  # row 22b, as WS-A wires it: checkpoint.add_cosignature
            u = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(u.query)
            if u.path != "/checkpoint/cosignature":
                return self._send(404, "text/plain", b"not found\n")
            body = self.rfile.read(int(self.headers["Content-Length"]))
            status, ctype, out = cp.add_cosignature(q["log_id"][0], int(q["size"][0]), body, store=store,
                                                    settings=settings, env=w2_env or {})
            self._send(status, ctype, out)

        def do_GET(self):
            u = urllib.parse.urlparse(self.path)
            log_id = urllib.parse.parse_qs(u.query).get("log_id", ["audit"])[0]
            if u.path == "/checkpoint":
                row = cp.latest(log_id, store=store)
                return self._send(200, "text/plain; charset=utf-8", row["note"].encode()) if row else \
                    self._send(404, "application/json", b'{"error":"not_found"}')
            if u.path == "/audit/export":
                body = log.export(log_id, store=store, settings=settings)
                if tamper:
                    tamper(body)
                return self._send(200, "application/json", json.dumps(body).encode())
            self._send(404, "text/plain", b"not found\n")
    return H


def _w2_standin_handler(store, settings, seen):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            seen.append(body)
            if self.path != "/add-checkpoint":
                status, ctype, out = 404, "text/plain", b"not found\n"
            else:
                status, ctype, out = witness.add_checkpoint(body, store=store, settings=settings)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
    return H


def _grow(store, settings, n: int) -> None:
    for i in range(n):
        log.append(log.make_event("witness_refusal", {"witness": "test", "status": 409, "old_size": i, "size": i},
                                  subject_id=None, actor="witness"), store=store, settings=settings, checkpoint=False)
    log.tick("audit", store=store, settings=settings)


@pytest.fixture
def world(tmp_path, monkeypatch):
    """Executor (own log key, W1 in-process) + W2 stand-in (own key dir and store, trusts the executor's log key)."""
    ex_settings, ex_store = make_settings(tmp_path / "executor"), FakeStore()
    w2_settings, w2_store = make_settings(tmp_path / "w2", log_origin="supervisor.example"), FakeStore()
    real_trusted = witness.trusted_logs
    monkeypatch.setattr(witness, "trusted_logs",
                        lambda s: real_trusted(ex_settings) if s is w2_settings else real_trusted(s))
    monkeypatch.setattr(relay_w2, "_known_size", {})
    return ex_settings, ex_store, w2_settings, w2_store


def _w2_vkey(w2_settings) -> str:
    return cp.verifier_key(cp.witness_name(w2_settings), kms.public_key(settings=w2_settings, key="w1"),
                           cp.SIG_COSIGNATURE)


def test_relay_happy_path_and_remembered_size(world, capsys):
    ex_settings, ex_store, w2_settings, w2_store = world
    _grow(ex_store, ex_settings, 5)
    seen: list[bytes] = []
    with _serve(_executor_handler(ex_store, ex_settings)) as ex_url, \
            _serve(_w2_standin_handler(w2_store, w2_settings, seen)) as w2_url:
        assert relay_w2.relay_once(executor_url=ex_url, w2_url=w2_url) == 200
        note = cp.latest("audit", store=ex_store)["note"]
        cosig = capsys.readouterr().out
        assert cosig.startswith(f"{cp.DASH} {cp.witness_name(w2_settings)} ")
        body = note.split("\n\n")[0] + "\n"
        log_line = next(x for x in note.splitlines() if x.startswith(f"{cp.DASH} {ORIGIN} "))
        parsed = cp.verify_note(f"{body}\n{log_line}\n{cosig}", [cp.vkeys(ex_settings)["log"], _w2_vkey(w2_settings)])
        assert isinstance(parsed["verified"][cp.witness_name(w2_settings)], int)
        assert seen[0].startswith(b"old 0\n\n")
        assert b"/w1 " not in seen[0]  # W1's cosignature is not forwarded, only the log signature
        size1 = w2_store.get("witness_state", {"origin": ORIGIN})["size"]

        _grow(ex_store, ex_settings, 4)
        r = relay_w2.relay(executor_url=ex_url, w2_url=w2_url)
        assert r.status == 200 and r.old_size == size1 and r.size > size1
        assert seen[1].startswith(f"old {size1}\n".encode()) and len(seen) == 2
        assert w2_store.get("witness_state", {"origin": ORIGIN})["size"] == r.size


def test_relay_409_retries_once_with_w2_size(world):
    ex_settings, ex_store, w2_settings, w2_store = world
    seen: list[bytes] = []
    with _serve(_executor_handler(ex_store, ex_settings)) as ex_url, \
            _serve(_w2_standin_handler(w2_store, w2_settings, seen)) as w2_url:
        _grow(ex_store, ex_settings, 3)
        assert relay_w2.relay_once(executor_url=ex_url, w2_url=w2_url) == 200
        size1 = w2_store.get("witness_state", {"origin": ORIGIN})["size"]
        relay_w2._known_size.clear()  # a fresh relay process does not know W2's size
        _grow(ex_store, ex_settings, 3)
        r = relay_w2.relay(executor_url=ex_url, w2_url=w2_url)
        assert r.status == 200 and r.old_size == size1
        assert [s.split(b"\n", 1)[0] for s in seen[1:]] == [b"old 0", f"old {size1}".encode()]


def test_relay_reports_w2_fork_refusal(world):
    ex_settings, ex_store, w2_settings, w2_store = world
    _grow(ex_store, ex_settings, 3)
    # W2 already holds a different tree of the same size as the executor's checkpoint
    size = cp.latest("audit", store=ex_store)["size"]
    w2_store.put("witness_state", {"origin": ORIGIN, "size": size, "root_hash": "00" * 32, "note": ""})
    with _serve(_executor_handler(ex_store, ex_settings)) as ex_url, \
            _serve(_w2_standin_handler(w2_store, w2_settings, [])) as w2_url:
        r = relay_w2.relay(executor_url=ex_url, w2_url=w2_url, old_size=size)
    assert r.status == 422 and r.cosignatures == []


def test_relay_flags_w2_rollback(world):
    """W2 already cosigned a larger tree than the executor serves: no resubmission, rollback flagged."""
    ex_settings, ex_store, w2_settings, w2_store = world
    _grow(ex_store, ex_settings, 3)
    size = cp.latest("audit", store=ex_store)["size"]
    w2_store.put("witness_state", {"origin": ORIGIN, "size": size + 50, "root_hash": "00" * 32, "note": ""})
    seen: list[bytes] = []
    with _serve(_executor_handler(ex_store, ex_settings)) as ex_url, \
            _serve(_w2_standin_handler(w2_store, w2_settings, seen)) as w2_url:
        r = relay_w2.relay(executor_url=ex_url, w2_url=w2_url)
    assert r.status == 409 and r.rollback_suspected and r.old_size == size + 50 and len(seen) == 1


def test_relay_keeps_only_lines_verifying_against_w2_vkey(world, tmp_path):
    ex_settings, ex_store, w2_settings, w2_store = world
    _grow(ex_store, ex_settings, 3)
    wrong = _w2_vkey(make_settings(tmp_path / "someone-else"))
    with _serve(_executor_handler(ex_store, ex_settings)) as ex_url, \
            _serve(_w2_standin_handler(w2_store, w2_settings, [])) as w2_url:
        good = relay_w2.relay(executor_url=ex_url, w2_url=w2_url, w2_vkey=_w2_vkey(w2_settings))
        relay_w2._known_size.clear()
        w2_store.tables["witness_state"].clear()
        bad = relay_w2.relay(executor_url=ex_url, w2_url=w2_url, w2_vkey=wrong)
    assert good.status == 200 and len(good.cosignatures) == 1 and good.unverified == []
    assert bad.status == 200 and bad.cosignatures == [] and len(bad.unverified) == 1


def test_relay_uploads_w2_cosignature_row_22b(world):
    ex_settings, ex_store, w2_settings, w2_store = world
    _grow(ex_store, ex_settings, 3)
    w2_vkey = _w2_vkey(w2_settings)
    with _serve(_executor_handler(ex_store, ex_settings, w2_env={"AIRGAP_W2_VKEY": w2_vkey})) as ex_url, \
            _serve(_w2_standin_handler(w2_store, w2_settings, [])) as w2_url:
        r = relay_w2.relay(executor_url=ex_url, w2_url=w2_url, w2_vkey=w2_vkey)
    assert r.status == 200 and r.upload_status == 200
    stored = cp.latest("audit", store=ex_store)["note"]
    vk = cp.vkeys(ex_settings)
    assert cp.witness_name(w2_settings) == "supervisor.example/w1"  # distinct from the executor's W1 name
    assert set(cp.verify_note(stored, [vk["log"], vk["w1"], w2_vkey])["verified"]) == {
        cp.origin("audit", ex_settings), cp.witness_name(ex_settings), cp.witness_name(w2_settings)}


def test_relay_once_returns_executor_error(world):
    ex_settings, ex_store, w2_settings, w2_store = world  # no checkpoint yet -> executor 404
    with _serve(_executor_handler(ex_store, ex_settings)) as ex_url, \
            _serve(_w2_standin_handler(w2_store, w2_settings, [])) as w2_url:
        assert relay_w2.relay_once(executor_url=ex_url, w2_url=w2_url) == 404


def test_relay_refuses_export_that_contradicts_checkpoint(world):
    ex_settings, ex_store, w2_settings, w2_store = world
    _grow(ex_store, ex_settings, 3)

    def tamper(body):
        body["leaves"][0]["leaf_hash"] = "11" * 32

    seen: list[bytes] = []
    with _serve(_executor_handler(ex_store, ex_settings, tamper)) as ex_url, \
            _serve(_w2_standin_handler(w2_store, w2_settings, seen)) as w2_url:
        with pytest.raises(ValueError, match="do not reproduce"):
            relay_w2.relay_once(executor_url=ex_url, w2_url=w2_url)
    assert seen == []


# ------------------------------------------------------------------------------------- real litewitness (opt-in)

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _litewitness_bins(workdir: Path) -> Path:
    """$AIRGAP_LITEWITNESS_BIN (dir with litewitness + witnessctl) or `go install ...@v0.10.0` into workdir/bin."""
    if os.environ.get("AIRGAP_LITEWITNESS_BIN"):
        return Path(os.environ["AIRGAP_LITEWITNESS_BIN"])
    bindir = workdir / "bin"
    subprocess.run(["go", "install", "filippo.io/torchwood/cmd/litewitness@v0.10.0",
                    "filippo.io/torchwood/cmd/witnessctl@v0.10.0"], check=True, timeout=600,
                   env={**os.environ, "GOBIN": str(bindir)}, capture_output=True)
    return bindir


@pytest.mark.skipif(os.environ.get("AIRGAP_TEST_LITEWITNESS") != "1" or shutil.which("go") is None
                    or shutil.which("ssh-agent") is None, reason="opt-in: AIRGAP_TEST_LITEWITNESS=1, go, ssh-agent")
def test_real_litewitness(tmp_path):
    """Unmodified litewitness v0.10.0 ("independent supervisor witness (simulated operator)") cosigns our checkpoint
    (with its policy/code extension lines), and the cosignature verifies with our 0x04 verifier."""
    settings, store = make_settings(tmp_path / "executor"), FakeStore()
    _grow(store, settings, 5)
    work = Path(tempfile.mkdtemp(prefix="lw", dir="/tmp"))  # short path: unix socket names are <= 104 bytes
    procs: list[subprocess.Popen] = []
    try:
        bins = _litewitness_bins(work)
        sock, db, key = work / "a.sock", work / "w2.db", work / "w2key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "airgap-w2", "-f", str(key)], check=True)
        procs.append(subprocess.Popen(["ssh-agent", "-D", "-a", str(sock)], stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL))
        for _ in range(50):
            if sock.exists():
                break
            time.sleep(0.1)
        subprocess.run(["ssh-add", str(key)], check=True, env={**os.environ, "SSH_AUTH_SOCK": str(sock)},
                       capture_output=True)
        fp = subprocess.run(["ssh-keygen", "-lf", f"{key}.pub", "-E", "sha256"], check=True, capture_output=True,
                            text=True).stdout.split()[1]
        subprocess.run([bins / "witnessctl", "add-log", "-db", db, "-origin", ORIGIN], check=True, capture_output=True)
        subprocess.run([bins / "witnessctl", "add-key", "-db", db, "-origin", ORIGIN, "-key", cp.vkeys(settings)["log"]],
                       check=True, capture_output=True)
        port = _free_port()
        lw_log = work / "litewitness.log"
        with open(lw_log, "wb") as out:
            procs.append(subprocess.Popen([bins / "litewitness", "-db", db, "-name", "airgap.example/demo/w2",
                                           "-key", fp, "-ssh-agent", sock, "-listen", f"127.0.0.1:{port}"],
                                          stdout=out, stderr=subprocess.STDOUT))
        vkey = None
        for _ in range(100):
            m = re.search(r"vkey=(\S+)", lw_log.read_text())
            if m and "msg=listening" in lw_log.read_text():
                vkey = m.group(1)
                break
            time.sleep(0.1)
        assert vkey, lw_log.read_text()
        assert cp.parse_vkey(vkey)["sig_type"] == cp.SIG_COSIGNATURE

        with _serve(_executor_handler(store, settings)) as ex_url:
            relay_w2._known_size.clear()
            r1 = relay_w2.relay(executor_url=ex_url, w2_url=f"http://127.0.0.1:{port}")
            assert r1.status == 200, r1.body
            _grow(store, settings, 4)
            relay_w2._known_size.clear()  # forces the 409 text/x.tlog.size round trip against real litewitness
            r2 = relay_w2.relay(executor_url=ex_url, w2_url=f"http://127.0.0.1:{port}")
            assert r2.status == 200 and r2.old_size == r1.size, r2.body
        note = cp.latest("audit", store=store)["note"]
        body = note.split("\n\n")[0] + "\n"
        log_line = next(x for x in note.splitlines() if x.startswith(f"{cp.DASH} {ORIGIN} "))
        parsed = cp.verify_note(f"{body}\n{log_line}\n" + "".join(c + "\n" for c in r2.cosignatures),
                                [cp.vkeys(settings)["log"], vkey])
        assert isinstance(parsed["verified"]["airgap.example/demo/w2"], int)
        assert parsed["extensions"][0].startswith("policy sha256:")
    finally:
        for p in procs:
            p.terminate()
            p.wait(5)
        shutil.rmtree(work, ignore_errors=True)


def test_relay_uses_injected_transports(world):
    """AWS path: reads, upload and W2 delivery go through the given callables (sigv4() / ssm_post())."""
    ex_settings, ex_store, w2_settings, w2_store = world
    _grow(ex_store, ex_settings, 3)
    calls: list[tuple[str, str]] = []

    def get(url, timeout):
        calls.append(("get", url))
        return relay_w2._get(url, timeout)

    def post(url, data, timeout):
        calls.append(("post", url))
        return relay_w2._post(url, data, timeout)

    with _serve(_executor_handler(ex_store, ex_settings)) as ex_url, \
            _serve(_w2_standin_handler(w2_store, w2_settings, [])) as w2_real:
        def w2_post(url, data, timeout):  # "http://w2" is never dialled: only the path is used, as over SSM
            calls.append(("w2", url))
            return relay_w2._post(w2_real + "/add-checkpoint", data, timeout)

        r = relay_w2.relay(executor_url=ex_url, w2_url="http://w2", w2_vkey=_w2_vkey(w2_settings),
                           get=get, post=post, w2_post=w2_post)
    assert r.status == 200 and r.cosignatures
    assert [k for k, _ in calls] == ["get", "get", "w2", "post"]
    assert calls[2][1] == "http://w2/add-checkpoint" and "/checkpoint/cosignature?" in calls[3][1]


@pytest.mark.parametrize("raw, want", [
    (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\xe2\x80\x94 w2 AAAA\n",
     (200, "text/plain; charset=utf-8", b"\xe2\x80\x94 w2 AAAA\n")),
    (b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 409 Conflict\r\nContent-Type: text/x.tlog.size\r\n\r\n12\n",
     (409, "text/x.tlog.size", b"12\n")),
    (b"HTTP/1.1 422 Unprocessable Entity\nContent-Length: 0\n\n", (422, "", b"")),
])
def test_parse_http_response(raw, want):
    assert relay_w2.parse_http_response(raw) == want


@pytest.mark.parametrize("raw", [b"", b"curl: (7) Failed to connect", b"HTTP/1.1 200 OK\r\nContent-Type: x"])
def test_parse_http_response_rejects_garbage(raw):
    with pytest.raises(ValueError):
        relay_w2.parse_http_response(raw)


def test_export_publishes_w2_vkey_from_env(world, monkeypatch):
    ex_settings, ex_store, w2_settings, _ = world
    _grow(ex_store, ex_settings, 1)
    monkeypatch.delenv("AIRGAP_W2_VKEY", raising=False)
    assert log.export("audit", store=ex_store, settings=ex_settings)["pubkeys"]["w2"] is None
    monkeypatch.setenv("AIRGAP_W2_VKEY", _w2_vkey(w2_settings))
    assert log.export("audit", store=ex_store, settings=ex_settings)["pubkeys"]["w2"] == _w2_vkey(w2_settings)
