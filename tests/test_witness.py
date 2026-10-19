"""S8 witness tests (C2SP tlog-witness, CONTRACTS.md v2 §7.3, §8.2). Owner: WS-B."""
from __future__ import annotations

import base64
import hashlib
import json
import threading
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from executor.audit import checkpoint as cp
from executor.audit import kms, log, merkle
from tests.ws_b_store import FakeStore, make_settings
from witness import witness

FIXTURES = Path(__file__).resolve().parents[1] / "contracts" / "fixtures" / "witness_add_checkpoint"
POLICY, CODE = "ab" * 32, "cd" * 32


def _leaves(n: int, tag: str = "main") -> list[bytes]:
    return [merkle.leaf_hash(f"{tag}-{i}".encode()) for i in range(n)]


def _note(settings, hashes: list[bytes], *, log_id: str = "audit", root: bytes | None = None) -> str:
    o = cp.origin(log_id, settings)
    body = cp.checkpoint_body(o, len(hashes), (root or merkle.root(hashes)).hex(), policy_hash=POLICY,
                              code_sha256=CODE)
    return cp.sign_note(body, name=o, settings=settings)


def _submit(settings, store, old: int, proof: list[bytes], note: str):
    return witness.add_checkpoint(cp.add_checkpoint_request(old, proof, note), store=store, settings=settings)


def _state(settings, store):
    return store.get("witness_state", {"origin": cp.origin("audit", settings)})


def _refusals(store) -> list[dict]:
    events = [json.loads(r["event"]) for r in log.leaves("audit", store=store)]
    return [e["data"] for e in events if e["type"] == "witness_refusal"]


@pytest.fixture
def env(tmp_path):
    return make_settings(tmp_path), FakeStore()


def _prime(settings, store, hashes: list[bytes]) -> None:
    status, _, _ = _submit(settings, store, 0, [], _note(settings, hashes))
    assert status == 200


# ------------------------------------------------------------------------------------------------- S8 (named tests)

def test_s8_fork_refused(env):
    settings, store = env
    main = _leaves(4)
    _prime(settings, store, main)
    before = _state(settings, store)
    fork = _leaves(7, "fork")  # different leaves; validly log-signed; proof honestly computed from the fork itself
    status, _, body = _submit(settings, store, 4, merkle.consistency_proof(4, fork), _note(settings, fork))
    assert status == 422 and body == b"consistency proof does not verify\n"
    assert _state(settings, store) == before
    assert _refusals(store) == []  # W1 never writes the audit log (S7); the checkpointer records refusals


def test_s8_stale_409(env):
    settings, store = env
    main = _leaves(8)
    _prime(settings, store, main[:4])
    before = _state(settings, store)
    status, ctype, body = _submit(settings, store, 2, merkle.consistency_proof(2, main), _note(settings, main))
    assert (status, ctype, body) == (409, "text/x.tlog.size", b"4\n")
    status, ctype, body = _submit(settings, store, 0, [], _note(settings, main))  # client thinks witness is fresh
    assert (status, ctype, body) == (409, "text/x.tlog.size", b"4\n")
    assert _state(settings, store) == before
    assert _refusals(store) == []  # W1 never writes the audit log (S7)


# ------------------------------------------------------------------------------------------------- 200 paths

def test_200_cosignature_verifies_and_persists(env):
    settings, store = env
    hashes = _leaves(10)
    note = _note(settings, hashes[:4])
    status, ctype, body = _submit(settings, store, 0, [], note)
    assert status == 200 and ctype.startswith("text/plain")
    lines = body.decode().splitlines()
    assert len(lines) == 1 and lines[0].startswith(f"{cp.DASH} {cp.witness_name(settings)} ")
    vk = cp.vkeys(settings)
    assert cp.parse_vkey(vk["w1"])["sig_type"] == cp.SIG_COSIGNATURE
    parsed = cp.verify_note(note + body.decode(), [vk["log"], vk["w1"]])
    assert parsed["verified"][cp.origin("audit", settings)] is None
    assert isinstance(parsed["verified"][cp.witness_name(settings)], int)
    with pytest.raises(cp.NoteError):  # the cosignature commits to the body: a different body must not verify
        cp.verify_note(_note(settings, hashes[:5]) + body.decode(), [vk["w1"]])
    state = _state(settings, store)
    assert state["size"] == 4 and state["root_hash"] == merkle.root(hashes[:4]).hex()
    assert state["note"] == note + body.decode()

    note10 = _note(settings, hashes)
    status, _, body = _submit(settings, store, 4, merkle.consistency_proof(4, hashes), note10)
    assert status == 200
    cp.verify_note(note10 + body.decode(), [vk["log"], vk["w1"]])
    assert _state(settings, store)["size"] == 10
    assert _refusals(store) == []


def test_same_size_resubmission(env):
    settings, store = env
    hashes = _leaves(4)
    _prime(settings, store, hashes)
    status, _, _ = _submit(settings, store, 4, [], _note(settings, hashes))
    assert status == 200
    other = _leaves(4, "other")
    status, _, body = _submit(settings, store, 4, [], _note(settings, other))
    assert status == 422 and body == b"consistency proof does not verify\n"
    assert _state(settings, store)["root_hash"] == merkle.root(hashes).hex()


# ------------------------------------------------------------------------------------------------- refusals

def test_403_bad_log_signature(env, tmp_path):
    settings, store = env
    hashes = _leaves(3)
    note = _note(settings, hashes)
    body, sig_line = note.split("\n\n")
    name, b64 = sig_line.split(" ")[1:]
    raw = bytearray(base64.b64decode(b64))
    raw[-1] ^= 1  # known key id, broken signature
    forged = f"{body}\n\n{cp.DASH} {name} {base64.b64encode(bytes(raw)).decode()}\n"
    status, _, _ = _submit(settings, store, 0, [], forged)
    assert status == 403
    assert _state(settings, store) is None
    assert _refusals(store) == []  # W1 never writes the audit log (S7)


def test_403_unknown_key_only(env, tmp_path):
    settings, store = env
    rogue = make_settings(tmp_path / "rogue")  # same origin name, different (unknown) log key
    status, _, body = _submit(settings, store, 0, [], _note(rogue, _leaves(3)))
    assert status == 403 and b"known key" in body
    assert _state(settings, store) is None
    assert _refusals(store) == []  # W1 never writes the audit log (S7)


def test_404_unknown_origin(env):
    settings, store = env
    status, _, _ = _submit(settings, store, 0, [], _note(settings, _leaves(3), log_id="ledger"))
    assert status == 404
    assert _refusals(store) == []  # W1 never writes the audit log (S7)


def test_400_old_larger_than_size(env):
    settings, store = env
    _prime(settings, store, _leaves(4))
    status, _, body = _submit(settings, store, 9, [], _note(settings, _leaves(5)))
    assert status == 400 and b"larger" in body
    assert _refusals(store) == []  # 400 is a client error, not a refusal leaf


@pytest.mark.parametrize("request_body", [
    b"",
    b"old 0\n",  # no empty line / checkpoint
    b"old 01\n\nx\n",  # non-canonical size
    b"new 0\n\nx\n",
    b"old 0\nnot-base64!\n\nx\n",
    b"old 0\n" + base64.b64encode(b"short") + b"\n\nx\n",
    b"old 0\n" + b"".join(base64.b64encode(bytes(32)) + b"\n" for _ in range(64)) + b"\nx\n",
    b"old 0\n\nnot a checkpoint\n",
    b"\xff\xfe",
])
def test_400_malformed_request(env, request_body):
    settings, store = env
    status, _, _ = witness.add_checkpoint(request_body, store=store, settings=settings)
    assert status == 400
    assert _refusals(store) == []


def test_422_old_zero_with_proof(env):
    settings, store = env
    hashes = _leaves(4)
    status, _, body = _submit(settings, store, 0, [hashes[0]], _note(settings, hashes))
    assert status == 422 and b"empty" in body
    assert _state(settings, store) is None


def test_422_size_zero_with_non_empty_root(env):
    settings, store = env
    status, _, _ = _submit(settings, store, 0, [], _note(settings, [], root=hashlib.sha256(b"x").digest()))
    assert status == 422
    status, _, _ = _submit(settings, store, 0, [], _note(settings, []))  # the real empty-tree root is fine
    assert status == 200


# ------------------------------------------------------------------------------------------------- contract fixtures

def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


@pytest.fixture
def fixture_env(tmp_path):
    """Witness that trusts the contracts' public test log key (seed sha256('airgap-test-key:log'), contracts/build.py)
    and whose state is primed at size 36, as the fixtures assume."""
    settings = make_settings(tmp_path)
    key_dir = Path(settings.local_key_dir)
    key_dir.mkdir(parents=True)
    (key_dir / "log.ed25519").write_bytes(hashlib.sha256(b"airgap-test-key:log").digest())
    store = FakeStore()
    # Synthetic old root: the fixtures' roots and proofs are hashes of labels, not of a real tree.
    store.put("witness_state", {"origin": "airgap.example/demo/audit", "size": 36,
                                "root_hash": hashlib.sha256(b"root36").hexdigest(), "note": ""})
    return settings, store


@pytest.mark.parametrize("name", ["stale", "bad_proof"])
def test_contract_fixtures(fixture_env, name):
    settings, store = fixture_env
    fx = _fixture(name)
    status, ctype, body = witness.add_checkpoint(fx["request"].encode(), store=store, settings=settings)
    assert status == fx["status"] and body.decode() == fx["response"]
    if name == "stale":
        assert ctype == "text/x.tlog.size"
    assert store.get("witness_state", {"origin": "airgap.example/demo/audit"})["size"] == 36


def test_contract_fixture_ok_is_well_formed(fixture_env):
    """fixtures/ok.json cannot be replayed to a 200: its root and proof are synthetic hashes (no preimage tree), so any
    honest witness answers 422. Assert what is meaningful: the log signature verifies under the test key and the
    request parses; the fixture's cosignature verifies under the test W1 key."""
    settings, store = fixture_env
    fx = _fixture("ok")
    old, proof, note = witness._parse_request(fx["request"].encode())
    assert (old, len(proof)) == (36, 2)
    log_vk = witness.trusted_logs(settings)["airgap.example/demo/audit"]
    w1 = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"airgap-test-key:w1").digest())
    w1_vk = cp.verifier_key("airgap.example/demo/w1", w1.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                            cp.SIG_COSIGNATURE)
    parsed = cp.verify_note(note + fx["response"], log_vk + [w1_vk])
    assert set(parsed["verified"]) == {"airgap.example/demo/audit", "airgap.example/demo/w1"}


# ------------------------------------------------------------------------------------------------- concurrency

class RacingStore(FakeStore):
    """FakeStore whose first witness_state read in each of two threads waits for the other, so both requests pass the
    size check before either writes: only the conditional write can arbitrate."""

    def __init__(self) -> None:
        super().__init__()
        self.barrier = threading.Barrier(2, timeout=5)
        self.racing = False

    def get(self, table, key):
        if table == "witness_state" and self.racing:
            self.barrier.wait()
            self.racing = False
        return super().get(table, key)


def test_concurrent_add_checkpoint_one_wins(env):
    settings, _ = env
    store = RacingStore()
    hashes = _leaves(9)
    _prime(settings, store, hashes[:4])
    store.racing = True
    results: list[tuple[int, str, bytes]] = []

    def run(n: int) -> None:
        results.append(_submit(settings, store, 4, merkle.consistency_proof(4, hashes[:n]),
                               _note(settings, hashes[:n])))

    threads = [threading.Thread(target=run, args=(n,)) for n in (7, 9)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    statuses = sorted(r[0] for r in results)
    assert statuses == [200, 409]
    loser = next(r for r in results if r[0] == 409)
    final = _state(settings, store)
    assert loser[1] == "text/x.tlog.size" and loser[2] == f"{final['size']}\n".encode()
    assert final["size"] in (7, 9)
    assert _refusals(store) == []  # W1 never writes the audit log (S7)


# ------------------------------------------------------------------ checkpointer-side refusals and pinned log key

def test_checkpointer_logs_w1_fork_refusal(env):
    """W1 refuses (422) after its state diverges from the log; the checkpointer, not W1, appends witness_refusal."""
    settings, store = env
    for i in range(3):
        log.append(log.make_event("tool_call", {"session_id": "s", "step": i, "tool": "t", "args_sha256": "0" * 64,
                                                "result": "ok", "rule_ids": [], "untrusted_read": False},
                                  subject_id=None, actor="agent"), store=store, settings=settings, checkpoint=False)
    cp.make_checkpoint("audit", store=store, settings=settings)
    state = _state(settings, store)
    store.put("witness_state", {**state, "root_hash": "11" * 32})  # witness remembers a different tree
    for i in range(3, 6):
        log.append(log.make_event("tool_call", {"session_id": "s", "step": i, "tool": "t", "args_sha256": "0" * 64,
                                                "result": "ok", "rule_ids": [], "untrusted_read": False},
                                  subject_id=None, actor="agent"), store=store, settings=settings, checkpoint=False)
    note = cp.make_checkpoint("audit", store=store, settings=settings)
    assert cp.witness_name(settings) not in note
    events = [json.loads(r["event"]) for r in log.leaves("audit", store=store)]
    refusals = [e for e in events if e["type"] == "witness_refusal"]
    assert len(refusals) == 1 and refusals[0]["actor"] == "checkpointer"
    assert refusals[0]["data"]["status"] == 422 and refusals[0]["data"]["old_size"] == 3


def test_pinned_log_vkey(env, tmp_path):
    settings, _ = env
    other = make_settings(tmp_path / "other")
    pinned = cp.verifier_key(cp.origin("audit", other), kms.public_key(settings=other, key="log"))
    assert witness.trusted_logs(settings, {"AIRGAP_W1_LOG_VKEY": pinned}) == {cp.origin("audit", other): [pinned]}
    assert witness.trusted_logs(replace(settings, backend="aws"), {}) == {}  # AWS without a pin trusts nothing
    assert set(witness.trusted_logs(settings, {})) == {cp.origin("audit", settings), cp.origin("attest", settings)}


@pytest.mark.parametrize("old_line", ["old \u0661", "old 1\u0660"])
def test_400_non_ascii_digits(env, old_line):
    settings, store = env
    status, _, _ = witness.add_checkpoint((old_line + "\n\nx\n").encode(), store=store, settings=settings)
    assert status == 400


@pytest.mark.parametrize("mutate", [
    lambda n: n.replace("\n", "\r\n", 1),                              # control char in origin line
    lambda n: n + n[n.rindex("\n\n") + 2:],                             # duplicate signature line
    lambda n: n.replace(" airgap.example/demo/audit ", " airgap+x ", 1),  # '+' in key name
])
def test_parse_note_rejects_malformed(env, mutate):
    settings, _ = env
    body = cp.checkpoint_body(cp.origin("audit", settings), 0, hashlib.sha256(b"").hexdigest(),
                              policy_hash="0" * 64, code_sha256="0" * 64)
    note = cp.sign_note(body, name=cp.origin("audit", settings), settings=settings)
    cp.parse_note(note)
    with pytest.raises(cp.NoteError):
        cp.parse_note(mutate(note))


# ------------------------------------------------------------------ row 22b: W2 cosignature upload

def test_add_cosignature_row_22b(env, tmp_path):
    settings, store = env
    for i in range(3):
        log.append(log.make_event("tool_call", {"session_id": "s", "step": i, "tool": "t", "args_sha256": "0" * 64,
                                                "result": "ok", "rule_ids": [], "untrusted_read": False},
                                  subject_id=None, actor="agent"), store=store, settings=settings, checkpoint=False)
    original = cp.make_checkpoint("audit", store=store, settings=settings)
    size = cp.parse_note(original)["size"]
    w2 = make_settings(tmp_path / "w2")  # stand-in W2 key (real W2 = litewitness, witness/w2/README.md)
    w2_name = "supervisor.example/w2"
    w2_vkey = cp.verifier_key(w2_name, kms.public_key(settings=w2, key="w1"), cp.SIG_COSIGNATURE)
    line = cp.cosign(cp.parse_note(original)["body"], name=w2_name, settings=w2)
    pinned = {"AIRGAP_W2_VKEY": w2_vkey}

    assert cp.add_cosignature("audit", size + 99, line.encode(), store=store, settings=settings, env=pinned)[0] == 404
    assert cp.add_cosignature("audit", size, line.encode(), store=store, settings=settings, env={})[0] == 403
    forged = line[:-6] + ("A" if line[-6] != "A" else "B") + line[-5:]
    assert cp.add_cosignature("audit", size, forged.encode(), store=store, settings=settings, env=pinned)[0] == 403
    status, _, out = cp.add_cosignature("audit", size, line.encode(), store=store, settings=settings, env=pinned)
    assert status == 200 and out.decode() == original + line
    assert cp.add_cosignature("audit", size, line.encode(), store=store, settings=settings, env=pinned)[2] == out
    stored = cp.latest("audit", store=store)["note"]
    vk = cp.vkeys(settings)
    assert set(cp.verify_note(stored, [vk["log"], vk["w1"], w2_vkey])["verified"]) == {
        cp.origin("audit", settings), cp.witness_name(settings), w2_name}


# ------------------------------------------------------------------ W1 over HTTP: endpoint URL and misrouting

def test_witness_endpoint_accepts_base_or_full_url():
    base = "https://api.example/prod/witness"
    assert cp.witness_endpoint(base) == base + "/add-checkpoint"
    assert cp.witness_endpoint(base + "/add-checkpoint/") == base + "/add-checkpoint"


@pytest.mark.parametrize("reply,refusal_leaf", [
    ((403, "application/json", b'{"message":"Missing Authentication Token"}'), False),  # API Gateway, not W1
    ((403, "text/plain; charset=utf-8", b"no signature from a known key\n"), True),     # W1's own refusal
])
def test_only_real_w1_refusals_are_logged(env, monkeypatch, reply, refusal_leaf):
    settings, store = env
    monkeypatch.setattr(cp, "_submit_w1", lambda *a, **k: reply)
    for i in range(2):
        log.append(log.make_event("tool_call", {"session_id": "s", "step": i, "tool": "t", "args_sha256": "0" * 64,
                                                "result": "ok", "rule_ids": [], "untrusted_read": False},
                                  subject_id=None, actor="agent"), store=store, settings=settings, checkpoint=False)
    note = cp.make_checkpoint("audit", store=store, settings=settings)
    assert cp.witness_name(settings) not in note
    events = [json.loads(r["event"]) for r in log.leaves("audit", store=store)]
    assert any(e["type"] == "witness_refusal" for e in events) is refusal_leaf
    assert events[-1]["type"] == "checkpoint" and events[-1]["data"]["cosigners"] == []


def test_aws_backend_never_falls_back_to_a_local_key(tmp_path):
    s = replace(make_settings(tmp_path), backend="aws", kms_key_id="k-log", witness_kms_key_id=None)
    with pytest.raises(kms.KeyNotConfigured, match="AIRGAP_WITNESS_KMS_KEY_ID"):
        kms.public_key(settings=s, key="w1")
    with pytest.raises(kms.KeyNotConfigured, match="AIRGAP_KMS_KEY_ID"):
        kms.sign_ed25519(b"x", settings=replace(s, kms_key_id=None), key="log")
    assert not (tmp_path / "keys").exists()
