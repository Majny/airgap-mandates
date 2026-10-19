# W2: independent supervisor witness (simulated operator)

W2 is **unmodified upstream litewitness** from `filippo.io/torchwood` v0.10.0 (`cmd/litewitness`). In the demo we run
it ourselves on its own EC2 instance with its own key, standing in for an independent supervisor; the operator is
simulated, the software is not. It speaks C2SP tlog-witness: `POST /add-checkpoint` at the root of its listener
(W1 serves the same protocol at `/witness/add-checkpoint`).

Verified locally (Go 1.27, macOS): litewitness accepts our checkpoints including the `policy sha256:` /
`code sha256: ... pcr0 -` extension lines, answers 409 `text/x.tlog.size` to a stale `old` size, and its
cosignature verifies with `executor/audit/checkpoint.verify_note` and its logged `0x04` verifier key.
Test: `AIRGAP_TEST_LITEWITNESS=1 .venv/bin/pytest -q tests/test_relay_w2.py::test_real_litewitness`.

## Build

```sh
GOBIN=$PWD/.local/w2/bin go install filippo.io/torchwood/cmd/litewitness@v0.10.0 filippo.io/torchwood/cmd/witnessctl@v0.10.0
```

## Key (ssh-agent; litewitness never reads a key file itself)

```sh
W=/tmp/w2   # keep it short: the agent socket path must fit in a unix socket name (104 bytes on macOS)
mkdir -p $W
ssh-keygen -q -t ed25519 -N "" -C airgap-w2 -f $W/w2key
ssh-agent -D -a $W/a.sock &                         # dedicated agent for litewitness
SSH_AUTH_SOCK=$W/a.sock ssh-add $W/w2key
FP=$(ssh-keygen -lf $W/w2key.pub -E sha256 | awk '{print $2}')   # SHA256:...
```

## Trust the executor's log key

The log verifier key is `pubkeys.log` from `GET /audit/export?log_id=audit` (or `checkpoint.vkeys(settings)["log"]`).

```sh
LOG_VKEY=$(curl -s "$EXECUTOR/audit/export?log_id=audit" | python3 -c 'import json,sys;print(json.load(sys.stdin)["pubkeys"]["log"])')
.local/w2/bin/witnessctl add-log -db $W/w2.db -origin airgap.example/demo/audit
.local/w2/bin/witnessctl add-key -db $W/w2.db -origin airgap.example/demo/audit -key "$LOG_VKEY"
```

## Run

```sh
.local/w2/bin/litewitness -db $W/w2.db -name airgap.example/demo/w2 -key "$FP" -ssh-agent $W/a.sock -listen 127.0.0.1:7380
```

The startup log prints `verifier key vkey=airgap.example/demo/w2+<id>+<base64(0x04||pub)>`; that string is W2's
cosigner vkey (configure it as `w2` for `tools/verify_audit.py` / the export `pubkeys.w2`). On EC2, terminate TLS in
front of it and expose only `/add-checkpoint`.

## Relay

```sh
.venv/bin/python -m witness.relay_w2 --executor-url $EXECUTOR --w2-url http://127.0.0.1:7380
```

Fetches `GET /checkpoint?log_id=audit` and `GET /audit/export?log_id=audit`, checks that the exported leaves reproduce
the checkpoint root, forwards the note with only the log signature, computes the consistency proof from the last size
W2 accepted (on 409 it reads `text/x.tlog.size` and retries once) and prints W2's cosignature line(s).

**Gap:** the executor has no endpoint to store W2's cosignature in its checkpoint note, so the cosignature is printed,
not uploaded; W2 therefore does not yet appear in `GET /checkpoint` or in receipts. The relay remembers W2's size only
in-process.
