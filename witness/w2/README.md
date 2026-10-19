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
W2 accepted (on 409 it reads `text/x.tlog.size` and retries once), keeps only W2 lines that verify against
`AIRGAP_W2_VKEY`, and uploads them with `POST /checkpoint/cosignature` (row 22b; the executor re-verifies them against
its own `AIRGAP_W2_VKEY` and appends them to the stored note). The relay remembers W2's size only in-process.

## On AWS

W2 runs on the `airgap-w2` t4g.nano (`infra/w2_userdata.sh`, `infra/w2_ctl.sh`; owner WS-E), listening on
127.0.0.1:7380 only, no inbound port. From a laptop with `AWS_PROFILE=hackathon`:

```sh
AIRGAP_W2_VKEY='airgap.example/demo/w2+d10d72b1+BMkDZNJkVEhYYAhvvLF7aV31FiFFRPg2PUPSI9/6v44B' \
.venv/bin/python -m witness.relay_w2 --executor-url https://ehhxkpbfcc.execute-api.eu-central-1.amazonaws.com/prod \
  --aws-role airgap-relay --read-role airgap-auditor --w2-ssm i-0bc5865c1ddae7b1d
```

- `--aws-role airgap-relay` signs the upload (SigV4); `--read-role airgap-auditor` signs the reads (the executor lets
  only auditor/host read `/audit/export`).
- `--w2-ssm` delivers the add-checkpoint request with SSM RunCommand (`curl` to 127.0.0.1:7380 on the instance), so
  no session-manager plugin and no open port are needed. It uses the operator's own credentials, not the relay role.
  With the plugin, `infra/w2_ctl.sh forward` + `--w2-url http://127.0.0.1:7380` works too.
- **Every checkpoint (checkpointer hook).** `witness.relay_w2.after_tick(log_id, store=, settings=)` runs in the
  checkpointer λ right after `log.tick`: it sends every stored checkpoint W2 has not cosigned yet, oldest first, over
  SSM, and appends W2's verified lines to the stored note (`checkpoint.add_cosignature`, the row 22b check). Off unless
  `AIRGAP_W2_INSTANCE_ID` and `AIRGAP_W2_VKEY` are set; never raises (a W2 outage leaves checkpoints log + W1, caught
  up on the next tick). A size W2 has already passed can never be cosigned and is reported as `skipped`.
- A demo reset (`infra/reset_state.py` empties W1's `witness_state`) must also reset W2's database, or W2 answers
  409 with the old, larger size and the relay reports `rollback_suspected` (exit 3). That is the correct behaviour
  of a real witness: an independent supervisor would never accept a reset log.
