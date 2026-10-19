# noteverify: checkpoints checked by code we did not write

`main.go` (~45 lines) verifies an AirGap Mandates audit checkpoint using only the unmodified
[`golang.org/x/mod/sumdb/note`](https://pkg.go.dev/golang.org/x/mod/sumdb/note) package (the Go
checksum-database signed-note verifier), pinned in `go.mod`/`go.sum`. It proves that the log's
signed-note format and Ed25519 log signature are standard C2SP signed-note, not a format our own
verifier happens to agree with.

What it does and does not check:

- Log signature (vkey type `0x01`, Ed25519): verified by stock Go code.
- W1 witness cosignature (vkey type `0x04`, C2SP tlog-cosignature): stock `note` does not know this
  algorithm, so `noteverify` cannot verify it. When the note carries a signature from that supplied key, the
  tool prints `UNCHECKED <name> <keyhash>` on stdout: exit 0 means only the `OK` lines were verified, never
  the `UNCHECKED` ones. Any other bad vkey exits 2. The cosignature is verified by our Python verifier
  (`executor/audit/checkpoint.py verify_note`) and was cross-checked once, manually, against
  `filippo.io/torchwood` v0.10.0 `CosignatureVerifier`; that check is not part of CI.

`tlogcheck/main.go` is a small helper for the tests: it reads hex leaf hashes on stdin and prints
tree hashes, inclusion proofs and consistency proofs computed by the unmodified
`golang.org/x/mod/sumdb/tlog` package (RFC 6962 hashing) as JSON. `tests/test_noteverify.py`
compares them byte for byte with `executor/audit/merkle.py`.

## Build and run

Requires Go (the first build downloads `golang.org/x/mod`):

```sh
cd tools/noteverify
go build -o noteverify .
./noteverify checkpoint.txt '<log vkey>' ['<w1 vkey>' ...]   # or '-' to read the note from stdin
```

On success it prints one `OK <name> <key hash hex>` line per verified signature and exits 0; on
any failure it prints `FAIL: <error>` to stderr and exits 1. Verifier keys come from
`GET /receipts/{tx_id}` (`vkeys`) or `checkpoint.vkeys(settings)`.

Tests: `.venv/bin/pytest -q tests/test_noteverify.py` (skipped when `go` is not on PATH).
