# Audit log: demo lines we can say on stage

Each line below is true today and comes with the command that proves it. If the proof stops passing, the line
comes out. Owner: WS-B. Anything simulated is labelled; the last section lists what we must **not** say.

## True, with proof

| # | Say this | Proof (run it) |
|---|---|---|
| L1 | "Our Merkle tree is byte-for-byte the one Go's checksum database uses: same roots, same inclusion proofs, same consistency proofs." | `.venv/bin/pytest -q tests/test_noteverify.py::test_merkle_matches_go_tlog` (sizes 1..17, every proof, against unmodified `golang.org/x/mod/sumdb/tlog`) |
| L2 | "Our checkpoints verify with code we did not write: Go's stock `sumdb/note`." | `.venv/bin/pytest -q tests/test_noteverify.py` · `tools/noteverify/` is ~50 lines around the unmodified library |
| L3 | "An unmodified, off-the-shelf witness (litewitness) cosigns our log, and its signature verifies." | `AIRGAP_TEST_LITEWITNESS=1 .venv/bin/pytest -q tests/test_relay_w2.py::test_real_litewitness` · steps in `witness/w2/README.md` |
| L4 | "The witness refuses a forked history: same size, different tree, and it answers 422 and won't sign." | `.venv/bin/pytest -q tests/test_witness.py::test_s8_fork_refused` (S8) |
| L5 | "The refusal itself is written into the log." | `tests/test_witness.py::test_checkpointer_logs_w1_fork_refusal` (`witness_refusal` leaf, actor `checkpointer`) |
| L6 | "Flip one byte in an exported audit bundle, Wi-Fi off, and the verifier goes red and names the entry: `seq N`." | `.venv/bin/pytest -q tests/test_verify_audit.py` (one-byte edit, delete, swap, re-hash) · property test `tests/test_audit_fuzz.py::test_property_single_mutation_detected` |
| L7 | "Every decision in the log is re-run offline from its logged inputs at its logged policy hash, and must come out the same." | `tests/test_audit_fuzz.py::test_s12_replay` (real executor run: allow, deny, challenge, step-up re-check; a tampered decision is caught) (S12) |
| L8 | "The witness key and the log key are different keys; the witness never writes to the log." | `witness/witness.py` (no audit writes; trusts a pinned log key `AIRGAP_W1_LOG_VKEY`) · CONTRACTS §7.3 |
| L9 | "A payment receipt is self-contained: inclusion proof plus a cosigned checkpoint. Amount and IBAN on it are covered by the signatures." | `.venv/bin/pytest -q tests/test_receipt.py` |
| L10 | "An auditor can pin the keys: a log re-signed under other keys is rejected." | `.venv/bin/pytest -q tests/test_verify_audit.py -k "pinned or trust_keys"` |
| L11 | "Every execution is covered by a witnessed checkpoint within 60 seconds." | `tests/test_audit_fuzz.py::test_s6_checkpoint_lag` (simulated clock; on AWS the 30 s tick is EventBridge, WS-E) (S6) |

## Labelled as simulated (say the label)

- **W2** is "independent supervisor witness (simulated operator)". The software is real and unmodified litewitness,
  but we run it, not an independent supervisor.
- **W1** runs in the same AWS account as the log, under a separate role, key and table. Its independence is weaker
  than W2's, and we say so.

## Do not say (yet)

- "Every signature in the log is re-verified offline from the device text." The re-render matches `text_sha256`
  on real leaves, but accepted signature leaves are currently logged without `sig` (WS-A fix pending). Until
  `tests/test_audit_fuzz.py::test_real_executor_run_verifies` passes, the EIP-191 half of S2 is not offline-verifiable.
- "Witness checked by stock Go." Stock `sumdb/note` cannot verify the 0x04 cosignature: `noteverify` prints
  `UNCHECKED` for it. The W1 cosignature was cross-checked against torchwood once, manually; in CI it is checked by
  our Python verifier.
- "The log is in a TEE." Lambda is Firecracker isolation, not a TEE (ARCHITECTURE TB1).
- "Tamper-proof storage." S3 Object Lock is GOVERNANCE mode with 1-day retention (so teardown is possible), not COMPLIANCE.
