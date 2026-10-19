# AWS pack from a main-only deploy, every checkpoint cosigned by both witnesses (Mon 19 Oct 2026)

Evidence. The stage pack is sealed on Tue after the freeze; `docs/audit/demo` (in-process pack) is unchanged.

Deployed by WS-E from a clean `origin/main` worktree at `03d1b55` (no local changes; `cdk.context.json` identical to
main). Every checkpoint note carries
`code sha256:dec242c4a1d442936a09b4b217a5465fc33c1356d0b34dda3bdb6946507a92b0 pcr0 -`, the hash of the Lambda zip
built from that worktree (= `/health` `code_sha256`).

Run (2026-10-19 evening, eu-central-1), after `infra.reset_state` (incl. W2 reset) + `load_inbox`:

1. `make demo-s1` (software keys): 4 payments, replayed signature refused (403 `nonce_reused`)
2. `make checkpoint-now`: the checkpointer signed (KMS log key), W1 cosigned (KMS W1 key), and in the same
   invocation `witness.relay_w2.after_tick` sent the checkpoint over SSM to W2 (unmodified litewitness on EC2), which
   cosigned: `"w2": {"cosigned": [44], "skipped": [], "error": null}`. No manual relay.
3. `python -m tools.demo_bundle --from-aws ...` (read-only, `airgap-auditor`, `AIRGAP_W2_VKEY` pinned): SEALED,
   46 leaves, 3 checkpoints, receipt `tx_f2cf27603fa01320` (seq 41, tree size 45)
4. `QUORUM=log,w1,w2 bash tools/offline_demo.sh docs/audit/aws-main-mon`: ALL PASS (tamper caught at seq 41)

## What it shows

- **All 3 checkpoints (sizes 13, 44, 45) carry log + W1 + W2**; `verify_audit --quorum log,w1,w2` is green on every
  one (`checkpoint_sig_w2=3`), consistency between them verifies, no uncovered leaf.
- The receipt's checkpoint carries the same three signatures.
- Enroll leaves carry `active` (the seeded emulator clerk is `active: false`); 5 approvers, 5 decisions replayed.
- Keys (`trust-keys.json`): log + W1 re-derived from KMS `GetPublicKey`; W2 pinned from the litewitness startup log
  (`infra/w2_ctl.sh vkey`); `/audit/export` `pubkeys.w2` and `/health` agree.

## Caveats

- W2 is "independent supervisor witness (simulated operator)": real, unmodified software, run by us.
- Stock Go `sumdb/note` checks the log signature only; W1/W2 cosignatures (type 0x04) are checked by `verify_audit`.
- If W2/SSM is down during a tick, that checkpoint stays log + W1 until the next tick catches it up; a size W2 has
  already passed can never be cosigned (reported as `skipped` in the checkpointer output).
