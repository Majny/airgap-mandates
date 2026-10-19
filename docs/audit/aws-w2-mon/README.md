# AWS rehearsal pack with W2 (Mon 19 Oct 2026)

Evidence, not the stage pack: the stage pack is sealed on Tue after the freeze from a main-only deploy
(`docs/audit/demo` is the in-process pack and is unchanged).

Sealed 2026-10-19 ~17:47 CEST from the deployed stack (eu-central-1, `https://ehhxkpbfcc.execute-api.eu-central-1.amazonaws.com/prod`),
read-only as `airgap-auditor`, after a fresh reset:

1. `make demo-s1` (software keys): 4 payments, replayed signature refused (403 `nonce_reused`)
2. `make checkpoint-now`
3. `python -m witness.relay_w2 --aws-role airgap-relay --read-role airgap-auditor --w2-ssm i-0bc5865c1ddae7b1d`:
   W2 200 (old 0 -> size 47), upload 200
4. `python -m tools.demo_bundle --from-aws ...` with `AIRGAP_W2_VKEY` set: SEALED, 48 leaves, 4 checkpoints
5. `bash tools/offline_demo.sh docs/audit/aws-w2-mon`: ALL PASS (tamper caught at seq 44)

## What it shows

- The latest checkpoint (size 47, `checkpoint.txt`) and the receipt (`tx_a5eb4d7527cffa7c`, seq 44) carry **three**
  signatures: log (KMS, `05e38094`), W1 (KMS, `a2e46ba2`) and W2 (unmodified litewitness on EC2, `d10d72b1`).
- Only that checkpoint has W2: the relay ran once, after `checkpoint-now`. Checkpoints 13, 15 and 22 carry log + W1.
  `verify_audit --quorum log,w1,w2` is therefore red on those three and green on 47; the default quorum
  `log AND (w1 OR w2)` is green.
- Keys in `trust-keys.json`: log and W1 re-derived from KMS `GetPublicKey`, W2 pinned from the litewitness startup
  log (`infra/w2_ctl.sh vkey`), not from the API.

## Caveats

- Deployed `code sha256:2f1a27e1ca4cc2e8c6f2193373ad5d1bebb9d2f55815e2e548827d7b0f3069d6` was built from a branch
  that was not yet merged, and it **predates** the enroll `active` merge (main 8873c40): the 5 enroll leaves have no
  `active` field (verifier: counted as active, noted). It does not match any main commit.
- W2 is "independent supervisor witness (simulated operator)": real software, run by us.
- Stock Go `sumdb/note` checks the log signature only; W1/W2 cosignatures (type 0x04) are checked by `verify_audit`.

Re-check offline: `bash tools/offline_demo.sh docs/audit/aws-w2-mon`
