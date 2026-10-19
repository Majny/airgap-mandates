# AirGap Mandates: audit log handout for supervisors and auditors

One page. Hackathon prototype; companies, accounts and invoices are fictitious. Anything simulated is labelled.
`[U]` = not yet verified against the legal text or a mentor; treat it as a pointer, not a claim.

## 1. What is logged, and what each entry proves

One append-only log per deployment (`audit`). Each entry is canonical JSON, hashed into an RFC 9162 Merkle tree
(the hash tree Certificate Transparency and Go's checksum database use). Decision entries carry the policy hash and
digests of the exact inputs.

| Entries | What they let you check |
|---|---|
| `enroll` | Which device key may approve, in which role, genuine device or emulator, and whether it is still active (deactivation is a later `enroll` entry with `active: false`) |
| `ingest`, `proposal`, `facts` | Which email/document (hash, DKIM result) a payment proposal came from, what the AI agent proposed verbatim, and which facts the executor computed |
| `decision` | Allow / deny / step-up, the rule ids and the policy hash. Its full inputs are logged, so the decision is **re-run offline** and must come out the same |
| `challenge`, `signature`, `mandate_signed` | The exact text a person approved on the hardware device (re-rendered offline from template + parameters, hash compared) and the device signature over it (signer recovered offline) |
| `execution`, `rail_submitted` | Payee account, amount, currency and the authorisation it ran under (mandate or a signed one-off approval); the payment file hash (rail is a mock in the demo) |
| `state_transition`, `change_event`, `attestation` | Each step of a payee bank-account change: attestations, callback, cooling-off, two approvers |
| `tool_call`, `egress_block` | What the AI agent tried and what was blocked |
| `checkpoint`, `anchor`, `witness_refusal` | Signed tree heads, their copies in write-once storage, and any witness that refused (e.g. a forked history) |

## 2. Verify offline in 3 commands

Get the public keys **out of band**, not from the bundle: the log key and the in-house witness key from the bank's
key service (on AWS: KMS `GetPublicKey`), the external witness key from its operator. Put them in `trust-keys.json`.
Then, with Wi-Fi off:

```sh
.local/bin/noteverify checkpoint.txt "$LOG_KEY" "$W1_KEY" "$W2_KEY"      # 1. stock Go sumdb/note checks the log signature
python -m tools.verify_audit bundle.json --trust-keys trust-keys.json --quorum log,w1,w2   # 2. whole log
python -m tools.verify_audit bundle.json --receipt receipt.json --trust-keys trust-keys.json # 3. one payment
```

1. Code we did not write (`golang.org/x/mod/sumdb/note`) confirms the log signature on the latest tree head.
2. Every entry hash, every tree root, consistency between successive tree heads, the signature quorum on each,
   every decision re-run, every approval re-rendered and its signer recovered, 2-of-2 rules, nothing uncovered. Any
   edit, deletion or reordering fails and names the entry (`seq N`).
3. A single payment receipt (also as a QR pointer) against the signed tree.

`bash tools/offline_demo.sh <dir>` runs all three plus a one-byte tamper that must fail. Evidence packs from AWS:
`docs/audit/aws-main-mon/`.

## 3. What the witnesses add, and their limits

A witness co-signs a tree head only if it is a consistent extension of the last one it saw (C2SP tlog-witness). The
operator therefore cannot show one history to the auditor and another to someone else, or rewrite the past, without
a witness refusing; the refusal is logged.

- **W1** (KMS key, own role and table) runs **in the same AWS account** as the log. It stops mistakes and a
  compromised executor role; it does not stop the account owner.
- **W2** is unmodified open-source software (`litewitness`) on its own machine with its own key, standing in for an
  independent supervisor. The operator is **simulated**: we run it. In production the supervisor or an independent
  party would run it, and our verifier already accepts its key.
- Witnesses prove consistency, not truth: a false entry written consistently is still false.
- On the main AWS deploy every tree head carries log + W1 + W2 (`docs/audit/aws-main-mon/`). If W2 is unreachable,
  a tree head carries log + W1 until the next tick catches it up.

## 4. "Aligned with" (never "compliant")

| Text | How the prototype relates | Status |
|---|---|---|
| DORA, Commission Delegated Regulation (EU) 2024/1774 (RTS on ICT risk management), Art. 12 Logging | Tamper-evident logging of ICT and decision events, protected against modification, verifiable by a third party | Article per our plan; detailed mapping pending mentor review [U] |
| PSD2 RTS on SCA, Commission Delegated Regulation (EU) 2018/389, Art. 5 Dynamic linking | The approver's device shows payee account and amount; the signature covers exactly that text; the log lets an auditor re-check it. The device approval is **not** presented as an SCA solution | Article confirmed in our architecture sources |
| EU AI Act, Regulation (EU) 2024/1689, human oversight (Art. 14 [U]) | The AI agent cannot move money; a person decides over-cap or new-account payments on a device; every agent action is logged | Design analogy; we do not claim the agent is a high-risk system |

## 5. What this does NOT prove

- **Completeness before logging.** The log shows what the executor recorded. Execution entries are written in the same
  transaction as the ledger, but the bundle does not carry the bank's ledger, so ledger ↔ log reconciliation is not
  part of the offline check.
- **That the payment reached the payee.** The rail is a mock; `rail_submitted` records our payment file, not settlement.
- **That the invoice is genuine.** An inflated invoice to a known payee inside a signed mandate is bounded by caps
  and duplicate rules, not prevented.
- **That a human read the screen.** Only that this device key signed exactly this text.
- **Independence.** W1 shares the account; W2 is run by us. Keys shipped next to a demo bundle prove nothing by
  themselves: get them out of band.
- **Execution environment.** The executor is AWS Lambda (Firecracker isolation, not a TEE); the code hash in each
  tree head is self-reported (`pcr0 -`).
- **Retention.** Write-once copies use S3 Object Lock GOVERNANCE, 1 day (so the demo can be torn down), not COMPLIANCE.
- **Privacy.** The export contains full account numbers; a redacted export is not implemented.
