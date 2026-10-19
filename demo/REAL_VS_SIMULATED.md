# Real vs simulated (said out loud; ARCHITECTURE §12, updated Mon 19 Oct evening)

Every "real" line points to evidence in this repo. Anything not listed as real is simulated, and the screen labels it.

| Real (evidence) | Simulated / not yet (labelled on screen) |
|---|---|
| **Physical Trezor Safe 3** (T2B1) as clerk; Optiga certificate chain verified at enrolment, `device=GENUINE` (`docs/device/enroll_clerk_physical.json`). EIP-191 text shown on the device, physical confirm, signature recovered by the executor | **Treasury** approver on the emulator, `device=EMULATOR` (`docs/device/enroll_treasury_emulator.json`). The prod profile refuses it; the demo profile allows it with a label. The architecture targets a Safe 5; the device on stage is a Safe 3 (`docs/device/measurements.md`) |
| **Executor on AWS eu-central-1**: Lambda behind API Gateway with IAM auth, DynamoDB, one role per function (`infra/evidence/outputs.json`). S1 end to end green on AWS (`infra/evidence/aws_e2e.txt`) | Companies, domains, accounts, inbox, invoices and the DKIM DNS snapshot are fictitious |
| **IAM split, proven**: the agent role gets explicitDeny on the ledger/mandates/audit/registry tables, `kms:Sign`, secrets, `/signatures` and `/mandates` (`infra/evidence/iam_simulate.txt`) | Supplier ERP and supplier bank issuers: real SD-JWT VC cryptography, simulated organisations (DEMO-ONLY keys in `data/issuer_keys/`) |
| **Agent VPC with no route out**: `example.com` and `checkip` unreachable, `no_route: true` (`infra/evidence/s10_probe.json`) | VoP responder is a mock with EPC codes (`data/vop_mock.json`); VoP for CZK applies later [U] |
| **KMS Ed25519** log key and W1 witness key (`ECC_NIST_EDWARDS25519`, `infra/airgap_stack.py`; key ids in `outputs.json`). C2SP checkpoint with W1 cosignature | **W2** (unmodified litewitness on its own EC2 instance `i-0bc5865c1ddae7b1d`) is deployed; trust setup is **pending** (`infra/evidence/post_deploy.json`, "next: w2_ctl.sh trust"). Until it lands, say "W1 only; W1 is in the same account" |
| **S3 Object Lock** (governance mode, 1 day) on the anchor bucket `airgap-log-503002144042` | Tripwire and callback go through the vendor-portal mock (no SMS provider); the "deepfake CFO" is a synthetic voice of a fictional person |
| Bedrock agent: Sonnet 4.5 (eu.) planner; Qwen3-235B for the bulk bench and the quarantined extractor. Bench numbers come only from frozen runs (`bench/results/REPORT.md`) | Bench humans (`diligent`, `rubber_stamp`) are a **model of a human, not a user study**. Bench A1 uses a regex twin of Guardrails; the deployed Bedrock Guardrail (`infra/airgap_stack.py`) is not in the bench numbers |
| Facts from real public-data snapshots: MostlyRight licence/VoP/warning lists, ADIS/ARES legal-entity data; ČNB synthetic transactions | Rail = mock ledger + pain.001.001.09 file (no live payment rail) |
| Offline verification with **unmodified upstream Go** `sumdb/note` and `verify_audit.py` with decision replay | The bench executor runs in-process (memory backend, same code); only the live demo runs on AWS |

**One-line version for the slide:** "Real: the device in my hand, the AWS executor and its IAM walls, the KMS-signed
log you can verify offline. Simulated and labelled: the companies, the second approver's device, the supplier
issuers and the humans in the benchmark."

## Known gaps (say them before anyone asks; WS-D adversarial review, each reproduced)

None of these is an attack inside our threat model; each has a named production fix.

| # | Gap | Why it is outside the demo threat model | Production fix |
|---|---|---|---|
| 1 | The 6-digit callback code is stored as an **unsalted SHA-256** in the portal table, which the vendor-portal role can read; that role could invert it offline | The portal role is a simulated supplier-side component; the demo attacker uses the agent and host roles, which have no access to the portal table. (Our laptops hold admin SSO, which could assume the portal role: the same honest limit as ARCHITECTURE §9; production uses a separate account.) | HMAC under an executor-only key (KMS `GenerateMac`); callback rows in an executor-only table |
| 2 | **Two-person rule = two addresses.** Clerk and treasury must be distinct enrolled addresses, but enrolment does not stop one Trezor enrolling at two derivation paths | Coercion or collusion of both approvers is explicitly out of scope; enrolment is a supervised ceremony | Compare device identity (certificate chain / serial) across roles at enrolment and at signing |
| 3 | **Shared demo issuer keys.** The same three simulated SD-JWT issuer keys (supplier-erp, supplier-bank, registry) are pinned for every vendor, and their private keys are in the repo (labelled DEMO-ONLY) | Real cryptography, simulated organisations; the attacker never holds issuer keys in the demo | Each vendor pins its own ERP key at enrolment; the bank key comes from a pinned trust list |
| 4 | **(until FACTS-1 merges, deadline Tue 03:00)** A proposal without an `email_id` skips the document / DKIM / domain checks in the executor; only the tools λ enforces it | The agent can only reach the executor through the tools λ, which binds every proposal to its source document | "No source document, no autopay" in the executor itself (WS-D FACTS-1). **Strike this row once merged.** |
