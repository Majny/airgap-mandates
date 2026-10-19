# AWS go/no-go probes (WS-E, gate Mon 15:00)

Account 503002144042, region eu-central-1, role `AWSReservedSSO_ai-hackathon-TeamAdmin`.
Probed Mon 19 Oct 2026 ~14:15-14:30 CEST. Round 1 = read-only probes and test calls only.
Round 2 (after human approval "APPROVE AWS", Mon ~15:30): resource probes ran as part of the real deploy; see below.

## Summary

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | Bedrock Sonnet 4.5 `eu.anthropic.claude-sonnet-4-5-20250929-v1:0` | GO | Converse OK, 1.5 s |
| 1 | Bedrock Sonnet 4.6 `eu.anthropic.claude-sonnet-4-6` | GO | Converse OK, 0.75 s |
| 1 | Bedrock Haiku 4.5 `eu.anthropic.claude-haiku-4-5-20251001-v1:0` | GO | Converse OK, 0.46 s |
| 1 | Qwen `qwen.qwen3-235b-a22b-2507-v1:0` (on-demand, no profile) | GO | Converse OK, 0.19 s |
| 1 | gpt-oss `openai.gpt-oss-120b-1:0`, `openai.gpt-oss-20b-1:0` | GO | Converse OK; output is reasoning first, so maxTokens=20 had no text block. Give it >=200 tokens |
| 1 | Rate limits (account quotas) | GO | Sonnet 4.5 eu CRIS **50 req/min**, 5M tok/min; Sonnet 4.6 50 req/min, 6M tok/min; Haiku 4.5 50 req/min; Qwen3 235B **1000 req/min**, 100M tok/min. Throttling not load-tested |
| 2 | Lambda + API GW deploy | PENDING | needs IAM role creation (not run) |
| 2 | DynamoDB `TransactWriteItems` | PENDING | needs table creation (not run) |
| 2 | KMS Ed25519 (`ECC_NIST_EDWARDS25519`) + P-256 Sign | PENDING | `kms list-keys` works (0 keys); create+sign not run |
| 3 | S3 Object Lock (governance) | PENDING | not run |
| 4 | Bedrock Guardrails | API GO | `list-guardrails` -> `[]` (no denial). Create+ApplyGuardrail pending |
| 4 | AgentCore Gateway / Runtime / Identity / Policy | API GO | `list-gateways`, `list-agent-runtimes`, `list-workload-identities`, `list-policy-engines` all answer `[]`. Create pending |
| 4 | VPC endpoint services | GO | present: `bedrock-runtime`, `execute-api`, `bedrock-agentcore`, `bedrock-agentcore-control`, **`bedrock-agentcore.gateway`**, `kms`, `dynamodb`, `logs` |
| 4 | EventBridge Scheduler | API GO | `list-schedules` -> `[]` |
| 4 | CloudTrail | GO | org trail `ai-hackathon-org` (multi-region, home eu-central-1); `lookup-events` works |
| 4 | CloudTrail Lake | NO-GO (expected) | `list-event-data-stores` -> `[]`; closed to new customers, not planned |
| 4 | VPC Flow Logs | API GO | `describe-flow-logs` -> 0; create pending |
| 5 | SCP listing | DENIED | `organizations list-policies`: `AccessDeniedException ... You don't have permissions to access this resource.` SCP content unknown; no denials seen on any read-only call |
| 6 | MostlyRight dataset | GO | see below |

## Bedrock inference profiles seen (eu./global.)

Claude: `eu.anthropic.claude-sonnet-4-5-20250929-v1:0`, `eu.anthropic.claude-sonnet-4-6`,
`eu.anthropic.claude-haiku-4-5-20251001-v1:0`, plus newer `eu.anthropic.claude-sonnet-5`,
`eu.anthropic.claude-sonnet-5-5`, `eu.anthropic.claude-haiku-5-5`, `eu.anthropic.claude-opus-*`
(listed; Opus 4.7 was reported denied, not re-tested).
On-demand: `qwen.qwen3-235b-a22b-2507-v1:0`, `qwen.qwen3-32b-v1:0`, `qwen.qwen3-coder-30b-a3b-v1:0`,
`openai.gpt-oss-120b-1:0`, `openai.gpt-oss-20b-1:0`.

## Datasets

Bucket `s3://ai-hackathon-datasets-422928733782/` has prefixes `CNB/`, `MerchantKYB/`, `MostlyRIght/`.

- `MostlyRIght/MostlyRight_EU_financial_firm_licences_and_warnings_2026-10-18.csv` (3.2 MiB)
  copied to `~/Desktop/MyProjects/mostlyright-dataset/` (outside the repo: `data/` is not gitignored).
  - **15,572 data rows, 34 columns.**
  - Encoding: **not clean UTF-8** (some lines fail UTF-8 and cp1250). WS-D loader must decode
    tolerantly (e.g. try utf-8, fall back per line).
  - Columns: `record_id, record_type, source_list, authority, authority_country, name, other_names,
    country, national_id, lei, bic, eu_reference_number, un_id, website, website_domain, email_domain,
    address, city, category, detail, value_kind, passported_to, since, until, in_sct_inst,
    sct_inst_ready_since, sct_inst_leaving_date, in_vop, vop_status, vop_role, vop_ready_since,
    vop_leaving_date, name_count, regulation_url`
- `CNB/clients.csv` (486 KiB), `CNB/transactions.csv` (34.8 MiB) — listed, not copied.
- `MerchantKYB/` 8 objects, 2.8 MiB — listed, not copied.

## Pending probes (need approval to create, then delete, resources)

All named `airgap-probe-*`, tagged `project=airgap-mandates`, deleted right after
(KMS keys: scheduled deletion, 7 days):
1. IAM role for Lambda; `simulate-principal-policy` on it.
2. Lambda py3.12 arm64 + HTTP API invoke; PRIVATE REST API create/delete.
3. Two on-demand DynamoDB tables, `transact-write-items` success + `TransactionCanceledException`.
4. KMS `ECC_NIST_EDWARDS25519` Sign/Verify (`ED25519_SHA_512`) + offline verify of the public key; `ECC_NIST_P256` ECDSA_SHA_256.
5. S3 Object Lock bucket (GOVERNANCE 1 day): delete without bypass refused, with bypass OK.
6. Guardrail with PROMPT_ATTACK + IBAN regex, ApplyGuardrail on an injected text.
7. AgentCore Gateway create (MCP, AWS_IAM authorizer).
8. VPC (no IGW/NAT) + interface endpoints `bedrock-runtime`, `execute-api`; Flow Logs.

## Round 2: confirmed by the deployed stack (Mon 19 Oct, after "APPROVE AWS")

| Item | Status | Evidence |
|---|---|---|
| Lambda py3.12 arm64 + REST API (regional IAM + private) | GO | stack `AirgapMandates`; `/health` 200 |
| DynamoDB `TransactWriteItems` | GO | S1 executions (`infra/evidence/aws_e2e*.txt`) |
| KMS Ed25519 Sign | GO | signed-note checkpoints verified by stock Go `sumdb/note` (WS-B) |
| S3 Object Lock GOVERNANCE 1 d | GO | delete without bypass -> AccessDenied (WS-B) |
| Guardrails create + ApplyGuardrail | GO | `airgap-a1` in the stack |
| AgentCore Gateway (MCP, AWS_IAM) | GO | create -> READY -> deleted (probe); not on the demo path |
| VPC no-NAT + endpoints + Flow Logs + DNS Firewall | GO | S10 probe; Resolver query log NXDOMAIN/BLOCK |
| EventBridge Scheduler | GO | tick 1 min (Scheduler minimum), anchor 5 min |
| W2 litewitness on EC2 (t4g.nano) | GO | 3-signature checkpoints log + W1 + W2 (WS-B, `docs/audit/aws-main-mon`) |
| Account Lambda concurrency | LIMIT | **10 in total**; reserved concurrency impossible (AWS keeps 10 unreserved) |

## Known residuals (security review, low severity, open)

- Typed `invoice_no` can still carry very short imperative-looking values within its shape budget (e.g. `STOP/00`);
  the planner sees them as data only, and no money path depends on them.
- A later body-only "reminder" email for an already paid invoice with a different VS / due date is not linked to
  the first payment by the tools λ; the executor's I-DUP / F-SPLIT and the human step-up remain the gate.
- Lambda pool of 10 means overlapping ticks are possible; W2 answers 409 and the relay catches up.
