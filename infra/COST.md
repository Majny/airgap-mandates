# Cost estimate (WS-E) vs USD 800 budget

eu-central-1 list prices, hackathon window about 26 h. All figures are estimates; check Cost Explorer at Mon 20:00.

| Item | Unit price (approx.) | Per day | 26 h |
|---|---|---|---|
| 2 interface endpoints (bedrock-runtime, execute-api) × 1 AZ | ~USD 0.012/h each + 0.01/GB | 0.58 | 0.63 |
| W2 t4g.nano + public IPv4 + 8 GB gp3 (stopped when idle: EBS only) | 0.0048 + 0.005/h + 0.02/day | 0.26 | 0.28 |
| KMS: 2 Ed25519 keys (prorated USD 1/month) + Sign calls (1440 ticks/day) | 0.03/10k req | 0.08 | 0.09 |
| DynamoDB on-demand, 7 tables (demo + bench volume) | 1.53/M writes | < 0.50 | < 0.55 |
| Lambda (6 fns, arm64) + API Gateway REST (2 APIs) | 3.50/M requests | < 0.30 | < 0.35 |
| CloudWatch Logs + VPC Flow Logs (1-week retention) | 0.63/GB ingest | < 0.50 | < 0.55 |
| EventBridge Scheduler (1728 invocations/day) | 1.00/M | ~0 | ~0 |
| S3 inbox + Object Lock anchor bucket | storage negligible | < 0.05 | < 0.05 |
| **Infra subtotal** | | **≈ 2.3** | **≈ 2.5** |

Bedrock (measured token counts from the smoke runs, Mon 19 Oct):

| Model | Tokens / episode | USD / episode | Example volume | USD |
|---|---|---|---|---|
| Sonnet 4.5 planner (`eu.`) | ~11.7k (10.2k in, 1.5k out) | ~0.054 | 200 live + spot-check episodes | ~11 |
| Qwen3-235B planner/extractor | ~10-12k | ~0.004 | 5,000 bench episodes | ~20 |

Rule of thumb: infra < USD 5 for the whole event; Bedrock dominates and stays well under USD 100 unless Sonnet is
used for bulk bench runs (do not: 50 req/min shared, and ~13x Qwen's cost). No NAT gateway, ALB, OpenSearch or
Knowledge Bases are created. Budget alarm: create in the console (Budgets API is org-managed) at USD 300 / 500.

Teardown: `infra/teardown.sh` (empties the Object Lock bucket with `--bypass-governance-retention`, destroys the
stack, KMS keys go to 7-day PendingDeletion and stop billing). Between demo runs: `infra/w2_ctl.sh stop`.
