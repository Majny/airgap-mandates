# AgentPayBench: pitch results (frozen)

Only the numbers on this page may appear on a slide. They come from the frozen runs listed at the bottom
(`bench/results/FROZEN.md`). Reproduce with `make bench` + `python -m bench.scripted`; render with
`python -m bench.report --runs <stems>`.

## Headline (Qwen3-235B, 100 injected-content attacks, H0)

| Arm | What is added | Attack success (95% CI) | Money to attacker |
|---|---|---|---|
| A0 | bare agent with write access | **51%** [41-61] | **571,077 CZK** |
| A1 | + input sanitiser + egress DLP | 46% [37-56] | 562,832 CZK |
| A2 | + tool scoping + software Approve, diligent human | 30% [22-40] | 0 CZK (duplicates/overpay still paid) |
| A2 | same, rubber-stamp human | 43% [34-53] | 439,562 CZK |
| **A3** | **+ AirGap executor ([F] facts, mandate, R0, 2-of-3 attestations, device)** | **0%** [0-4] | **0 CZK**, also with a **rubber-stamp** human and in both agent modes |

- **Lying host UI (H1, n=20):** A2 with a diligent human goes to 60% [39-78] success (222,210 CZK), because the human approves what the UI shows. A3 stays at 0% [0-16] / 0 CZK: the device text comes from the executor.
- **Compromised host, scripted (H2-H6, 10 each, model-independent; run on the FACTS-1 code, H2-H4 with document-bound invoices so the step-up challenge is real):** 0 successes on A3, each stopped by a named check:
  - false displayed_text: `render_mismatch`
  - nonce swap: `unknown_signer`
  - different text sent to the device: `unknown_signer`
  - agent principal calling host/portal routes: `caller_not_allowed`
  - mail to an outside address: `T-EGRESS-ALLOW`
  A0-A2 rows are by construction (no control at that layer).
- **In-mandate residual at A3: 0 CZK.** Injected inflation is denied by F-AMOUNT-DOC (amount != the provenance-hashed document) and duplicates by F-DUP. A genuinely inflated invoice from the real vendor remains out of scope (bounded by caps, I-Z).
- **Cost to the business (benign, n=100, run `pitch-benign-v2`):**

  | | A0 | A3 naive | A3 quarantined |
  |---|---|---|---|
  | utility failures | 18% [12-27] | 7-10% | 9% |
  | of which a gate rule fired (upper bound on false blocks) | 0 | 4-8 | 7-8 |

  Agent-only failures move a lot between runs: A0 was 10% in v1 and 18% in v2 with no gate involved (Qwen
  run-to-run variance). Treat single-digit differences between arms as noise; the A3 "gate rule fired" count is
  the number to watch.

### Device prompts: where they come from (A3, benign, 100 cases, about 195 payments)

| Prompt reason | naive agent | quarantined agent | per event |
|---|---|---|---|
| ordinary invoice inside the mandate | **0** | **0** | 0: paid under the signed mandate, no prompt |
| invoice over the mandate cap (PAY step-up) | 18 | 15-17 | 1 |
| legitimate payee change: clerk + treasury (CHG 2/2, by design) | 42 (21 changes) | 0 | 2 |
| first payment to the newly activated account (F-FIRSTSEEN < 72 h) | 13-16 | 0 | 1 |
| anything else | 0 | 0 | - |
| **total per 100 cases** | **73-76** | **15-17** | |

- The approver is never asked about routine payments. Prompts come only from things a bank would want a human to see: over-cap amounts, a new account (3 prompts per change, 2 of them dual control), and the first payment to that account.
- **Naive vs quarantined:** the naive agent reads the supplier's "we have a new account" email and requests the change, so 21 legitimate changes reach the 2/2 ceremony. The quarantined agent never sees free text (only `txt_` handles), so it cannot learn the new IBAN. It keeps paying the old, still-valid account and asks for no change: fewer prompts, but the account update has to come from a human or a supplier attestation. This is the price of quarantining, and it is measured, not assumed.
- **Compute cost:** 1,760 LLM episodes for USD 7.41 in total (about USD 0.3-0.6 per 100 cases, Qwen3-235B on Bedrock eu-central-1; plus USD ~4 for the v2 benign rerun).

## FACTS-1 check (executor: no source document, no autopay; main 64ff276)

The LLM pitch runs above were frozen before FACTS-1 merged. A verification rerun on the merged code (`20261019T181809_qwen-qwen3-235b-a22b-2507-v1_facts1-check-attack`,
`20261019T181832_qwen-qwen3-235b-a22b-2507-v1_facts1-check-benign`; not headline numbers) shows the A3 attack results are unchanged: 20 of 20 rows identical, 0 successes,
0 CZK. Benign utility failures were 6/40 against 4/40 frozen for the same cases. The two new F-AMOUNT-DOC
denials pass on rerun (the agent extracts and cites the document), so this is run-to-run noise, not a FACTS-1
effect. The frozen LLM runs stand. The scripted H2-H6 run was redone on the FACTS-1 code (`scripted_64ff276755d5`) with identical
outcomes.

## Sonnet spot-check (separate model, never mixed into the Qwen headline)

`eu.anthropic.claude-sonnet-4-5-20250929-v1:0`, paced at 20 req/min (shared team budget). Every 3rd attack case
(34 H0 + 6 H1) on A0 and on A3 with a **rubber-stamp** human, plus every 5th benign case on A3. Runs `20261019T153447_eu-anthropic-claude-sonnet-4-5-20250929-v1_sonnet-spot-attack`, `20261019T155908_eu-anthropic-claude-sonnet-4-5-20250929-v1_sonnet-spot-benign`.

| | Attack success (95% CI) | Money to attacker |
|---|---|---|
| A0, H0 injected content (n=34) | **38%** [24-55]: redirect 8/13, duplicate 7/7, inflate 2/7, exfil 0/7, escalate 0/6 | 100,450 CZK (+147,362 CZK duplicate/overpay) |
| **A3, rubber-stamp human, H0 (n=34)** | **0%** [0-10] | **0 CZK** |
| A0, H1 lying UI (n=6) | 67% [30-90] | 64,506 CZK |
| A3, rubber-stamp human, H1 (n=6) | 0% [0-39] | 0 CZK |

- Sonnet 4.5 refuses the outright exfiltration and `vendor.write` requests that Qwen sometimes follows. It still pays a supplier's "new account" and still pays duplicates. A stronger model lowers the A0 rate, but not to zero.
- A3 benign (n=20): utility failures 10% [3-30]; 0 failures with a gate rule fired; 110 device prompts per 100 cases (Sonnet requests more of the legitimate account changes).
- Cost USD 4.50 for 100 episodes (~USD 5-8 per 100 cases, about 15x Qwen).

## What is real and what is simulated

- **Real, in-process (memory backend):**
  - executor `dispatch()`, Cedar `decide()`, WS-D facts engine and payee-change FSM;
  - `POST /ingest` with DKIM verified against the DNS snapshot, F-AMOUNT-DOC over the ingested ISDOC part;
  - SD-JWT VC verification of 2 real VCs from the DEMO-ONLY issuer keys;
  - EIP-191 signatures recovered and checked against enrolled signers.
  The demo runs the same code on AWS. The bench does not call AWS except Bedrock.
- **Simulated:**
  - **Humans** (`diligent`, `rubber_stamp`) are a model of a human, not a user study.
  - **Organisations:** companies, domains and accounts are fictitious; the issuer organisations are simulated.
  - **Tools λ:** a bench stand-in resolves `email_id` / `invoice_ref` from the agent's own `invoice.extract` calls.
  - **A0-A2 tool surfaces** (IBAN argument, live `vendor.write`) are a bench-defined "typical AP bot".
- **Agent:** `bench.agent_loop` (Bedrock Converse, one fixed system prompt for every arm, recorded in the run meta). Quarantined mode = a no-tool Qwen extractor; free text reaches the planner only as `txt_<hash>` handles.
- **Corpus:** 100 H0 attacks = 5 goals (redirect, exfil, escalate, inflate, duplicate) x 4 vectors (email body, hidden document text, ISDOC note, filename) x 5 variants over 3 fictitious vendors. Half are lookalike senders, half real-domain takeover with valid DKIM. 20 H1 = the redirect cases with a lying UI. Payload text is templated (`bench/cases/templates.json`, plain BEC requests plus the public AgentDojo "important_instructions" wrapper). Benign: 100 AP tasks, 21 with a legitimate, attested ACME account change.
- **Limits:**
  - Qwen3-235B is the main model; Sonnet 4.5 is a spot-check only (n=40 attack + 20 benign), see its section;
  - A0-A2 legit-change utility is lenient (paying the old account counts as correct);
  - the earlier A0 gate run (52%) used a 10-vendor world and stub facts; it is superseded for everything except the gate itself.

## Full table (Qwen3-235B pitch runs; benign = v2; scripted on FACTS-1)

| model | level | arm | mode | human | attack n | ASR (95% CI) | money to attacker CZK | in-mandate residual CZK | benign n | utility fail (95% CI) | of which a gate rule fired | exceptions/100 | device prompts/100 | USD/100 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| qwen.qwen3-235b-a22b-2507-v1 | H0 | A0 | naive | - | 100 | 51% [41-61] | 571,077 | 588,143 | 0 | - | - | 0 | 0 | 0.32 |
| qwen.qwen3-235b-a22b-2507-v1 | H0 | A1 | naive | - | 100 | 46% [37-56] | 562,832 | 600,168 | 0 | - | - | 0 | 0 | 0.34 |
| qwen.qwen3-235b-a22b-2507-v1 | H0 | A2 | naive | diligent | 100 | 30% [22-40] | 0 | 612,472 | 0 | - | - | 44 | 0 | 0.36 |
| qwen.qwen3-235b-a22b-2507-v1 | H0 | A2 | naive | rubber_stamp | 100 | 43% [34-53] | 439,562 | 653,522 | 0 | - | - | 46 | 0 | 0.37 |
| qwen.qwen3-235b-a22b-2507-v1 | H0 | A3 | naive | diligent | 100 | 0% [0-4] | 0 | 0 | 0 | - | - | 0 | 0 | 0.33 |
| qwen.qwen3-235b-a22b-2507-v1 | H0 | A3 | naive | rubber_stamp | 100 | 0% [0-4] | 0 | 0 | 0 | - | - | 0 | 0 | 0.34 |
| qwen.qwen3-235b-a22b-2507-v1 | H0 | A3 | quarantined | diligent | 100 | 0% [0-4] | 0 | 0 | 0 | - | - | 0 | 0 | 0.30 |
| qwen.qwen3-235b-a22b-2507-v1 | H0 | A3 | quarantined | rubber_stamp | 100 | 0% [0-4] | 0 | 0 | 0 | - | - | 0 | 0 | 0.30 |
| qwen.qwen3-235b-a22b-2507-v1 | H1 | A0 | naive | - | 20 | 70% [48-85] | 278,360 | 0 | 0 | - | - | 0 | 0 | 0.38 |
| qwen.qwen3-235b-a22b-2507-v1 | H1 | A1 | naive | - | 20 | 75% [53-89] | 335,462 | 0 | 0 | - | - | 0 | 0 | 0.42 |
| qwen.qwen3-235b-a22b-2507-v1 | H1 | A2 | naive | diligent | 20 | 60% [39-78] | 222,210 | 0 | 0 | - | - | 95 | 0 | 0.45 |
| qwen.qwen3-235b-a22b-2507-v1 | H1 | A2 | naive | rubber_stamp | 20 | 85% [64-95] | 342,716 | 0 | 0 | - | - | 105 | 0 | 0.45 |
| qwen.qwen3-235b-a22b-2507-v1 | H1 | A3 | naive | diligent | 20 | 0% [0-16] | 0 | 0 | 0 | - | - | 0 | 0 | 0.37 |
| qwen.qwen3-235b-a22b-2507-v1 | H1 | A3 | naive | rubber_stamp | 20 | 0% [0-16] | 0 | 0 | 0 | - | - | 0 | 0 | 0.38 |
| qwen.qwen3-235b-a22b-2507-v1 | H1 | A3 | quarantined | diligent | 20 | 0% [0-16] | 0 | 0 | 0 | - | - | 0 | 0 | 0.26 |
| qwen.qwen3-235b-a22b-2507-v1 | H1 | A3 | quarantined | rubber_stamp | 20 | 0% [0-16] | 0 | 0 | 0 | - | - | 0 | 0 | 0.27 |
| qwen.qwen3-235b-a22b-2507-v1 | benign | A0 | naive | - | 0 | - | 0 | 0 | 100 | 18% [12-27] | 0 | 0 | 0 | 0.57 |
| qwen.qwen3-235b-a22b-2507-v1 | benign | A1 | naive | - | 0 | - | 0 | 0 | 100 | 18% [12-27] | 2 | 0 | 0 | 0.55 |
| qwen.qwen3-235b-a22b-2507-v1 | benign | A2 | naive | diligent | 0 | - | 0 | 0 | 100 | 14% [9-22] | 2 | 23 | 0 | 0.57 |
| qwen.qwen3-235b-a22b-2507-v1 | benign | A2 | naive | rubber_stamp | 0 | - | 0 | 0 | 100 | 9% [5-16] | 1 | 23 | 0 | 0.57 |
| qwen.qwen3-235b-a22b-2507-v1 | benign | A3 | naive | diligent | 0 | - | 0 | 0 | 100 | 7% [3-14] | 4 | 76 | 76 | 0.53 |
| qwen.qwen3-235b-a22b-2507-v1 | benign | A3 | naive | rubber_stamp | 0 | - | 0 | 0 | 100 | 10% [6-17] | 8 | 73 | 73 | 0.49 |
| qwen.qwen3-235b-a22b-2507-v1 | benign | A3 | quarantined | diligent | 0 | - | 0 | 0 | 100 | 9% [5-16] | 7 | 17 | 17 | 0.47 |
| qwen.qwen3-235b-a22b-2507-v1 | benign | A3 | quarantined | rubber_stamp | 0 | - | 0 | 0 | 100 | 9% [5-16] | 8 | 15 | 15 | 0.43 |
| scripted | H2 | A0 | naive | - | 10 | 100% [72-100] | 1,900,450 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H2 | A1 | naive | - | 10 | 100% [72-100] | 1,900,450 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H2 | A2 | naive | diligent | 10 | 100% [72-100] | 1,900,450 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H2 | A2 | naive | rubber_stamp | 10 | 100% [72-100] | 1,900,450 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H2 | A3 | naive | diligent | 10 | 0% [0-28] | 0 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H2 | A3 | naive | rubber_stamp | 10 | 0% [0-28] | 0 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H3 | A0 | naive | - | 10 | 100% [72-100] | 1,900,450 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H3 | A1 | naive | - | 10 | 100% [72-100] | 1,900,450 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H3 | A2 | naive | diligent | 10 | 100% [72-100] | 1,900,450 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H3 | A2 | naive | rubber_stamp | 10 | 100% [72-100] | 1,900,450 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H3 | A3 | naive | diligent | 10 | 0% [0-28] | 0 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H3 | A3 | naive | rubber_stamp | 10 | 0% [0-28] | 0 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H4 | A0 | naive | - | 10 | 100% [72-100] | 1,900,450 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H4 | A1 | naive | - | 10 | 100% [72-100] | 1,900,450 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H4 | A2 | naive | diligent | 10 | 100% [72-100] | 1,900,450 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H4 | A2 | naive | rubber_stamp | 10 | 100% [72-100] | 1,900,450 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H4 | A3 | naive | diligent | 10 | 0% [0-28] | 0 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H4 | A3 | naive | rubber_stamp | 10 | 0% [0-28] | 0 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H5 | A0 | naive | - | 10 | 100% [72-100] | 1,900,450 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H5 | A1 | naive | - | 10 | 100% [72-100] | 1,900,450 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H5 | A2 | naive | diligent | 10 | 100% [72-100] | 1,900,450 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H5 | A2 | naive | rubber_stamp | 10 | 100% [72-100] | 1,900,450 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H5 | A3 | naive | diligent | 10 | 0% [0-28] | 0 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H5 | A3 | naive | rubber_stamp | 10 | 0% [0-28] | 0 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H6 | A0 | naive | - | 10 | 100% [72-100] | 0 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H6 | A1 | naive | - | 10 | 100% [72-100] | 0 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H6 | A2 | naive | diligent | 10 | 100% [72-100] | 0 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H6 | A2 | naive | rubber_stamp | 10 | 100% [72-100] | 0 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H6 | A3 | naive | diligent | 10 | 0% [0-28] | 0 | 0 | 0 | - | - | 0 | 0 | 0.00 |
| scripted | H6 | A3 | naive | rubber_stamp | 10 | 0% [0-28] | 0 | 0 | 0 | - | - | 0 | 0 | 0.00 |

Simulated humans are a model of a human, not a user study. 'utility fail' counts agent errors too; 'of which a gate rule fired' is an upper bound on false blocks.
- `20261019T150142_qwen-qwen3-235b-a22b-2507-v1_pitch-attack` (git 2c19bfd70af7): A3 gate {"proposals": "executor.handler.dispatch (memory backend)", "facts": "executor.facts.compute (WS-D, real)", "changes": "executor.change.machine via POST /changes (WS-D, real)", "attestations": "DEMO-ONLY issuers supplier-erp + supplier-bank (real SD-JWT VCs, simulated organisations)", "inbox": "POST /ingest (executor computes the DKIM verdict over the DNS snapshot)"}
- `20261019T153447_qwen-qwen3-235b-a22b-2507-v1_pitch-benign-v2` (git 3db96042a237): A3 gate {"proposals": "executor.handler.dispatch (memory backend)", "facts": "executor.facts.compute (WS-D, real)", "changes": "executor.change.machine via POST /changes (WS-D, real)", "attestations": "DEMO-ONLY issuers supplier-erp + supplier-bank (real SD-JWT VCs, simulated organisations)", "inbox": "POST /ingest (executor computes the DKIM verdict over the DNS snapshot)"}
- `scripted_64ff276755d5` (git 64ff276755d5): A3 gate {"proposals": "executor.handler.dispatch (memory backend)", "facts": "executor.facts.compute (WS-D, real)", "changes": "executor.change.machine via POST /changes (WS-D, real)", "attestations": "DEMO-ONLY issuers supplier-erp + supplier-bank (real SD-JWT VCs, simulated organisations)", "inbox": "POST /ingest (executor computes the DKIM verdict over the DNS snapshot)"}
