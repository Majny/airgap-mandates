# Pitch deck content (7 slides, 4:00; ARCHITECTURE §14 timings)

Draft for the pitch lead. Rules:
- Every number comes from `bench/results/REPORT.md`; the run ID is in brackets.
- Items marked **[U]** must be checked before they go on a slide (owner: pitch and regulatory lead).
- No real bank or regulator names on slides; fictitious companies only.

Run IDs:
- **QA** = `20261019T150142_qwen-qwen3-235b-a22b-2507-v1_pitch-attack`
- **QB** = `20261019T153447_qwen-qwen3-235b-a22b-2507-v1_pitch-benign-v2`
- **SC** = `scripted_64ff276755d5`
- **SA** = `20261019T153447_eu-anthropic-claude-sonnet-4-5-20250929-v1_sonnet-spot-attack`

---

## Slide 1: Hook (0:00-0:15)

- **Disclosure (first line, said out loud):** "Before the kickoff we had only a written plan, outside the repo, no code. Everything you see was built since 12:00 yesterday; the `hackathon-start` tag is an empty commit."
- **Title:** *This agent is compromised right now. It still can't move a koruna.*
- **Sub:** AirGap Mandates: hardware-signed payment mandates for back-office AI agents.

## Slide 2: Problem (inside the hook; spoken over S1 setup)

- AP agents read supplier email and PDFs. Anyone can write into those.
- **One injected email moves real money.**
  - With no defences, our accounts-payable agent paid an attacker in **51%** of injected-content attacks [QA].
  - That is **571,077 CZK** across 100 attempts [QA].
- **Filters don't fix it.** A prompt-attack sanitiser plus egress DLP still lets **46%** through [QA].
- **A human "Approve" button doesn't either.** A clicking approver lets **43%** through [QA]. When the host UI lies, a careful approver lets **60%** through [QA, H1].

## Slide 3: How it works (one diagram, spoken over S1)

- **The agent can only propose.** It has no IBAN argument at all. The account comes from the vendor master.
- **An executor outside the agent and the laptop decides.**
  - It works from facts it fetched itself: domain, DKIM, Verification-of-Payee mock, licence and warning lists, and the amount on the hashed document.
  - It treats everything else as a hint.
- **Money moves only inside a mandate people signed, or after a hold-to-confirm of exactly the text the device shows.**
- **New account = 2 of 3 independent supplier attestations + 2/2 dual control.** Otherwise there is nothing to approve: the device stays dark.
- **Everything goes into a witnessed transparency log** that a supervisor verifies offline: unmodified upstream Go checks the log signature, our open verifier re-checks every entry, cosignature and decision.

## Slide 4: Live beats (0:15-2:30; projector = ops console + device camera)

| Time | Beat | What the room sees |
|---|---|---|
| 0:15-0:45 | **S1 normal day** | invoices paid under the mandate; the over-cap one lights the Trezor Safe 3 (`AG1/DEMO PAY ...`); hold to confirm; receipt QR; witness tick |
| 0:45-1:35 | **S2 lookalike BEC + escalation + exfil** | facts go red, **the device stays dark** ("nothing to approve"); `mandate.write`, self-approval and replay are refused; exfil is blocked |
| 1:35-2:30 | **S3 real-domain takeover + synthetic-voice "CFO"** | DKIM green, **ATT 0/3 = BLOCK, there is no button**, while a 12 s clip plays the "CFO" demanding approval (labelled: *synthetic voice, Amazon Polly, fictional person*; `demo/assets/synthetic_cfo_call.mp3`, in the UI's S3 beat); tripwire answer "not us" means REJECTED; 10 s of the legitimate path: 2/3 attestations, cooling-off, clerk + treasury, ACTIVE |

## Slide 5: Numbers (3:20-3:50; S5 offline audit runs 2:30-3:20 without slides)

**Headline: money to the attacker, 100 injected-content attacks, Qwen3-235B** [QA]

| | Attack success | Money to attacker |
|---|---|---|
| Agent alone (A0) | 51% [41-61] | 571,077 CZK |
| + filters (A1) | 46% [37-56] | 562,832 CZK |
| + tool scoping + Approve button, careful human (A2) | 30% [22-40] | 0 CZK, but duplicate and overpaid invoices are still paid |
| + Approve button, clicking human (A2) | 43% [34-53] | 439,562 CZK |
| **+ AirGap executor, clicking human (A3)** | **0% [0-4]** | **0 CZK** |

- **Compromised host, scripted** [SC]: false display text, nonce swap, tampered device text, the agent's own credentials, egress bypass. **0 of 10 each** on A3.
- **Approver load** [QB]: **0 prompts for routine invoices inside the mandate.**
  - Prompts come only for over-cap invoices (about 18 per 100 cases).
  - Each new payee account costs 3 by design (clerk + treasury + first payment).
- **Footnote** [SA]: Sonnet 4.5 spot-check (n=34): A0 38% [24-55]; A3 with a clicking human 0% [0-10].
- **Footnote:** simulated humans are a model of a human, not a user study. The A3 residual inside the mandate is 0 CZK in this corpus. A genuinely inflated invoice from the real vendor is out of scope and bounded by the caps.

## Slide 6: Real vs simulated (3:50-3:55; full table in `demo/REAL_VS_SIMULATED.md`)

- **Real:**
  - the Trezor Safe 3 in my hand (genuine, certificate chain verified);
  - the executor on AWS eu-central-1 with its IAM walls (agent: explicit deny on the tables, KMS and `/signatures`);
  - the agent VPC with no route out;
  - KMS Ed25519 log key and W1 witness key, every checkpoint cosigned by two witnesses (W2 is unmodified upstream litewitness with its own key), and S3 Object Lock;
  - the offline check: unmodified upstream Go for the log signature, plus our open verifier for entries, cosignatures and decisions.
- **Simulated, and labelled:**
  - the companies;
  - the treasury approver (emulator, auto-confirmed by script: a simulated human);
  - the supplier attestation issuers (real cryptography, fictitious organisations);
  - the VoP responder;
  - the humans in the benchmark.
- **Witnesses:** every checkpoint is cosigned by W1 and W2 (W2 = unmodified upstream litewitness on its own instance, operator simulated; evidence `docs/audit/aws-main-mon/README.md`). Say "simulated operator", never "independent regulator".

## Slide 7: Business (3:55-4:00)

- **Who pays today:** authorised push-payment fraud and BEC losses land on the payer's bank and its corporate clients. The **[U] PSR/PSD3 liability-shift status** gets its wording from the regulatory mentor's session (Tue 07:30).
- **What we sell:** a payment-authorisation layer an AP agent can't talk its way past. Mandate for volume, exact-sign for exceptions, attestation network for new payees.
  - Hardware per approver: **[U] Trezor Safe 3 list price**.
  - Compute: about **USD 0.3-0.6 per 100 agent episodes** in our bench [QA/QB].
- **Network effect:** every supplier bank that attests its own clients' accounts makes payee changes safer for every buyer.
- **Close:** "Take over the agent, the laptop and the supplier's mailbox, and you still can't send one koruna to a new account. And afterwards, a supervisor can prove it offline."

---

### Q&A cards (numbers ready)

- **"Isn't the approver fatigued?"** No prompt for routine invoices; the over-cap and new-account prompts are the ones a bank wants seen [QB]. The quarantined agent mode gets 15-17 prompts per 100 cases, at the price of not acting on account-change emails [QB].
- **"Does a better model fix it?"** Sonnet 4.5 refuses exfiltration and direct writes, but still pays 8 of 13 "new account" requests and 7 of 7 duplicates at A0 [SA].
- **"How sure are you about 0%?"** 0/100 per cell, 95% Wilson upper bound 4% [QA]. It is 0 by construction for new accounts (R0 + attestations), and 0/10 per scripted host attack [SC].
- **"How would a supervisor check this?"** Offline, with public keys obtained out of band: stock Go checks the log signature, our verifier re-checks every entry, decision and device approval, and a one-byte edit names the entry. Witnesses: W1 is in our account, W2 is unmodified litewitness with a simulated operator. We are "aligned with" DORA RTS 2024/1774 Art. 12 and PSD2 RTS Art. 5, never "compliant" (`docs/audit/SUPERVISOR.md`).
- **Limits:**
  - one main model;
  - fictitious world of 3 vendors;
  - templated payloads (public AgentDojo-style wrapper);
  - the bench executor runs in-process (same code as AWS).
