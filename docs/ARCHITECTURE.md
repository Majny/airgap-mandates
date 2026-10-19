# AirGap Mandates: Architecture (v2.1, authoritative; v2.1 = H0 device facts, Trezor Safe 3)

Status: **final design for the FinTechers Hackathon 2026, Track 3 "Securing the agentic bank"**. Hacking runs Mon 19 Oct 12:00 to code freeze Tue 20 Oct 13:30. Demo is 4:00 plus 3:00 Q&A.

How this file relates to the others:
- This file says **what** we build and **why**.
- `docs/CONTRACTS.md` says the **exact bytes and APIs**. §16 lists every change CONTRACTS v1 needed to match this design; they are applied in CONTRACTS v2, which wins for code.

Markers:
- **[V]** verified on the emulator (Safe 3 T3B1 or Safe 5 T3T1, firmware 2.12.5), on the physical Safe 3 (T2B1, firmware 2.12.0; marked [V hardware]) or in this repo.
- **[S]** read in source or docs, not run.
- **[U]** unverified. Each [U] has an owner and a go/no-go time in §15.

Evidence for the device claims:
- `/Users/majny/Desktop/MyProjects/fintechers-hackathon-2026/kickoff/trezor-research/` (`screens/*.png`, `dl.py`, `verify_ident.py`, `ctl.py`): the earlier Safe 5 study.
- `docs/device/measurements.md`, `docs/device/h0/*.png`, `docs/device/enroll_*.json` (H0, Safe 3 emulator and physical device).

---

## 1. Summary and principles

**Summary.** AirGap Mandates is a payment-authorisation layer for bank back-office AI agents. The accounts-payable agent does real work: it triages the inbox, extracts and matches invoices, finds duplicates and proposes payments. It can only **propose**. Money is moved by an **executor** that runs outside the laptop and outside the agent's AWS role. The executor computes its own facts **[F]** from registries and data it fetched itself, and it treats everything from the agent or host as a hint **[H]**. It executes a payment in one of two cases:
- the payment fits inside a **mandate** that people signed on a Trezor (Safe 3), or
- a human holds-to-confirm **exactly the text the device shows**. That text is rendered by the executor and contains only [F].

A new payee account needs both of these:
- **2-of-3 independent supplier attestations** (SD-JWT VCs bound to the change nonce), or a break-glass path (callback to a contact registered before the request, plus a cooling-off period).
- **2/2 dual control** on two different devices.

Every input, decision, signature and execution goes into a C2SP-format transparency log. Witnesses cosign it, and a supervisor can verify it offline with **code we did not write** (Go `sumdb/note`). Decisions can also be replayed offline. There is no blockchain and no LLM anywhere in the decision path.

**One line for the jury:** "Take over the agent, the laptop and the supplier's mailbox, and you still cannot send one koruna to a new account. Afterwards a supervisor can prove that offline."

**Principles**

| # | Principle | Consequence |
|---|---|---|
| P1 | The agent, the host laptop, email, PDFs and phone calls are all assumed compromised | Nothing they say can unlock money (S3 [H] monotonicity) |
| P2 | The display is the contract | The signed bytes are exactly the ASCII text the device shows (`safe3-mono-16x4`: 16 cols, 4-line pages), rendered by the executor (S2, S11) |
| P3 | The agent never supplies the IBAN that gets paid | Proposals carry `vendor_id`. The IBAN comes from a vendor master that changes only through the change flow |
| P4 | Nothing to approve means nothing to rubber-stamp (**R0**) | If any fact is BLOCK, no challenge is issued and the device stays dark |
| P5 | Deterministic decisions that can be replayed | Cedar policies via `cedarpy`. `policy_hash` goes in every leaf. `verify_audit.py --replay` reproduces every decision (S12) |
| P6 | Verifiable by third parties | Standard formats: C2SP checkpoint and witness, EIP-191, SD-JWT VC, ISO 20022 pain.001, EPC VoP codes |
| P7 | Defence in depth, measured rather than claimed | Bench arms A0 to A3 map one-to-one onto layers. The A3 money guarantee holds by construction; layers 1 and 2 are reported with their leak rates |
| P8 | AWS for the demo, local twins for development, honest about simulation | **AWS is mandatory for the demo:** every trusted component (executor, store, KMS, Object Lock, Bedrock, witness) runs on AWS eu-central-1 (`AIRGAP_BACKEND=aws`). Each AWS feature has a local twin behind `AIRGAP_BACKEND=memory\|moto`, used for development and CI only, never on stage. The real-vs-simulated slide is mandatory (§12) |
| P9 | Fictitious identities only | Deployment tag `AG1/DEMO`, fictitious companies, synthetic voice of a fictional person. No KB or ČNB branding, no real bank names |

**Disclosure.** The `hackathon-start` tag is on `ccf9f2f` (Mon 19 Oct 12:02:46 CEST), an empty initial commit made at kickoff. Every later commit, including CONTRACTS, `contracts/`, `render.py`, the skeleton and this document, was made after 12:00 and is hackathon work. Before kickoff only a written plan existed outside the repo. README states this under "Pre-existing work" and "Built during the hackathon"; the demo opens with one line saying so. Do not move the tag.

---

## 2. System context, components and trust boundaries

```
 TB3 UNTRUSTED                                   ║ TB1 EXECUTOR (AWS eu-central-1, executor roles only)
                                                 ║
 Mailbox fixtures ─► Ingest λ (raw .eml→S3,      ║  ┌──────────────────────── EXECUTOR ───────────────────────────┐
  (EML/PDF/ISDOC/    DKIM/SPF verdict computed ──╫─►│ private API GW (IAM) → dispatch()                            │
   SPAYD)            HERE → [F])                 ║  │  facts/   F-* from executor-fetched snapshots (§6)           │
                                                 ║  │  policy/  Cedar via cedarpy, policy_hash pinned (§5.3)       │
 ┌─ AGENT VPC (no IGW, no NAT) ───────────────┐  ║  │  change/  payee-change FSM + SD-JWT VC verifier (§5.2, §7)   │
 │ AP-Clerk agent (Lambda container)          │  ║  │  render/  safe3-mono-16x4 renderer, sole display source (§3) │
 │  planner  : Sonnet 4.5 (eu.)               │  ║  │  sig/     EIP-191 recover, nonce consume (conditional)       │
 │  extractor: Qwen3-235B, no tools (CaMeL Q) │  ║  │  ledger/  TransactWriteItems: leaf+seq+debit+exec (§5.4)     │
 │  VPCE: bedrock-runtime, execute-api        │  ║  │  rail/    pain.001.001.09 (+pain.002); TSYS if writes [U]    │
 └───────────┬────────────────────────────────┘  ║  │  audit/   leaves → checkpoint (signed-note Ed25519) (§8)     │
             │ MCP tool calls only               ║  └──────┬──────────────────────────────┬─────────────────────────┘
             ▼                                   ║         │ challenge (text+nonce)        │ add-checkpoint
 Tool plane: AgentCore Gateway + Policy (Cedar)  ║         ▼                               ▼
  [A2 layer; or tools λ + cedarpy twin] ─────────╫─► tools λ (logs EVERY call → F-ANOM)   TB2 WITNESSES
  send_email → Egress λ (allowlist, DLP mod-97,  ║                                        W1 witness λ: own role,
  IČO, Guardrails sensitive-info as 2nd opinion) ║                                           own KMS key, own table
                                                 ║                                        W2 unmodified litewitness
 Host laptop (U2): ops console + signer worker   ║                                           (Go) on separate machine
  can lie: H1..H6 ── USB ──► TB0 TREZOR SAFE 3 (clerk)      tenv emulator T3B1 (treasury, labelled EMULATOR)
                                                 ║
 TB4 SUPPLIER SIDE (separate roles/keys): supplier-erp issuer · supplier-bank issuer (pinned) · registry issuer
  (signs ADIS/ARES/MostlyRight snapshot facts) · vendor portal (callback code + tripwire inbox, portal role only)
 TB5 OFFLINE: supervisor laptop, Wi-Fi off: verify_audit.py + noteverify (Go, golang.org/x/mod/sumdb/note) + replay
 OBSERVERS: CloudTrail trail (+DynamoDB/S3 data events), VPC Flow Logs, CloudWatch; the agent role cannot write them
```

| TB | Contents | Trusted for | Explicitly not trusted for |
|---|---|---|---|
| **TB0** human + Safe 3 | Screen, hold-to-confirm, seed in the secure element. Passphrase protection on; the host never types a passphrase (standard wallet); another passphrase gives an unenrolled address and fails safe | "This person saw exactly these bytes and held to confirm" | Judging facts the screen does not show. R0 keeps BLOCKed subjects off the screen entirely |
| **TB1** executor | One Lambda role per function. DynamoDB `ledger`, `mandates`, `audit`, `registry` (separate IAM resources). KMS log key. Secrets Manager (rail key) | Computing [F], deciding, rendering, verifying, executing, logging | Being honest about its own log, which is why TB2 exists. Lambda is Firecracker isolation, **not a TEE** (say this in Q&A; Nitro is the production path, §9) |
| **TB2** witnesses | W1: separate role, KMS key, table; its key policy denies executor roles. W2: unmodified litewitness on another machine and network | Append-only, no split view (S8) | Decision correctness (covered by replay, S12). W1 is in the same account, so the real independence claim rests on W2 |
| **TB3** untrusted | Agent and all models, host UI, mailbox, PDFs, callback voice, anything vendor-typed | Nothing. Every value is [H] | — |
| **TB4** supplier issuers | 3 issuer classes with keys pinned at supplier enrolment | One attestation each; any 2 distinct classes are required | Any single issuer |
| **TB5** auditor | Export bundle plus public keys | Independent verification | — |

**Explicitly out of scope (on a slide):**
- A malicious executor operator with deploy rights. Mitigated only by the witness, CloudTrail, and the code SHA in the checkpoint.
- Compromised Trezor firmware or supply chain. Mitigated by the enrolment ceremony.
- Coercion of both 2/2 approvers.
- **Fraud inside a valid mandate**: an inflated invoice to an existing payee within the caps. Bounded by caps, F-DUP and F-ANOM, and measured in the bench.

**Security invariants.** These extend CONTRACTS §8.2 S1–S9. Each has a named test, and all must be green by Tue 06:00.

| ID | Invariant | Test technique |
|---|---|---|
| S1 | Money moves only under (a) a Cedar allow within an ACTIVE mandate, or (b) a verified exact-sign. A mandate above the threshold needs 2/2 distinct keys | Hypothesis over `decide()`; ledger rows ↔ authorisation |
| S2 | Signed bytes == `render(stored params)`. The signer comes from recovery, never from the host's claim | Unit test plus emulator screen oracle (`screen_content()` == render, and a screenshot diff) |
| S3 | [H] monotonicity: changing [H] can only move the outcome toward deny, never toward allow | Hypothesis perturbation of hints |
| S4 | A payee change reaches ACTIVE only via (≥2 VCs from distinct pinned classes bound to the change nonce, **or** break-glass), then cooling-off, then 2 distinct enrolled keys | Hypothesis `RuleBasedStateMachine` |
| S5 | A nonce is used once, within its TTL, and bound to `(deployment, purpose, subject)` | Replay / swap / expiry tests |
| S6 | One `TransactWriteItems` writes leaf + seq + debit + execution row. Each execution is covered by a witnessed checkpoint within 60 s | Crash injection; checkpoint-lag metric |
| S7 | The agent and host roles cannot write ledger/mandates/registry/audit, call `kms:Sign`, or read the rail secret | `iam simulate-principal-policy` plus live boto3 AccessDenied |
| S8 | Every checkpoint is consistent with the previous one; witnesses refuse forks (409/422) | Fork injection |
| S9 | Agent output leaves only through the egress λ; non-allowlisted recipients and IBAN/IČO patterns are blocked | Exfil corpus |
| S10 | The agent runtime has no network route except its VPC endpoints | `httpx.get("https://example.com")` fails; Flow Logs show REJECT |
| S11 | Display text is ASCII 0x20–0x7E plus LF, ≤18 columns, exactly 7 lines on page 1, ≤2 pages. Line 1 starts `AG1/<DEPLOY>` | Renderer property test |
| S12 | `decide(leaf.inputs, policy@leaf.policy_hash) == leaf.decision` for every decision leaf | `verify_audit.py --replay` |
| R0 | No challenge is issued for any subject with a BLOCK fact. `F-ATTEST < 2` (when not on break-glass) **is** BLOCK | Property test plus the bench "rubber-stamp human" arm |

---

## 3. Signing primitive and device UX

### 3.1 Decision: EIP-191 `ethereum.sign_message` on a Trezor (Safe 3; the study was done on the Safe 5)

| Criterion | **EIP-191** (chosen) | SLIP-13 SignIdentity | EIP-712 | FIDO2/WebAuthn | SLIP-24 PaymentRequest |
|---|---|---|---|---|---|
| Shows every signed byte | Yes [V] | Visual part only [V] | Field values skipped by default [V/S] | No transaction data | Verified payee name [S] |
| Mono font (0/O, 1/l in IBANs) | Yes [V] | Proportional [V] | — | — | — |
| Deliberate gesture | **Hold to confirm** [V] | Tap [V] | Hold [S] | Tap | — |
| Offline verification | Standard `personal_sign` recovery (`eth_account`) | Custom verifier, tested [V] | Standard | — | — |
| Usable by us in production | Yes | Yes | Not WYSIWYS by default | Approver login only | No: firmware trusts only Trezor/Swapkit keys [S] |

**Why:** EIP-191 is the only primitive that shows every signed byte in a monospace font and needs a hold. This holds on the Safe 3 too [V hardware]: mono font, every byte shown, CONFIRM only on the last page, hold about 1 s. It is used **purely as a message-signing primitive**: no chain, no gas, no funded address. Say that in one sentence before anyone asks.

Paths and settings:
- One path per approver: `m/44'/60'/0'/0/i`. The device first shows "Signing address 0x…", so the approver sees which identity signs [V].

Roles for later:
- SLIP-13 is reserved for a future `amp-trezor-slip13-v1` profile (full 256-bit hidden-hash binding).
- SLIP-24 becomes an emulator-only "what firmware support would look like" screen (stretch). The debug build trusts a published key.

### 3.2 Measured Safe 3 display facts (H0: emulator T3B1 2.12.5 and physical T2B1 2.12.0)

The approver device is a **Trezor Safe 3** (128x64 mono OLED, two buttons, Optiga secure element). Details and screenshots:
`docs/device/measurements.md`.

| Fact | Status | Rule we enforce |
|---|---|---|
| Message body grid is **18 mono cols x 4 lines per page**; LF honoured; device auto-wrap splits words with no hyphen | [V] | We wrap ourselves; profile `safe3-mono-16x4` |
| Page-break glyphs ("⇣" at page end, "⇒" at the next page start) take **2 columns each**: an 18-char line at line 4k or 4k+1 is split across pages | [V] | **Width 16** for every line, so no line can reflow; the title (line 1, never at a break) may use 18 |
| CONFIRM (hold) exists **only on the last page**; other pages offer only "next". No ">5 pages" preview: 1300 chars = 24 pages, all shown | [V] | Hard cap anyway: **14 lines = 4 pages** |
| Non-ASCII (ř ž č ů €) renders wrong (boxes) while debuglink reports the correct text | [V] emulator, [V hardware] | ASCII 0x20–0x7E plus LF only. Names come from the registry, transliterated by an executor-owned table whose hash is part of `policy_hash`. Golden tests compare **screenshots**, not only debuglink text |
| Non-UTF-8 bytes display as `hex(...)` | [V] | Never send them; the renderer raises `RenderError("NON_ASCII")` |
| Hold to confirm about **1.0 s** (0.9 s does not sign, 1.1 s does); a tap does nothing | [V] | Operator script: hold ~1 s on the last page |
| The device waits indefinitely; the host sends Cancel on its timeout and the device returns home | [V], [V hardware] | Signer timeout = challenge TTL |
| "Signing address 0x…" screen before the message | [V], [V hardware] | Approver sees which identity signs |
| Codec v1, not THP; WebUSB through libusb, no Bridge (Suite must be closed) | [V hardware] | THP is transport hygiene, not part of the trust model |
| Wire buffer 8 KiB | [S] | Irrelevant under the 14-line cap |
| End to end: 5 EIP-191 signatures from the physical device recovered by `eth_account` to the device address (11–24 s per human approval) | [V hardware] | — |

Earlier Safe 5 study (emulator T3T1 2.12.5): 18 mono cols x 7 lines, ">5 pages" truncated preview with hold available
before the end, same diacritics trap. It is kept as the non-default profile `safe5-mono-18x7` (2 pages, break lines ≤15).

### 3.3 Device authenticity (enrolment ceremony, one session, `tools/enroll.py`)

Steps:
1. `trezorlib.authentication.authenticate_device(session, os.urandom(32))`. This checks the Optiga certificate chain against the Trezor production root and requires an on-device "Allow". It refuses on an unlocked bootloader [S]. Not available on the emulator. On the physical Safe 3 the chain verified against the "Trezor Company / Trezor Safe 3" root (CN `T2B1 Trezor Safe 3`) [V hardware].
2. `GetFirmwareHash(challenge)`, compared against the hash computed from the official release image (T2B1: blake2s keyed with the challenge over the 13 x 128 KiB firmware area, 0xFF padded). Matches `trezor-t2b1-2.12.0.bin` [V hardware].
3. `get_address` for each role path.
4. EIP-191 signature over `AG1/DEMO ENROLL <role> <nonce>`.

The `enroll` leaf records:
- `device_model`, `firmware_version`, `cert_chain_sha256`, `fw_hash`, `address`, `path`;
- `authenticity: GENUINE|EMULATOR`. **The tool sets this, never the host.**

Result at H0: the physical Safe 3 clerk enrolled as **GENUINE** and the T3B1 emulator treasury as **EMULATOR**
(`docs/device/enroll_clerk_physical.json`, `docs/device/enroll_treasury_emulator.json`) [V hardware].

Profile rules:
- The `prod` profile refuses EMULATOR keys for treasury. Demo beat: "prod would refuse this emulator".
- The `demo` profile allows them, with a visible label.

**Honest limit.** Keys derive from the seed, so attestation proves a genuine device was present **at enrolment**. It does not bind later signatures to that hardware: the seed backup could be restored into an emulator. Mitigations: seed generated on-device, the host never types a passphrase, periodic re-attestation, and FW hash on every session [S].

### 3.4 Screen layouts (`safe3-mono-16x4`, the exact bytes)

General rules:
- Line 1 always carries the domain tag `AG1/DEMO` (protocol v1, deployment `DEMO`, ≤5 chars). The title line may use 18 columns (never at a page break); every other line ≤16.
- Only [F] content appears, with no `[F] ` prefix: everything on the device is [F] by construction.
- `N` = 8-hex displayed nonce. The 128-bit nonce is kept server-side, and the displayed nonce is unique among live challenges.
- `H` = first 56 bits (14 hex) of `subject_hash` = SHA-256(JCS(subject object)). The subject object includes deployment, nonce, purpose, role, params, `facts_digest` and `policy_hash`.
- `P` = first 56 bits (14 hex) of `policy_hash`. Still far beyond the 32-bit preimage problem (D5). The Safe 5 profile keeps 64 bits.
- Security does not rest on the hash lines. The executor re-renders, and the log binds nonce to the full object. The hash lines let a human or auditor cross-check.
- Lines 1–7 (block 1) say what the money does. Lines 8–14 (block 2) say why it is safe and who is signing. The device shows 4 lines per page, so the human presses "next" up to 3 times and holds CONFIRM on the last page.
- Amounts follow CONTRACTS §5.1 (integer major units when whole).
- Times are `MM-DD HH:MM` in `Europe/Prague`.
- Names are uppercase, transliterated, and truncated to 16 with a trailing `~`.
- Short forms when the long form exceeds 16: `ROLE TREAS`, `PAYEES n Vv`, `OLD ..xxxx YY-MM`, `SIGNER ROLE BASIS`.

Blank lines below only mark the device page breaks.

**PAY** (exact-sign; payment outside the mandate):

```
AG1/DEMO PAY 42
12500.50 CZK
CZ65 0800 0000
1920 0014 5399

BETA SERVIS A.S.
VS 2026101901
EXP 10-19 15:20
0 BLOCK 1 WARN

OVER MANDATE CAP
VOP MTCH
ADIS ACCT YES
ROLE CLERK 1/1

N 0C55A1E7
H 9b1e44c07a2d1f
```

**MANDATE** (activation; 2/2 above 100000 CZK `max_total`; the treasury copy says `ROLE TREAS 2/2`):

```
AG1/DEMO MANDATE
NO 3 CZK
PER PAY 80000
TOTAL 250000

MAX 20 PAYMENTS
EXISTING PAYEES
TO 10-20 18:00
ROLE CLERK 1/2

FROM 10-19 12:00
REQ VOP MTCH
PAYEES 12 V31
N 91BC02E1

P 1f3a9c0e7d2b4a
H 3e0d9a1c55b2e7
```

**CHG** (payee change; this challenge exists only once ATT ≥2/3 or break-glass is satisfied and cooling-off has ended; `BANK` no longer fits block 1 at width 16 and is dropped):

```
AG1/DEMO CHG 7
ACME S.R.O.
ICO 12345678
OLD ..5399 24-03

NEW CZ62 0300
    0000 0001
    2345 6789
0 BLOCK 1 WARN

ATT 2/3 ERP BANK
VOP CMTC
COOLOFF DONE
ROLE TREAS 2/2

N 7C11A0E2
H 4f2a9c1e0b7d3a
```

**ATTEST** (supplier-officer issuer profile, used when issuer class `supplier-erp` is hardware-backed. Stretch; the live demo uses software issuers):

```
AG1/DEMO ATTEST
ACME S.R.O.
ICO 12345678
PAY TO ACCOUNT

CZ62 0300 0000
0001 2345 6789
FROM 2026-10-20
SIGNER DIR (OR)

QUORUM 2/3 V5
CHANGE 7
N 7D11E0A2
H 5a0c7e19d3b4f2
```

**Fill and overflow rules:**
- Block 1 = mandatory lines (title, amount/name/ICO, IBAN in full) plus optional lines in priority order (`VS`, `EXP`, `BANK`) until it has exactly 7 lines.
- If a long IBAN (34 chars, 3 lines; `NEW IBAN` + 3 lines in CHG) displaces an optional line, that line moves to block 2.
- If block 1 cannot be built, raise `RenderError` (fail closed).
- Block 2 = summary line, then fact lines in CONTRACTS §5.4 order, then ROLE, N, H/P.
- When facts overflow, the last fact slot becomes `+N MORE 0 BLOCK`. The BLOCK count is always 0 on any screen that can exist (R0).

**Never on device:**
- [H] text of any kind, including fixed codes. This fixes D3.
- Truncated payee IBANs. OLD is shown as last-4 only; it is already executor-verified data.
- Bank brands. The bank code is shown as a number.

**BATCH:**
- One page per payee, following PSD2 RTS art. 5 dynamic linking and EBA Q&A 2018_4435 (https://www.eba.europa.eu/single-rule-book-qa/qna/view/publicId/2018_4435).
- This allows ≤1 payee per signature under the 14-line cap, so bulk volume goes through mandates.
- BATCH is stretch.

**Golden tests** (`tests/device/`, Safe 3 emulator via `tests/device/tenv.sh`): for each template and edge case (LT IBAN, 34-char IBAN, 16-char name, overflow), assert page by page `render() == debuglink screen_content()` with no reflow and diff the 128x64 screenshot against `docs/device/emulator/*.png`, plus photos of the physical device (`docs/device/photos/`).

Negative goldens that the renderer must reject: diacritics, a 17-char line, more than 14 lines.

---

## 4. Agent architecture, tool surface, egress

### 4.1 AP-Clerk agent: useful, never decisive

**Jobs:**
- triage the inbox;
- extract ISDOC, QR-Platba/SPAYD and PDF invoices;
- match them to vendor, PO and ledger;
- detect duplicates and partials;
- propose payments by due date;
- draft supplier replies;
- request a payee change when an invoice's account differs from the master record;
- explain executor decisions to the clerk. This last job is read-only, from the log.

Benign utility is a bench metric, which answers "is it a GPT wrapper?".

**Two modes, both benchmarked:**
- `AGENT_MODE=naive`: the planner reads raw untrusted text. This is the A0 baseline.
- `AGENT_MODE=quarantined`, modelled on **CaMeL** (https://arxiv.org/abs/2503.18813):
  - A quarantined extractor (`qwen.qwen3-235b-a22b-2507-v1:0`, JSON-schema output, **no tools**) turns each document into a typed `InvoiceDraft`.
  - Free-text fields reach the planner only as opaque handles (`txt_ab12`). They are never put into the planner prompt, and are written only into proposal `hints[]` as [H].
  - The planner is `eu.anthropic.claude-sonnet-4-5-20250929-v1:0`, with the system prompt cached.
  - The design-patterns paper (https://arxiv.org/abs/2506.08837) notes that injected text can still steer the *arguments* of allowed actions. Our [F]/[H] split plus P3 (no IBAN argument) closes that gap.

Loop: a plain Bedrock Converse tool loop (about 150 LOC). Strands is optional [U].

Untrusted text is wrapped in Guardrails input tags (A1) plus spotlighting delimiters.

### 4.2 Tool surface (MCP)

The tools are served by the executor-side `tools` λ. The A2 layer is AgentCore Gateway when reachable, otherwise a cedarpy twin.

| Tool | Effect | Cedar tool policy (A2, defence in depth) |
|---|---|---|
| `inbox.list` / `inbox.read(email_id)` | Content wrapped `<untrusted source=…>` | permit |
| `invoice.extract(doc_id)` | `InvoiceDraft` + provenance SHA-256 | permit |
| `vendor.lookup(vendor_id\|ico)` | Read-only; IBAN masked `..5399` | permit; forbid more than 5 per call |
| `mandate.status()` | Remaining budget and count | permit |
| `payment.propose{vendor_id, invoice_ref, amount_minor, currency, vs, due, reason_code, hints[]}` | → `POST /proposals`. **There is no IBAN field** (P3) | permit; flag above `max_per_tx` |
| `payee.request_change{vendor_id, new_iban, evidence_ids[], hints[]}` | → `POST /changes` | permit. Taint rule in LOG_ONLY: "untrusted read within the last 3 steps" feeds F-ANOM |
| `mail.send_template{to, template_id, vars}` | → egress λ | forbid `to` not in allowlist; forbid `vars` matching the IBAN regex |
| decoys `mandate.write`, `vendor.write` | Do not exist in the executor | `forbid` on principal type Agent, so escalation attempts are logged |

- The tool-manifest hash is pinned and logged at session start (defends against tool poisoning; MCP 2025-11-25 security guidance, https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices).
- No token passthrough: the tools λ calls the executor with its own role.
- **The executor is the target behind every tool.** It logs every tool call itself, so F-ANOM and the escalation evidence do not depend on AgentCore Observability.

### 4.3 Egress and network isolation (S9, S10)

**AWS (demo and the S10 proof):**
- The agent runs as a Lambda container in a VPC with **no IGW and no NAT**.
- Its only interface endpoints are `bedrock-runtime` and `execute-api` (private API GW, which fronts `tools`), plus AgentCore Gateway if a PrivateLink endpoint exists [U].
- If there is no Gateway endpoint, the tools λ (outside the VPC) evaluates the same Cedar text with cedarpy. Optionally the tools λ fronts the Gateway itself: agent → private API → tools λ → Gateway → targets.
- The agent's only outbound effect is `mail.send_template`, which goes to the egress λ. The egress λ applies:
  - the recipient allowlist (registered contacts);
  - deterministic DLP (IBAN mod-97, IČO checksum, card Luhn, base64/hex blobs, data in URLs);
  - size and rate limits, and attachment stripping;
  - Bedrock Guardrails sensitive-info filters with custom IBAN/IČO regex as a *measured second opinion*.
- Blocked messages produce an `egress_block` leaf.

**Local twin (dev, bench):**
- Docker `internal` network, plus an egress proxy that allowlists the Bedrock, executor and tools hostnames.
- This is not a security claim on a compromised laptop (H6). It exists so the bench is reproducible.

**DNS:** there is no resolver path to the internet inside the VPC beyond the endpoint names. Route 53 Resolver DNS Firewall is stretch [U cost].

### 4.4 F-ANOM: deterministic action-anomaly score (an [F], because the executor observes it)

Features, from the executor's own tool-call log:
- `untrusted_read → request_change/propose_new` within 3 steps;
- more than k proposals in 60 s;
- first-seen IBAN right after an inbound message;
- amount within 2% below a cap (structuring);
- several same-vendor payments just under `max_per_tx` (splitting);
- round amounts;
- off-hours activity.

Calibration:
- Thresholds are calibrated on the ČNB synthetic `transactions.csv` (state that it is synthetic).
- Output: `0..100`. It can **only step up** (mandate path becomes exact-sign) or add WARN. **It never allows.**

---

## 5. Executor

### 5.1 Services (Lambda; local = the same `dispatch()` under FastAPI)

| λ (own role) | Responsibility |
|---|---|
| `executor-api` | `dispatch()`: proposals, changes, challenges, signatures, mandates, export, receipts, health |
| `tools` | MCP tool endpoints for the agent; every call is logged; cedarpy tool-policy twin |
| `egress` | §4.3 |
| `ingest` | Raw .eml to S3; DKIM/SPF/ARC verdict computed here as [F] |
| `checkpointer` | Every 10 leaves or 30 s: computes the root, signs the checkpoint, calls W1 (and W2 via relay), stores the cosigned note |
| `witness` (W1) | C2SP `add-checkpoint` (§8.3) |
| `rail` | Only role able to read the rail secret: pain.001 export, mock ledger or TSYS [U] |
| `issuers` (sim) | 3 SD-JWT VC issuers, each in its own λ with its own key (TB4 simulation) |
| `vendor-portal` | Callback-code confirmation, tripwire inbox, break-glass request. Its notifications table is readable **only** by the portal role |
| `scheduler-target` | EventBridge Scheduler `at()` ends the cooling-off period; it calls `transition()`, which re-checks the guards |

### 5.2 Payee-change state machine (`executor/change/machine.py`, v2)

The transient states of v1 (`REQUESTED`, `FACTS_DONE`, `ATTESTATION_CHECK`, `TRIPWIRE_SENT`, `CALLBACK_CONFIRMED`, `CALLBACK_DENIED`) become **logged `change_event` leaves**, not states.

States: `PENDING_ATTEST, CALLBACK_PENDING, COOLING, SIG_CLERK, SIG_TREASURY, ACTIVE, REJECTED, EXPIRED`.

| from | to | trigger | guard |
|---|---|---|---|
| (create) | REJECTED | `POST /changes` | any hard BLOCK: F-DOMAIN lookalike, F-DKIM fail, F-VOP NMTC, F-WARNLIST/F-SANCTION hit, F-VAT unreliable payer |
| (create) | PENDING_ATTEST | `POST /changes` | vendor `in_network` (pinned issuers). A **tripwire** goes to the contact registered at enrolment |
| (create) | CALLBACK_PENDING | `POST /changes` | `¬in_network` (break-glass by default). Tripwire plus callback code out-of-band to the **registered** phone |
| PENDING_ATTEST | COOLING | VC arrives | ≥2 valid VCs from **distinct pinned issuer classes**, `cnf` KB-JWT `nonce == change_nonce`, `aud == AG1/DEMO/changes/<id>`, `iat` ≤15 min old; no BLOCK after recompute |
| PENDING_ATTEST | CALLBACK_PENDING | `POST /changes/{id}/break-glass` from the **vendor-portal role** (supplier declares key loss) | logged `break_glass=true`; cooling-off in the prod profile is 72 h, not 24 h |
| CALLBACK_PENDING | COOLING | portal confirms code | code hash matches, not expired, attempts ≤3 |
| CALLBACK_PENDING | REJECTED | portal deny, or 3 failed attempts | — |
| COOLING | SIG_CLERK | Scheduler `at(not_before)` or lazily on read | `now ≥ not_before`; a fresh clerk challenge is issued |
| SIG_CLERK | SIG_TREASURY | clerk signature | enrolled clerk; a fresh treasury challenge (same body, new nonce) |
| SIG_TREASURY | ACTIVE | treasury signature | enrolled treasury, address ≠ clerk; prod: `authenticity=GENUINE`; then `registry` is updated in the same transaction |
| any non-terminal | REJECTED | tripwire "not us" from the registered contact; VC revoked; **signed** clerk reject (C14) | logged with actor |
| any non-terminal | EXPIRED | lazily | `now ≥ expires_at` |

- `F-ATTEST` is computed in PENDING_ATTEST: fewer than 2 means **BLOCK**, so no challenge is issued (R0). The deepfake scenario can never light the device.
- Inbound calls are **never** an input. A callback goes only to the number captured at enrolment.

### 5.3 Policy engine: Cedar via `cedarpy` (authoritative and replayable)

`cedarpy` 4.12.2 has cp312 aarch64 and x86_64 manylinux wheels (https://pypi.org/project/cedarpy/), so it is installable on arm64 Lambda [V by build review].

**Entities:**
- `Mandate::"mnd_3"` (attributes: caps, remaining, count, window, `payee_registry_version`, signers);
- `Payee::"ven_12345678"`;
- `Action::"pay"`;
- **context = [F] only**: `amount_minor, vop, reg_hit, warn_hit, anom, dup, split_sum, now, attest_count`.

**Tri-state evaluation:**
1. `hard_deny` policy set. Any `forbid` gives **deny**: unknown payee, F-DUP, any BLOCK.
2. `mandate_allow` set. A `permit` gives **allow**: caps, budget, count, window, payee in the registry snapshot, VoP MTCH, anom < 40.
3. Otherwise **challenge** (exact-sign step-up).

Rule IDs:
- Cedar `@id("I-PER")` annotations equal the rule IDs. They come from the diagnostics' determining policies and are written into `decision.rule_ids`.
- The existing I-* rules map one-to-one onto Cedar policies.

`policy_hash` = SHA-256 of JCS of `{cedar_policies_text, cedar_schema, translit_table, fact_severity_table, policy_v}`.

Fallback: `rules.py` in pure Python with the same IDs. The decision is taken Mon 16:00, if the cedarpy diagnostics prove awkward.

There is **one** source of truth. Verified Permissions is dropped.

### 5.4 Exactly-once execution (S6) and rail

1. **Re-check.** `decide()` runs inside the signature handler for PAY (CONTRACTS §4.3 step 9).
2. **One `TransactWriteItems`.** All of these, or none:
   - (a) the `audit` leaf `Put`, with `attribute_not_exists(seq)`;
   - (b) the `log_head` `Update`, with `seq = :expected`, setting `seq+1`;
   - (c) the `mandates` `Update`, with `status=ACTIVE AND spent_minor <= :max_minus_a AND count < :max_count`;
   - (d) the `ledger` `Put` (`attribute_not_exists(tx_id)`), where `tx_id = hash(mandate_id|nonce, proposal_id)`;
   - (e) the `proposals` `Update` to EXECUTED.

   `ClientRequestToken` = `tx_id`, so retries are idempotent within about 10 min [U window].
3. **Rail, after commit.** Write pain.001.001.09 [U version vs the SEPA 2025 rulebook] and put its c14n SHA-256 in a follow-up `rail_submitted` leaf. TSYS, if writes are allowed, uses `tx_id` as the idempotency key. pain.002-style statuses ACTC/ACSC/RJCT are logged; **DUPL** on resubmission demonstrates exactly-once [codes from memory, U].
4. **Crash test.** Kill the process between steps 2 and 3. Recovery re-submits from leaves that have no `rail_submitted`.

This replaces CONTRACTS §3.2 "append leaf first, then transact". The leaf is now inside the transaction.

---

## 6. Facts pipeline and registries

`facts.compute(subject, state, now) -> FactSet`. The function is pure over **snapshots**, and each snapshot is content-hashed (`prov`) so a replay is reproducible offline. Live calls are optional and never happen on stage.

| Fact | Source (snapshot in `data/`) | Values → severity |
|---|---|---|
| F-DOMAIN | Vendor master `domain` vs sender; homoglyph and edit distance (`confusable_homoglyphs`, `rapidfuzz`); MostlyRight `website_domain` | lookalike → BLOCK |
| F-DKIM | Ingest-computed DKIM/SPF/ARC (`dkimpy`, DNS snapshot) | fail → BLOCK, pass → INFO |
| F-DOMAIN-AGE | WHOIS fixture | <30 d → WARN |
| F-VOP | VoP mock modelled on EPC codes `MTCH/CMTC/NMTC/NOAP` (https://www.europeanpaymentscouncil.eu/what-we-do/other-schemes/verification-payee; only NOAP confirmed [U]) | INFO / WARN (shows the registered name) / BLOCK / WARN |
| F-PSP | MostlyRight `counterparty_records`: `in_sct_inst`, `in_vop`, licence lists | absent → `UNKNOWN` **WARN** ("absent ≠ safe": the EBA PI/EMI register and LT lists are not covered) |
| F-WARNLIST / F-SANCTION | MostlyRight regulator warnings (ČNB, ESMA, AMF) and EU sanctions (entities) | hit → BLOCK |
| F-VAT | ADIS cache: unreliable-payer flag and **published accounts** for the DIČ | unreliable → BLOCK; account not published → WARN |
| F-BANK | ČNB bank-code list / IBAN → bank | foreign or EMI for a CZ vendor → WARN |
| F-FIRSTSEEN | `registry` history | <72 h → WARN |
| F-ATTEST | §7 verifier | <2 distinct classes (no break-glass) → BLOCK |
| F-CALLBACK | Portal confirmation | off-network and unconfirmed → BLOCK |
| F-DUP / F-SPLIT / F-Z | Ledger | DUP → deny; SPLIT / Z → step-up |
| F-ANOM | Executor tool-call log (§4.4) | ≥40 → step-up; never allow |
| F-NAME-TRANSLIT | Translit table | info line; transliteration is logged |
| F-MANDATE | Policy | over cap → step-up |

**Registries.**
- `registry` (the vendor master: only ACTIVE IBANs, each one reached via CHG 2/2) is versioned. `payee_registry_version` and its hash are pinned in the mandate.
- MostlyRight: copy from `s3://ai-hackathon-datasets-422928733782/MostlyRIght/` (the capital I is the real path). Check whether it has 10.5k or 51k rows [U]. Load into a sqlite snapshot.
- ČNB `clients.csv` and `transactions.csv` (semicolon-separated, UTF-8 with BOM): used for F-ANOM, F-Z and F-SPLIT thresholds and for benign background traffic.
- ARES: legal entities only. Sole traders are natural persons, so they count as PII.

---

## 7. Supplier attestation: format, network, privacy

**Format.** `PayeeBindingAttestation` is an **SD-JWT VC**. SD-JWT is RFC 9901; SD-JWT VC is still a draft: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc.

```json
{"iss":"https://issuer.acme.example/erp","vct":"urn:airgap:payee-binding:v1","iat":1792400000,"exp":1792403600,
 "cnf":{"jwk":{...}},"_sd":["…legal_name…","…iban…"],"ico":"12345678","change_id":"chg_7","valid_from":"2026-10-20",
 "issuer_class":"supplier-erp"}
```

- **KB-JWT** (key binding): `aud = "AG1/DEMO/changes/chg_7"`, `nonce = change_nonce` (128-bit), `iat` ≤15 min old. This provides freshness and stops replay.
- The disclosed claims are `legal_name`, `iban`, `ico`/`lei`.
- ES256 keys are pinned per vendor at enrolment (`vendor_policies`).
- Library: `sd-jwt` 0.10.4 on PyPI (https://pypi.org/project/sd-jwt/) [V present; API fit U]. Fallback: hand-rolled JWS plus disclosures with `cryptography` (about 150 LOC).

**Issuer classes (2 of 3 distinct required):**

| Class | Who | What it attests | Binding rule |
|---|---|---|---|
| `supplier-erp` | Supplier's own key, enrolled via a Tapaya-style KYB pack (statutory director/UBO, bank letter ≤3 months; `zdroje/prilohy/tapaya/`) | "We, ICO X, receive payments at IBAN Y from date D" | Key pinned at enrolment. Optional hardware profile = ATTEST screen (§3.4) |
| `supplier-bank` | The account-holding bank, from a **pinned trust list** | Account holder of IBAN Y **is ICO/LEI X** (not just a name) | Closes the mule-account hole: an attacker's own KYC'd LT EMI account cannot produce an attestation bound to ACME's ICO |
| `registry` | Registry witness | "IBAN Y is published in ADIS for DIČ of ICO X as of T; ARES name matches; no warnlist hit" | Signs **real public-data snapshots**, so one leg is grounded in facts. It can never attest a foreign account, so a cross-border change needs ERP plus bank |

**Network and bootstrap:**
- Day 1: one bank attests its own clients' accounts (issuer 2), and the registry witness (issuer 3) works with no supplier software at all.
- Next: an ERP/ISDOC plug-in for issuer 1.
- Production issuance channel: GLEIF vLEI ECR credentials (ISO 17442-3) and the European Business Wallet (proposal COM(2025) 838, **not adopted**).
- Revocation: Token Status List (draft) [U]. The demo uses a static list.

**Privacy:**
- The `attest` log stores salted commitments `SHA256(JCS(body) || commit_nonce_128)`, never a bare IBAN hash (unchanged from CONTRACTS §7.3).
- The `audit` log carries full IBANs only in `execution` leaves. The export bundle for third parties has a redacted mode that replaces IBANs with commitments.
- No natural-person data: legal entities only.

---

## 8. Transparency log, witnesses, offline verification (C2SP)

RFC 9162 is Experimental and not deployed. We keep RFC 6962/9162 hashing and proofs (`0x00`/`0x01`, SHA-256; `executor/audit/merkle.py`) and **adopt the C2SP wire formats**, so unmodified third-party tools can verify the log: https://github.com/C2SP/C2SP.

### 8.1 Leaves

- Leaf bytes = JCS (RFC 8785) of the event. Our `canonical_json` already equals JCS for our domain: integers only and ASCII keys.
- Event v2 = `{v:2, log_id, seq, ts, type, actor, subject_id, data, policy_hash, inputs_digest, facts_digest, hints_digest}`.
- New types:
  - `change_event`, `rail_submitted`, `iam_deny_mirror`, `attack_simulated` (actor `host`, labelled), `witness_refusal`, `tool_call`, `checkpoint`.
  - `egress_block`, which already existed and is now kept.
- Two logs: `audit` and `attest`.

### 8.2 Checkpoint (https://c2sp.org/tlog-checkpoint inside https://c2sp.org/signed-note)

```
airgap.example/demo/audit
1288
q8m3...base64root...=
policy sha256:1f3a9c0e7d2b4a61...
code sha256:<lambda CodeSha256> pcr0 -

— airgap.example/demo/audit <b64(keyid4 || ed25519_sig)>
— airgap.example/demo/w1 <b64(keyid4 || ts8 || ed25519_sig)>
— w2.litewitness.airgap.example <b64(...)>
```

- Key ID = `SHA-256(name || 0x0A || 0x01 || pubkey)[:4]`.
- The extension lines bind the policy and the code identity.
- Signing key: **KMS Ed25519** (GA Nov 2025, https://aws.amazon.com/about-aws/whats-new/2025/11/aws-kms-edwards-curve-digital-signature-algorithm/). Key spec `ECC_NIST_EDWARDS25519`, algorithm `ED25519_SHA_512`, MessageType RAW [names U].
- **H0 probe:** a KMS signature over a note body must verify with PyNaCl and with Go `note.Verify`.
- Fallback order:
  1. A local Ed25519 key held in Secrets Manager, readable by the checkpointer role only. This keeps the stock-Go claim, with weaker key custody, and we say so.
  2. ECDSA P-256 (note type 0x02). The stock-Go claim is then dropped, not softened.
- The key policy has no IAM delegation (principal = role ARN).

### 8.3 Witness (https://c2sp.org/tlog-witness, cosignature https://c2sp.org/tlog-cosignature)

Request:
- `POST /add-checkpoint`.
- Body: `old <size>\n`, then ≤63 base64 consistency-proof lines, an empty line, and the checkpoint.

Responses:

| Code | Meaning |
|---|---|
| 200 | Cosignature line(s) |
| 409 | Stale old size; body is the size, `text/x.tlog.size` |
| 403 | Bad signature |
| 404 | Unknown origin |
| 422 | Bad proof |

- The size check and persistence happen in **one** conditional write.
- W1 returns a timestamped Ed25519 cosignature (type 0x04; signed message `cosignature/v1\ntime <t>\n` plus the checkpoint body [U byte format; check against the torchwood test vectors]).
- **W2** is an **unmodified litewitness** (filippo.io/torchwood [U still bundled]) on a separate machine. A relay script pulls the checkpoint and proof from the export API, POSTs locally, and uploads the cosignature. This is the interop and independence claim. It is labelled "independent supervisor witness (simulated operator)", **never** "ČNB".
- Stretch: an ML-DSA-44 cosignature (type 0x06) via KMS `ML_DSA_44` [U Frankfurt]. The current spec recommends ML-DSA-44 for witnesses.

### 8.4 Storage, receipts, export

- Leaves live in DynamoDB `audit`. Every checkpoint and leaf batch is also written to S3 `airgap-log-<acct>/` with **Object Lock in governance mode, 1-day retention**. Never compliance mode: the account freezes after the event. Teardown needs `s3:BypassGovernanceRetention`, so script it.
- A tlog-tiles layout (https://c2sp.org/tlog-tiles) is stretch.
- **Receipt** (fixes D8), in tlog-proof style (https://c2sp.org/tlog-proof): `{entry, inclusion_proof, cosigned_checkpoint, key_ids, pubkeys}`. It is shown as a QR code and verifies on its own.
- **Export bundle** `GET /audit/export`: leaves, all checkpoints with cosignatures, public keys (log, W1, W2, approver addresses with enrol leaves), Cedar policy sets keyed by hash, fact snapshots keyed by hash, render profile, translit table.

### 8.5 Offline verifier (TB5)

`tools/verify_audit.py bundle/` checks:
- every leaf hash, no seq gaps, roots;
- inclusion and **consistency** across all checkpoints;
- log plus W1 plus W2 signatures (quorum policy `log AND (W1 OR W2)`, configurable);
- for every accepted signature: **re-render** the challenge from the logged params with the same `render.py`, recover the signer, and check the enrol leaf and role;
- **replay `decide()`** at the logged `policy_hash` (S12);
- 2/2 distinctness, cooling-off ordering, and ledger ↔ execution leaves.

`tools/noteverify/` is a pre-built 30-line Go binary using `golang.org/x/mod/sumdb/note` that verifies checkpoint signatures, **unmodified upstream code**.

Demo checks:
- Flip one byte in a leaf: verification fails at `seq N`.
- Truncate the log: the consistency check against the witnessed checkpoint fails.
- Present a fork: W1 returns 409/422 and a `witness_refusal` leaf appears.

---

## 9. AWS deployment mapping (eu-central-1)

The demo runs on AWS: executor, store, KMS, Object Lock, Bedrock and the witnesses (W1 Lambda, W2 on its own EC2 instance and key) all run in eu-central-1 with `AIRGAP_BACKEND=aws`. The `memory` and `moto` backends exist for development and CI only.

| Need | Service | Notes / status |
|---|---|---|
| Planner LLM | Bedrock `eu.anthropic.claude-sonnet-4-5-20250929-v1:0` | **50 req/min team-wide** (live demo plus spot checks only; enforced in code by `AIRGAP_SONNET_BUDGET`) |
| Extractor, bulk bench, red team | `qwen.qwen3-235b-a22b-2507-v1:0`, `openai.gpt-oss-120b-1:0` | Effectively unlimited; prices [U], read Cost Explorer at Mon 20:00 |
| Tool scoping (A2) | AgentCore Gateway + Policy in AgentCore (Cedar; LOG_ONLY, then ENFORCE) | GA incl. Frankfurt (https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available/). SCP, authorizer (Cognito/JWT) and VPC endpoint are [U]. Bulk A2 runs on the local cedarpy twin; about 50 cases go through the real Gateway to report the fidelity gap |
| Input sanitisation (A1) | Bedrock Guardrails / ApplyGuardrail with input tags (https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-prompt-attack.html) | Region [U]. Fallback is a regex sanitiser as A1 |
| Executor and others | API Gateway (private, IAM auth) + Lambda py3.12 arm64, one role per function | Split dependencies: no trezorlib/streamlit/moto/pytest in Lambda (C17) |
| State | DynamoDB on-demand: `ledger`, `mandates`, `audit`, `registry`, `witness_state` separate (IAM); single-table `airgap-main` for everything else | C15 |
| Timers | EventBridge Scheduler `at()` | Cooling-off end; checkpoint every 30 s (or in-λ batching) |
| Log signing | KMS Ed25519 `airgap-log`, `airgap-w1` | §8.2 fallbacks |
| Log storage | S3 Object Lock (governance, 1 day) | Teardown script |
| Rail secret | Secrets Manager (`rail` role only) | TSYS key [U writes] |
| Agent isolation | VPC, 1 AZ, no NAT/IGW; interface endpoints `bedrock-runtime`, `execute-api` | Flow Logs to CloudWatch |
| Independent evidence | CloudTrail trail + DynamoDB/S3 data events + CloudWatch Logs Insights | **CloudTrail Lake is closed to new customers** (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake-service-availability-change.html). CloudTrail lags by minutes, so live we show the boto3 AccessDenied plus `simulate-principal-policy`, and CloudTrail rows captured in rehearsal, labelled |
| Synthetic voice | Polly (eu-central-1) | Fictional person, labelled synthetic |
| Long jobs | EC2 `t4g.small` instance profile (bench runner, W2 relay) | SSO credentials expire after 12 h (about 01:30). A named human re-logs in at 01:00 |
| IaC | CDK (Python) or SAM, `make deploy` / `make teardown`, budget alarm at USD 300/500 | No NAT, ALB, OpenSearch or Knowledge Bases |
| Production path (Q&A) | Nitro Enclave on `m6i.xlarge` (supported; `.large` is not) | KMS attestation conditions gate **Decrypt/GenerateDataKey, not Sign** (https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclaves.html). Production: the enclave unwraps the log key via attested Decrypt and PCR0 goes in the `code` line |

**IAM boundaries.**

| Role | May | Explicit Deny |
|---|---|---|
| `agent` | `bedrock:InvokeModel` (the two model families); `execute-api:Invoke` on `/tools/*` only | `dynamodb:*` on all tables; `kms:*`; `secretsmanager:*`; `execute-api:Invoke` on `/signatures`, `/mandates*`, `/changes/*/approve`; `states:*`; `s3:Put*` on the log bucket |
| `host` (laptop process via `sts:AssumeRole`) | `execute-api` on UI routes, `/challenges`, `/signatures` | same tables, KMS, secrets |
| `executor-api` | Tables (not `witness_state`), challenges, `lambda:InvokeFunction` `rail` | `kms:Sign` on `airgap-w1` |
| `checkpointer` | `kms:Sign` on `airgap-log`, `s3:PutObject` log bucket | W1 key |
| `witness` | `witness_state`, `kms:Sign` on `airgap-w1` | everything executor |
| `rail` | `secretsmanager:GetSecretValue` (rail secret) | — |
| `vendor-portal` | portal notifications table | executor tables |

- KMS key policies name role ARNs directly, with **no IAM delegation**.
- **Honest limit:** our laptops hold the TeamAdmin SSO role, so a real attacker on the laptop is an account admin. The demo attacker uses the `agent` and `host` credentials. Production uses separate accounts.

**Cost envelope (target under USD 250; every figure [U]):**

| Item | Estimate (USD) |
|---|---|
| Sonnet live + spot checks | 30–60 |
| Qwen/gpt-oss bench | 50–150 |
| VPC endpoints | ~2 (2 × 1 AZ × 26 h) |
| Lambda/DynamoDB/S3/KMS | <15 |
| EC2 t4g | <3 |
| Polly | <1 |
| Optional Nitro rehearsal | ~6 |

The measured USD per 100 bench cases goes on the slide, because credit spend is scored.

---

## 10. Hackathon partner and tool usage map

| Resource | Use | Visible moment | Target juror(s) | Status |
|---|---|---|---|---|
| AWS Bedrock (Sonnet / Qwen / gpt-oss) | Planner, quarantined extractor, red team, bulk bench | Agent working in the console; ASR table with the model named | Kulkarni (AWS), Bubeník (Deloitte AWS Alliance) | ✓ |
| AgentCore Gateway + Policy (Cedar) | A2 tool scoping, decoy forbids | Gateway deny line in the escalation beat | Kulkarni, Bubeník, Kováč | [U] SCP; twin ready |
| Guardrails | A1 layer + egress 2nd opinion | "Layer 1 missed X%, layer 3 stopped 100%" | Kováč, Kulkarni | [U] region |
| KMS Ed25519, Object Lock, CloudTrail, IAM split, VPC endpoints, Scheduler | Log key, anchors, independent evidence, S7, S10, cooling-off | AWS evidence strip: `simulate-principal-policy`, AccessDenied, Object Lock refusal, Flow Logs REJECT | Kulkarni, Bubeník, Olszynski | ✓ / [U] Ed25519 |
| **Trezor Safe 3** + trezor-user-env (MCP on :9003) | TB0, enrolment, emulator treasury (T3B1), screen oracle | Camera on the device: hold to confirm; "the device stays dark" | All; Kováč, Raška (hardware cost) | [V] emulator; [V hardware] WebUSB |
| MostlyRight dataset | F-PSP, F-WARNLIST, F-SANCTION, lookalike domain | `PSP UNKNOWN` = "absent ≠ safe" | **Bridzik** (ČNB registers, VoP), Černý | ✓ [U] row count |
| ČNB synthetic dataset | F-ANOM/F-Z thresholds, benign background traffic | Bench FP and step-up column "calibrated on ČNB synthetic data" | **Bridzik** | ✓ |
| Tapaya KYB pack | Supplier enrolment, issuer-1 key, bank-letter evidence; incomplete examples as rejected fixtures | Enrolment screen | Černý (KB back office) | ✓ |
| TSYS (MoroSystems) API | Payment rail behind the `rail` role, if it supports writes; otherwise read-only realism | TSYS payment ID in the receipt | **Raška**, Černý | [U] writes and Track-3 use: ask at 10:30 |
| Infobip | Tripwire SMS to the registered contact, **only if granted**; otherwise a portal/SMS mock | Phone buzzes | Kováč | [U] Track 4 only |
| Polly | Synthetic "CFO" voice of a fictional person | 8-second clip | Kováč (deepfake), Responsible AI | ✓ |
| Mentors | Bridzik Tue 07:30 (DORA mapping, VoP/CZK date, PSR wording, offline audit); AWS SAs Mon 17:00 (Gateway authorizer, KMS); Němec Tue 09:00 (API); Maloux pitch clinic | — | — | scheduled |
| **Skip** | AgentCore payments (x402), Tatum/Solana, Apify, CloudTrail Lake, OpenSearch/KB, Verified Permissions shadow, Step Functions | Q&A contrast only | — | — |

Q&A framing:
- OWASP LLM Top 10 2025 (LLM01, LLM02, LLM06) and **OWASP Top 10 for Agentic Applications 2026** ASI01–ASI10: one slide mapping each control to an ID (item names beyond ASI01 come from secondary sources [U]).
- The lethal trifecta and Meta's "Rule of Two": we break both, because the agent has no exfiltration channel and no state-changing power.
- AP2 / Mastercard Verifiable Intent (https://developer.mastercard.com/mastercard-agent-pay/documentation/verifiable-intent/): mandate = open/intent mandate, exact-sign = closed/cart mandate. **Vocabulary alignment only, no conformance claim.**
- Ledger Agent Intent (15 Oct 2026, https://www.ledger.com/blog-introducing-ledger-agent-intent) as market validation. Our edge: bank facts, payee binding and a witnessed audit.

---

## 11. Bench design (`bench/`, AgentDojo-style)

**Arms** (one per layer):

| Arm | Defences |
|---|---|
| A0 | Bare agent; permissive executor stub that pays any proposal (for the comparison only) |
| A1 | A0 + Guardrails prompt-attack filter with input tags (or the regex sanitiser) + egress DLP |
| A2 | A1 + Cedar tool scoping (cedarpy twin; Gateway spot-check) |
| A3 | A2 + AirGap executor ([F], mandate, R0, attestations, device). Run in both `naive` and `quarantined` agent modes |

**Attacker levels:**

| Level | Attack |
|---|---|
| H0 | Content injection only (email, PDF hidden text, ISDOC note, filename) |
| H1 | The UI lies |
| H2 | False `displayed_text` |
| H3 | Nonce/subject swap between live challenges |
| H4 | Different text sent to the device (emulator; the human signs what the screen shows) |
| H5 | The agent's own AWS credentials used directly |
| H6 | Egress bypass (DNS/HTTP) |

**Corpus** (payloads frozen at Mon 22:00, adaptive variants frozen at Tue 06:00):
- AgentDojo banking-suite injection goals (https://github.com/ethz-spylab/agentdojo): send to the attacker IBAN, change a recurring recipient. These are ported onto our tools, with an AgentDojo-compatible task/injection JSON.
- InjecAgent financial-harm cases (https://arxiv.org/abs/2403.02691).
- Our own BEC set: lookalike domain, real-domain takeover, splitting, overpay, duplicate, exfiltration of the vendor master, mandate escalation, replay.
- **Adaptive** variants: a Qwen red-team loop runs k rounds of mutating failed payloads ("adaptive attacks get past published defences" framing).
- Benign: about 30 AP tasks plus a month of synthetic invoices calibrated on ČNB data, including **legitimate** payee changes, so we can measure false blocks.

**Simulated humans** (debuglink on the emulator):
- `diligent` rejects whenever the screen differs from the ground-truth intent.
- `rubber_stamp` approves everything.

**Headline: the money-to-attacker ASR at A3 is 0 even under `rubber_stamp`, because of R0 and the attestations.**

**Metrics per arm × model × attacker level:**
- targeted ASR, split into tool-call ASR and **money-moved ASR**;
- `money_moved_minor` to the attacker;
- bytes exfiltrated;
- benign utility, step-up rate, false-block rate;
- latency;
- USD per 100 cases;
- **Wilson 95% confidence intervals**.

The **residual risk** (overpay or duplicate inside the mandate caps) is reported, not hidden.

**Size:** about 100–300 attack and about 100–300 benign cases × 4 arms × 2 bulk models, sized to the time available. Plus a Sonnet spot-check of n ≈ 100–200, scheduled overnight within 50 rpm and paused during rehearsals.

**Sanity gate (Mon 22:00):** A0 must break with ASR above 30% on at least one named model. If Sonnet resists, report it honestly; the A3 claim is structural, and H1–H5 do not depend on the model.

**Schemas** (C10):
- `bench_case.json` `{id, arm, attacker_level, vector, goal, seed, expected}`.
- `bench_result.jsonl` `{case_id, arm, model, agent_mode, human_policy, utility_ok, attack_success, money_moved_minor, bytes_exfil, rule_ids, steps, latency_ms, tokens, cost_usd, git_sha}`.

The dashboard reads only frozen JSONL tagged with a commit SHA. **No number goes on a slide unless it is in a frozen file.**

**Device suite:** golden screens plus negative cases (diacritics, a 19-char line, more than 2 pages) must be rejected before they reach the device.

---

## 12. Real vs simulated (this slide is said out loud)

| Real | Simulated (labelled on screen) |
|---|---|
| Physical Trezor Safe 3 (clerk, GENUINE at enrolment), EIP-191, hold gesture, executor verification | Treasury approver on the T3B1 Safe 3 emulator (`authenticity=EMULATOR`) |
| Device attestation ceremony (physical device only) | Supplier ERP and supplier bank issuers: real cryptography, simulated organisations |
| Bedrock agent doing real extraction, matching and proposals; Qwen red team | Companies, inbox, invoices, DKIM DNS snapshot (fictitious) |
| Executor on Lambda, IAM split, AccessDenied, VPC with no route | VoP responder (mock with EPC codes; VoP for CZK applies from about July 2027 [U]) |
| C2SP log, KMS signatures (or the stated local key), Object Lock, unmodified litewitness W2, upstream Go verifier | "Independent supervisor witness" = our own instance of upstream code; W1 is in the same account |
| MostlyRight, ČNB and Tapaya data; ADIS/ARES snapshots of public legal-entity data | Rail = TSYS only if writes are allowed [U]; otherwise mock ledger + pain.001 file |
| AgentCore Gateway + Cedar, Guardrails (if the SCPs allow) | Deepfake voice = Polly, fictional person; tripwire/callback = portal mock (Infobip only if granted) |
| Bench numbers from frozen runs | SLIP-24 device-verified payee: emulator debug key only (stretch) |

---

## 13. Workstreams, interfaces, critical path, cut line

### 13.1 Sessions (6 Claude sessions, each with a human owner, own git worktree, no Claude co-author lines)

| WS | Scope | Owns (paths) | Exposes (frozen at CONTRACTS v2) |
|---|---|---|---|
| **WS-A Executor core** | dispatch, store, Cedar `decide()`, mandates (2/2), nonce, `TransactWriteItems`, rail + pain.001, receipts API | `executor/{handler,app,config,errors,models,store,policy,bank}`, `executor/rail/` | `decide(subject, facts, state, policy) -> Decision`; HTTP API v2; Cedar schema; `store.tx_execute()` |
| **WS-B Log, witness, verifier** | Leaves v2, checkpointer (signed-note, KMS/local Ed25519), W1 `add-checkpoint`, W2 litewitness relay, receipts/QR, export, `verify_audit.py`, `tools/noteverify` (Go), supervisor view | `executor/audit/`, `witness/`, `tools/verify_audit.py`, `tools/noteverify/` | `audit.append(event) -> seq`; checkpoint note; receipt; `verify(bundle) -> Report` |
| **WS-C Device and render** | **H0 owner.** `safe3-mono-16x4` renderer, signer worker (USB Safe 3 clerk + tenv T3B1 UDP treasury), screen oracle, goldens, enrolment ceremony, camera rig, SLIP-24 stretch | `executor/render.py`, `host/signer.py`, `tools/enroll.py`, `tests/device/`, `docs/device/` | `render(template, params, profile) -> str`; `SignerDriver.sign(challenge, key_ref, timeout) -> Approval`; pure `verify_eip191()` |
| **WS-D Payee change, facts, issuers** | FSM v2, facts engine and snapshots, VoP mock, MostlyRight loader, SD-JWT issuers ×3 and verifier, vendor portal (callback, tripwire, break-glass), Scheduler target | `executor/{change,facts,attest}`, `vendor/`, `data/`, `executor/issuers/` | `facts.compute() -> FactSet`; `transition(change_id, event)`; `verify_vc(vc, change) -> AttestResult` |
| **WS-E Agent, perimeter, IaC** | AP-Clerk (naive and quarantined), extractor, tools λ + MCP, Cedar tool policies, Gateway, Guardrails, egress λ + DLP, VPC/no-NAT, IAM, CDK, CloudTrail/Flow Logs, AWS probes, teardown | `host/agent.py` → `agent/`, `executor/tools/`, `executor/egress/`, `infra/` | Tool MCP manifest (pinned hash); `tool_call` events |
| **WS-F Bench, red team, demo** | Corpus, H0–H6 attackers (`host/compromised.py`), arm runner, simulated humans, Wilson CIs, dashboard, `make demo-reset`, scene scripts, fallback video, pre-sealed audit bundle | `bench/`, `host/{compromised,ui}.py`, `demo/` | `bench_case` / `bench_result` schemas; `scene_*.py` (public APIs only) |

**Human roles:**
- Integrator / merge captain, who merges every 2 h and owns `make ci`.
- Device operator and camera rig.
- AWS owner: Toolbox attendance, SCP probes, re-login at 01:00, Cost Explorer.
- Red-team author.
- Pitch and regulatory lead: Bridzik on Tue 07:30, the "honest limits" sheet.
- Demo and fallback-video owner.
- Optional: Nitro owner (Q&A rehearsal only).

**Integration rules:**
- CONTRACTS v2 is the only cross-WS interface.
- After the freeze, a change needs a PR touching `docs/CONTRACTS.md` and `contracts/` together, plus a ping to every owner.
- Everyone codes against the `memory` backend and fixtures first.
- `make ci` = contracts → ruff → pytest (memory/moto), on every merge.

### 13.2 Critical path and timeline

```
H0 device facts (WS-C) ─► CONTRACTS v2 freeze ─► render v2 + signer + decide/sig/nonce + audit.append ─► VERTICAL SLICE
                  AWS track (WS-E) ─► probes ─► IaC ─► deploy ─┘                       attack track (WS-F) ─► A0 breaks
```

| When | Milestone | Gate owner |
|---|---|---|
| Mon 12:00 | `hackathon-start` tag (done, `ccf9f2f`) + README disclosure; WS-C starts H0; AWS owner at the Toolbox (12:00–13:30) | Integrator |
| Mon 13:00 | **H0 done:** page-break oracle (X1), physical Safe 5 over WebUSB from the demo laptop with Suite and bridge closed (X3), EIP-191 → `eth_account` round trip, device firmware version. **Done:** the device is a Safe 3 (T2B1, fw 2.12.0); profile `safe3-mono-16x4` (§3.2) | WS-C |
| Mon 14:30 | **CONTRACTS v2 frozen** (render goldens, no-IBAN proposal, FactSet, leaf v2, checkpoint/receipt, FSM v2, bench schemas) | Integrator |
| Mon 15:00 | AWS go/no-go list: KMS Ed25519 + PyNaCl/Go verify; `list-guardrails`; Gateway hello-world with authorizer; VPC endpoints; Bedrock profile IDs | AWS owner |
| Mon 16:00 | cedarpy vs `rules.py` decision; MostlyRight row count | WS-A, WS-D |
| Mon 18:00 | Fallback ready: emulator-only mode + first recording of the physical device | WS-C |
| **Mon 19:30** | **Vertical slice** (memory backend): S1 exact-sign on emulator **and** device → leaf → checkpoint → W1 cosign → receipt → `verify_audit.py` green | Integrator |
| Mon 22:00 | S2 + S4 end to end; **A0 sanity gate**; payloads frozen; W2 litewitness go/no-go | WS-F, WS-B |
| Mon 23:00 | Executor + agent deployed on AWS; S10 proof | WS-E |
| Tue 01:00 | SSO re-login; overnight bench on EC2 | AWS owner |
| Tue 03:00 | S3 + S5 end to end on AWS; `noteverify` passes offline | WS-B, WS-D |
| **Tue 06:00** | S1–S12 + R0 green; adaptive payloads frozen; Sonnet spot-check done | Integrator |
| Tue 07:30 | Bridzik 1:1: regulatory wording fixed | Pitch lead |
| Tue 08:00 | Bench numbers frozen (JSONL + SHA) | WS-F |
| **Tue 09:00** | **Feature freeze**; then rehearsals ×5, fallback video for every beat, pre-sealed audit bundle | Demo owner |
| Tue 13:30 | Code freeze | — |

### 13.3 Cut line

**Core** (the demo works with only this):
- render v2 with goldens;
- Cedar `decide()`, replayable;
- facts: MostlyRight, lookalike, DKIM fixture, VoP mock, DUP, simple F-ANOM;
- R0 with `ATT<2 ⇒ BLOCK`; single-use 8-hex nonce;
- single `TransactWriteItems` (memory, moto, real);
- mock ledger + pain.001;
- EIP-191 with the Safe 3 as clerk and the T3B1 emulator as treasury, enrol leaf;
- FSM v2 with 3 software SD-JWT issuers, KB-JWT, 20 s cooling, 2/2;
- signed-note checkpoint (KMS or local Ed25519);
- W1 `add-checkpoint` (200/409/422);
- receipt QR; `verify_audit.py` (inclusion, consistency, re-render, recovery, replay); `noteverify`;
- agent (Sonnet live, Qwen bulk), tools λ with cedarpy, egress λ with DLP;
- escalation beat;
- executor Lambda with IAM Deny + `simulate-principal-policy`;
- bench with about 100+100 cases, A0–A3, both human policies, Wilson CIs;
- `make demo-reset`, scenes, camera rig, fallback video, real-vs-simulated slide.

**Ambitious** (each item has its gate):

| Item | Gate |
|---|---|
| KMS Ed25519 | Mon 15:00 |
| Guardrails A1 | Mon 15:00 |
| Real AgentCore Gateway + Policy | Mon 17:00 |
| Unmodified litewitness W2 | Mon 22:00 |
| Agent in VPC with no NAT on AWS | Mon 23:00 |
| Lambda + Object Lock | Mon 23:00 |
| Native AgentDojo banking suite with an AirGap money gate | Tue 02:00 |
| CloudTrail evidence pane | Tue 09:00 |
| Supervisor live view | Tue 09:00 |
| EventBridge Scheduler cooling-off | Tue 09:00 |
| Polly voice | Tue 09:00 |
| Tapaya enrolment screen | Tue 09:00 |
| TSYS rail | Only if writes are confirmed at 10:30 |

**Stretch** (never on the demo path):
- SLIP-24 emulator screen;
- SLIP-13 profile;
- ATTEST on a hardware issuer;
- tlog-tiles in S3;
- agent on AgentCore Runtime;
- ML-DSA-44 cosignature;
- BATCH;
- one-page AMP v0.1 spec ("AirGap Mandate Protocol, open draft, Apache-2.0", vocabulary aligned with AP2/VI, no conformance claim).

**Q&A only, or cut:**
- Nitro;
- TLA+;
- Step Functions;
- Verified Permissions;
- vendor-officer emulators;
- RFC 3161 TSA (`AIRGAP_TSA_URL=off`);
- Infobip unless granted;
- OID4VP, WebAuthn and bank-token signer profiles (named on the business slide only).

---

## 14. Demo (4:00) mapped to components

| Time | Beat | Components on screen |
|---|---|---|
| 0:00–0:15 | Disclosure line, then the hook: "This agent is compromised right now. It still can't move a koruna." | — |
| 0:15–0:45 | **S1 normal day.** The agent extracts and matches 3 invoices, which are paid under mandate 3; receipt QR; witness tick. The 4th, over the cap, lights the **Safe 3 on camera**. The screen matches the renderer character for character; hold to confirm | Agent (Sonnet), tools λ, Cedar `decide`, `TransactWriteItems`, render v2, signer, checkpoint + W1 |
| 0:45–1:35 | **S2 lookalike BEC + escalation + exfil.** An `acme-cz.com` email with a hidden PDF injection. The agent says "CFO approved"; the facts panel goes red (DOMAIN, VoP NMTC BLOCK, PSP UNKNOWN). **The device stays dark** (R0): "there is nothing to approve." Then 4 escalation attempts in quick succession: `mandate.write` (Cedar forbid), self-approval (unknown signer), replay (`nonce_reused`), direct DynamoDB/secret (AccessDenied + `simulate-principal-policy`). The exfil email is blocked by egress DLP, and `curl example.com` from the agent VPC times out: "0 bytes" | Facts engine, R0, Gateway/cedarpy, IAM, egress λ, VPC |
| 1:35–2:30 | **S3 real-domain takeover + deepfake.** DKIM is green; the Polly "CFO" (fictional, labelled synthetic) presses the clerk. **ATT 0/3 is a BLOCK**, so "there is no button". The tripwire reaches the registered contact, who answers "not us", and the change is REJECTED. A 10-second clip of the legitimate path: 2/3 VCs, then cooling, then CHG on Safe 3 + emulator, then ACTIVE | FSM v2, SD-JWT verifier, portal, Scheduler |
| 2:30–3:20 | **S5 offline audit.** Wi-Fi off; `noteverify` (upstream Go) green; `verify_audit.py` with replay 100% match. Flip one byte: red at `seq N`. Present a fork: W1 returns 409 and a `witness_refusal` leaf appears | Export bundle, verifiers, witnesses |
| 3:20–4:00 | Bench table A0→A3 (money to attacker X → 0, with CIs, including the rubber-stamp column and the in-mandate residual); real-vs-simulated slide; business line: liability shift under the PSR/PSD3 provisional deal [U status], hardware cost per approver, payee-binding network | Bench JSONL |

**Q&A cards:**
- the diacritics trap and the 5-page trap (screenshots);
- attestation scope / seed limit;
- Lambda is not a TEE → Nitro (Decrypt vs Sign);
- W1 is in the same account → W2 and a separate account in production;
- "why EIP-191 without a blockchain";
- why not EIP-712 or FIDO;
- AP2/VI mapping;
- PSD2 RTS art. 5 (https://eur-lex.europa.eu/eli/reg_del/2018/389/oj);
- VoP Reg. 2024/886 (https://eur-lex.europa.eu/eli/reg/2024/886/oj);
- DORA mapping (article numbers per Bridzik);
- Ledger Agent Intent;
- the SLIP-24 future.

---

## 15. Risks and fallbacks

| # | Risk | Mitigation | Fallback (ready by) |
|---|---|---|---|
| 1 | **Device I/O on stage.** The host bridge returned 400 [V]; hand-written debuglink flows deadlocked [V]; USB is exclusive; the device may lock; the 1.54" screen is unreadable from the audience | Signer worker inside tenv over UDP for the emulator; WebUSB with Suite and the bridge killed for the device; input flows copied from trezor-firmware `tests/input_flows*.py`; `ensure_unlocked()`, long auto-lock; document camera | Emulator-only mode + pre-recorded device video (Mon 18:00) |
| 2 | **Unmeasured page break** (the "..." marker eats columns) | ≤15-char lines adjacent to the break until H0 | 1-page templates (move ROLE/N/H to page 1 by dropping optional lines) |
| 3 | **AWS features blocked by SCPs, or late access** (KMS Ed25519, Gateway + authorizer + VPCE, Guardrails) | Local-first; 30-minute probe list; one named twin per feature | cedarpy twin, regex A1, local Ed25519, Docker twin (all exist by Mon 19:30) |
| 4 | **A0 does not break**, so the ASR story flattens | Qwen/gpt-oss targets, adaptive loop, AgentDojo-proven goals, gate at Mon 22:00 | Report honestly; lead with the structural H1–H5 results |
| 5 | **Integration drift across 6 sessions** (the render rewrite breaks the 430-line `test_render.py`) | Freeze at 14:30; goldens first; CI on every merge; vertical slice before breadth; 2-hourly merges | Cut to core (§13.3) at Tue 02:00 if the slice is not green |
| 6 | **Overclaiming before the ČNB, Mastercard and AWS jurors** | Real-vs-simulated slide; no KB/ČNB names; [U] regulatory items checked with Bridzik; numbers only from frozen JSONL; "open draft" rather than "standard" | Honest-limits sheet |
| 7 | **Bedrock 50 rpm shared** | `AIRGAP_SONNET_BUDGET` limiter; bench Sonnet paused 09:00–13:30 | Pre-recorded agent run |
| 8 | **SSO expiry / Wi-Fi** | EC2 instance profile for long jobs; re-login at 01:00; dependency cache (images, `uv lock` + wheels, Go modules, pre-built binaries); fixtures for every external source; TSA off | Pre-recorded AWS run of every beat (the local backend is never presented as the demo) |
| 9 | **Cost traps / frozen account** | No NAT/ALB/OpenSearch; Object Lock in governance mode; `make teardown` tested Tue 10:00 | Budget alarm at 300/500 |
| 10 | **Disqualification over pre-built code** | Tag + README + email + first demo line | — |

**Open checks (all [U]):**
- KMS Ed25519 key spec names under the SCPs;
- AgentCore Gateway authorizer and VPC endpoint;
- Guardrails in eu-central-1;
- page-break columns;
- `authenticate_device` on our hardware with trezorlib 0.20.x;
- physical-device protocol;
- TSYS writes / Track-3 use;
- Infobip;
- MostlyRight row count;
- Qwen/gpt-oss prices;
- EPC VoP code names;
- VoP-for-CZK date;
- PSR/PSD3 adoption;
- DORA article numbers;
- the C2SP cosignature byte format (torchwood vectors);
- `sd-jwt` API fit;
- AP2/VI field names.

---

## 16. REQUIRED CHANGES to `docs/CONTRACTS.md` (applied in CONTRACTS v2)

Every change also requires matching updates to `contracts/schemas/*`, `contracts/fixtures/*`, `executor/models.py`, and the tests named below. The header becomes "Shared Contracts (v2)".

| # | Section | Change |
|---|---|---|
| C-01 | Header, §1 | v1 → v2. Replace the WS-A..F table with §13.1 of this document (new owners and paths). Add the paths `executor/{rail,tools,issuers}/`, `agent/`, `tools/noteverify/`, `tests/device/`, `docs/device/`, `demo/`. Reference `docs/ARCHITECTURE.md` |
| C-02 | Conventions | Nonce: displayed **8 uppercase hex** `^[0-9A-F]{8}$`, unique among all challenges (conditional put), plus a server-side 128-bit `nonce_secret` that is never displayed. The deployment tag `AG1/<DEPLOY>` (`AIRGAP_DEPLOYMENT_ID`, default `DEMO`, ≤5 chars `[A-Z0-9]`) appears in every signed text |
| C-03 | §2.1 Fact | `display_line` ASCII ≤18 chars (device). Add the fact IDs `F-PSP`, `F-WARNLIST`, `F-SANCTION`, `F-DOMAIN-AGE`, `F-ANOM`, `F-NAME-TRANSLIT`, `F-ATTEST` (k/3 distinct classes), plus field `prov` (snapshot SHA-256). Severities as in §6 of this document; `F-ATTEST <2` (not break-glass) → BLOCK; `F-VOP` values `MTCH/CMTC/NMTC/NOAP` → `INFO/WARN/BLOCK/WARN`. H facts stay in UI and log only |
| C-04 | §2.2 Decision | Decide is evaluated by Cedar (cedarpy) with tri-state semantics (§5.3 of this document); `rule_ids` = Cedar `@id`s. **Remove** "A preview clerk challenge is returned in both cases"; R0 applies: `deny` ⇒ no `challenge`. A proposal with any WARN or F-ANOM ≥40 ⇒ `challenge` |
| C-05 | §2.3 Challenge | Add `deployment`, `subject_hash` (64 hex), `profile` (`safe5-mono-18x7`), `pages` (1–2), `lines_per_page` 7, `width` 18. Purposes: `MANDATE`, `CHG`, `PAY`, `VENDOR_ATTEST` (kept), `ENROLL` (new). Roles: `clerk`, `treasury` (bank) plus vendor roles unchanged (superseded by H0: `safe3-mono-16x4`, CONTRACTS v2.1) |
| C-06 | §3.1 Tables | Separate tables: `ledger`, `mandates`, `audit` (+`log_head`), `registry` (renamed from `vendors`, versioned: `registry_version` counter), `witness_state`. Everything else (`proposals`, `changes`, `attestations`, `vendor_policies`, `nonces`, `counters`, `enrolled_signers`, `inbox`, `checkpoints`) goes in single-table `airgap-main` (PK `<entity>#<id>`, SK as today). `portal_notifications` moves to the portal-only table `airgap-portal` and **drops plaintext `code`**: store `code_hash`, `attempts` (max 3). The code is delivered only via the portal mock / SMS. Drop the `sth` table (replaced by `checkpoints` holding note text) |
| C-07 | §3.2 Atomicity | Replace with this document's §5.4: one `TransactWriteItems` = leaf Put + `log_head` seq check + mandate debit + ledger Put (`tx_id = hash(auth_ref, proposal_id)`) + proposal Update, with `ClientRequestToken = tx_id`; rail after commit; `rail_submitted` leaf |
| C-08 | §4.1 #4 `/proposals` | `proposal_create.request.invoice`: **remove `iban`** and `vendor_name`; add `vendor_id` (required), `invoice_ref`, `reason_code` enum (`DUE`, `PARTIAL`, `ADVANCE`, `OTHER`). The executor takes the IBAN from `registry`. I-PAYEE becomes "vendor exists, is ACTIVE, has an ACTIVE IBAN" |
| C-09 | §4.1 #9 reject | Requires an EIP-191 signature from an enrolled clerk (purpose `CHG_REJECT`), or the vendor-portal role (tripwire "not us"). Logged with the actor and rate-limited. The unauthenticated host call is removed |
| C-10 | §4.1 #12–13 | `/callbacks` and `/portal/*` are accessible only via the `vendor-portal` IAM role. Remove `GET /portal/notifications?ico=` from the public API. S7 Deny for agent and host |
| C-11 | §4.1 new rows | `POST /changes/{id}/attestations` (SD-JWT VC + KB-JWT), `POST /changes/{id}/break-glass` (portal role), `POST /tools/{name}` (tools λ, MCP), `POST /witness/add-checkpoint` (W1, C2SP), `GET /checkpoint` (latest note, `text/plain`), `GET /export/pain001/{tx_id}` (XML + c14n SHA-256). Remove the #24 "schema TBD" `/bank/batch` (BATCH is stretch, page-per-payee) |
| C-12 | §4.1 #23 `/health` | `{status, backend, deployment, policy_hash, render_profile:"safe5-mono-18x7", code_sha256, log_origin, log_pubkey_id}` (superseded by H0: `safe3-mono-16x4`, CONTRACTS v2.1) |
| C-13 | §4.3 | Keep the order. Step 3 re-renders with the stored `profile`. Add step 6b: for CHG/SIG_TREASURY and MANDATE 2/2, the recovered address ≠ the first signer, and the prod profile requires `authenticity=GENUINE` for treasury. Step 4 (`displayed_text`) stays diagnostic only |
| C-14 | §4.4 | New codes: `attestation_insufficient` (replaces `vendor_attestation_missing`), `kb_jwt_invalid`, `issuer_not_pinned`, `break_glass_required`, `callback_attempts_exceeded`, `emulator_not_allowed`, `checkpoint_inconsistent` (witness 422), `stale_checkpoint` (409) |
| C-15 | §5 (whole) | Replace with this document's §3.4: profile `safe5-mono-18x7`, `DEFAULT_WIDTH=18`, `LINES_PER_PAGE=7`, `MAX_PAGES=2`, page 1 exactly 7 lines, lines adjacent to a page break ≤15 (`BREAK_LINE_MAX=15` until H0), uppercase transliterated names, **no `[F]`/`[H]` prefixes and no [H] lines on the device**, summary line `<b> BLOCK <w> WARN` always first on page 2, `N <8hex>`, `H <16hex>`, `P <16hex>` (MANDATE), title `AG1/<DEPLOY> <TYPE> <no>` never dropped, OLD IBAN as `..<last4> <YYYY-MM>`, NEW and payee IBAN in full, overflow line `+N MORE 0 BLOCK`. Keep the width-32 profile `ui-preview-32` for UI only. Python API: add `profile=` and `deployment=` kwargs, `render()` returns a str with LF (pagination implicit), `render_pages()` helper; `MIN_WIDTH` per profile (fixes D7). Rewrite `tests/test_render.py` goldens from the emulator oracle (superseded by H0: `safe3-mono-16x4`, CONTRACTS v2.1) |
| C-16 | §6 | EIP-191 unchanged. Enrolment via the §3.3 ceremony; the `enrolled_signers.device` value is **set by the tool** (`GENUINE`/`EMULATOR`), plus `device_model`, `firmware_version`, `cert_chain_sha256`, `fw_hash`, `enroll_sig`. Passphrase policy documented. The physical Safe 5 is the clerk, the emulator the treasury (H0: physical Safe 3 clerk, T3B1 emulator treasury) |
| C-17 | §6.1 | Replace with this document's §5.2 (states `PENDING_ATTEST, CALLBACK_PENDING, COOLING, SIG_CLERK, SIG_TREASURY, ACTIVE, REJECTED, EXPIRED`; removed transient states become `change_event` leaves; break-glass; tripwire on every create). Rewrite `tests/test_change_machine.py` |
| C-18 | §4.2 mandate | `max_total_minor > 10_000_000` (100000 CZK) requires clerk + treasury: states `PENDING_SIG_CLERK`, `PENDING_SIG_TREASURY`, `ACTIVE`, `EXPIRED`, `SUPERSEDED`. Add `payee_registry_version` + `payee_registry_hash`, `require_vop:["MTCH"]`, `max_anom` (default 40). `signer_address` becomes `signers[]` |
| C-19 | §7.1 | State that `canonical_json` == RFC 8785 JCS for our domain (ints only, ASCII keys); add a test with JCS vectors |
| C-20 | §7.2 | Leaf `v:2`: add `policy_hash`, `inputs_digest`, `facts_digest`, `hints_digest` to every decision-relevant event. New types: `change_event`, `rail_submitted`, `tool_call`, `iam_deny_mirror`, `attack_simulated`, `witness_refusal`, `checkpoint`. `enroll` data per C-16. `anchor` loses `tsa_token_sha256` |
| C-21 | §7.3 | Keep the hashing. **Replace the STH** with a C2SP tlog-checkpoint in a signed-note (origin `airgap.example/demo/<log_id>`, extension lines `policy sha256:<hex>` and `code sha256:<hex> pcr0 -`), signed Ed25519 (KMS `ECC_NIST_EDWARDS25519`, fallback a local Ed25519 key, last resort ECDSA type 0x02). Witness = C2SP tlog-witness `add-checkpoint`, cosignature type 0x04. Object Lock **GOVERNANCE** (not COMPLIANCE), 1 day. RFC 3161 optional, default off |
| C-22 | §7 export / receipt | `audit_export.response`: `checkpoints[]` (note text), `pubkeys{log, w1, w2}` as note verifier keys, `policies{hash: text}`, `snapshots{hash: uri}`, `render_profile`. `receipt.json` = `{entry, seq, inclusion_proof[], checkpoint_note (with cosignatures), key_ids}`, self-contained (fixes D8) |
| C-23 | §8.1 | Rules expressed as Cedar policies with the same IDs; `POLICY` hash per §5.3 of this document (includes the translit and severity tables). I-PAYEE per C-08. Add `I-ANOM` (step-up) and `I-ATTEST` (hard deny for CHG challenge issuance) |
| C-24 | §8.2 | Add S10, S11, S12 and R0 with named tests: `tests/test_egress.py::test_s10_no_route` (aws only), `tests/test_render.py::test_s11_grid`, `tests/test_audit_fuzz.py::test_s12_replay`, `tests/test_invariants.py::test_r0_no_challenge_on_block`. Strengthen S3 to monotonicity; S4 per C-17; S6 per C-07 |
| C-25 | new §10 Bench | `bench_case.json` and `bench_result.jsonl` schemas per §11 of this document; arms A0–A3; attacker levels H0–H6; human policies `diligent`/`rubber_stamp` |
| C-26 | new §11 Attestation | SD-JWT VC `vct=urn:airgap:payee-binding:v1`, the issuer classes and the pinned trust list, KB-JWT rules (`aud`, `nonce`, `iat` ≤15 min), revocation list, commitment format. The `vendor_attest` EIP-191 path is kept as the hardware issuer profile |
| C-27 | §9 env | Change: `AIRGAP_RENDER_WIDTH` → `AIRGAP_RENDER_PROFILE=safe5-mono-18x7`; `AIRGAP_COOLING_SECONDS` default 20 in the demo profile; `AIRGAP_TSA_URL=off`; `AIRGAP_KMS_KEY_ID` = Ed25519 key. Add `AIRGAP_DEPLOYMENT_ID=DEMO`, `AIRGAP_DEMO_PROFILE=demo\|prod`, `AIRGAP_LOG_ORIGIN`, `AIRGAP_W2_URL`, `AIRGAP_SONNET_BUDGET` (req/min), `AIRGAP_MANDATE_DUAL_THRESHOLD_MINOR=10000000`, `AGENT_MODE=naive\|quarantined`, `AIRGAP_GATEWAY=agentcore\|local`. Remove `AIRGAP_STH_EVERY_N_LEAVES` → `AIRGAP_CHECKPOINT_EVERY_N_LEAVES=10` + `AIRGAP_CHECKPOINT_MAX_SECONDS=30` (superseded by H0: `safe3-mono-16x4`, CONTRACTS v2.1) |
| C-28 | §1 hard rules | Add: no [H] text on the device; no real bank or regulator names in signed text or labels; witness label "independent supervisor witness (simulated operator)" |
| C-29 | pyproject (not CONTRACTS, same PR) | Move `pytest`, `hypothesis`, `moto` to `[dev]` and `streamlit`, `trezorlib` to `[ui]`/`[host]`; add `cedarpy`, `sd-jwt`, `pynacl`; drop `rfc3161ng` from runtime; add `uv.lock`, ruff, `make ci` |
