# AirGap Mandates — Shared Contracts (v1)

Single source of truth for all workstreams. If code and this file disagree, this file wins
until it is changed by a PR that touches `docs/CONTRACTS.md` **and** `contracts/` together.
Machine-readable versions: `contracts/schemas/*.json` (JSON Schema 2020-12),
examples: `contracts/fixtures/<endpoint>/*.json`. `tests/test_contracts.py` validates fixtures.

Conventions used everywhere:

- JSON field names: `snake_case`. Enums: `UPPER_SNAKE` for states/kinds, lowercase for decisions/roles.
- Money: **integer minor units** (`amount_minor`, haléře / cents). Never floats anywhere (API, DB, audit).
- Currency: `"CZK"` or `"EUR"`.
- Timestamps in JSON/DB: ISO 8601 UTC with `Z`, millisecond precision optional
  (`2026-10-19T12:05:00Z`). Dates: `YYYY-MM-DD`. Display times: `Europe/Prague` local (`AIRGAP_TZ`).
- IBAN in JSON/DB: electronic format, uppercase, no spaces (`CZ6508000000192000145399`).
- ICO: 8 ASCII digits string.
- Ethereum-style address: `0x` + 40 hex. Stored and compared **lowercase**.
- Signature: `0x` + 130 hex (65 bytes r‖s‖v, v ∈ {27,28}).
- Nonce (challenge id): 6 uppercase hex chars `^[0-9A-F]{6}$`, generated with `secrets`,
  unique for the lifetime of the deployment (conditional put; regenerate on collision).
- IDs: `mnd_<n>`, `prp_<n>`, `chg_<n>`, `tx_<proposal_no>`, `ven_<ico>`, `eml_<16 hex of sha256(raw)>`.
  `<n>` comes from atomic counters (`mandate_no`, `proposal_no`, `change_no`), starting at 1.

---

## 1. Repo layout and ownership

```
executor/                    trusted side (Lambda behind API Gateway; local: uvicorn)
  handler.py        WS-A     lambda_handler(event, ctx) + dispatch(method, path, query, body) — single router
  app.py            WS-A     FastAPI wrapper around dispatch() for local dev (make dev)
  config.py         WS-A     Settings from env (§9), clock (AIRGAP_FAKE_NOW)
  errors.py         WS-A     ApiError + error codes (§4.4)
  models.py         all      enums + TypedDicts mirroring §2–§7 (edit only together with this doc)
  canonical.py      WS-B     canonical_json() (§7.1)
  render.py         WS-A     canonical display renderer (§5) — IMPLEMENTED, frozen API
  store/            WS-A     Store interface (§3.3), memory.py (in-memory), dynamo.py (boto3; moto in tests)
  facts/            WS-E     M1: dkim.py domain.py firstseen.py iban_bank.py dph.py vop.py attest_fact.py, compute.py
  policy/           WS-E     M4: rules.py (POLICY + policy_hash), mandate.py, invariants.py, decide.py (pure)
  change/           WS-A     M2: machine.py (state machine §6)
  attest/           WS-B     M3: attestation.py, policy.py (vendor key policies), or_registry.py, tlog.py
  audit/            WS-B: merkle.py (RFC 9162 primitives)   WS-A: log.py sth.py kms.py anchor.py rfc3161.py (M5)
  bank/             WS-A     ledger.py (mock ledger), pain001.py (P1 stretch)
  egress/           WS-C     M6 server side: dlp.py allowlist.py gateway.py
host/                        untrusted laptop
  agent.py          WS-C     AP agent (Bedrock Converse), tools call executor only
  egress.py         WS-C     client: every outbound tool effect -> POST /egress
  signer.py         WS-A     trezorlib ethereum.sign_message wrapper (device + emulator)
  compromised.py    WS-F     COMPROMISED UI switch (lies in the UI, never touches executor data)
  ui.py             WS-F     Streamlit dashboard
vendor/
  portal.html       WS-F     vendor portal (callback code, attestation signing UI)
  vendor_signer.py  WS-B     vendor signers (emulators) sign VENDOR ATTEST challenges
witness/witness.py  WS-B     independent STH cosigner (own key, consistency check)
bench/              WS-D     gen_attacks.py gen_month.py replay_month.py run_bench.py report.py, results/*.jsonl
tools/              WS-A: verify_audit.py enroll.py   WS-E: seed_data.py
data/               WS-E     vendors.json invoices/ emails/*.eml dns_snapshot.json adis_cache/ or_snapshot.json
                             bank_codes.json enrollment.json
infra/              WS-A     template.yaml (SAM) iam/
tests/              per module owner; test_render.py + test_contracts.py are shared (WS-A)
contracts/          all      schemas/ fixtures/  (change only with this doc)
docs/CONTRACTS.md   all
```

Workstreams: **WS-A** executor+crypto (M0, M2, M5) · **WS-B** attestation + transparency log + witness (M3) ·
**WS-C** agent + egress + attack corpus (agent, M6) · **WS-D** evals (M4 replay, M7) ·
**WS-E** data + registries + invariants (M1, M4) · **WS-F** UI + vendor portal.

Hard rules: no LLM in `executor/`. No blockchain. Synthetic data only. Fraudster IBAN is a fictitious
Lithuanian EMI: `LT483999000000001234` (bank code `39990`, "EMI Litva (fiktivni)") — never a real institution.
Canonical demo data: ACME s.r.o., ICO `12345678`, domain `acme.cz`, IBAN `CZ6508000000192000145399`;
lookalike `acme-cz.com`; Beta Servis a.s., ICO `87654321`, IBAN `CZ6203000000000123456789`.

---

## 2. Shared objects

### 2.1 Fact
```json
{"id": "F-DOMAIN", "kind": "F", "severity": "BLOCK", "label": "Sender domain vs registry",
 "display_line": "DKIM acme-cz.com != acme.cz", "evidence": {"from_domain": "acme-cz.com", "registry_domain": "acme.cz"}}
```
| field | type | rule |
|---|---|---|
| id | string `^[FH]-[A-Z0-9-]+$` | stable rule-like id, list below |
| kind | `"F"` \| `"H"` | F = verified by executor; H = hint from host/agent (never unlocks anything, S3) |
| severity | `"INFO"` \| `"WARN"` \| `"BLOCK"` | H facts are always `INFO` |
| label | string | human label for UI (may be non-ASCII) |
| display_line | string, ASCII, ≤ 28 chars recommended | text **without** `[F] `/`[H] ` prefix; renderer adds prefix, sanitizes and truncates |
| evidence | object, optional | raw inputs for audit replay; ints/strings/bools only |

Fact ids (F, owner WS-E unless noted) — this order is also the display tiebreak order (§5.4):
`F-MANDATE` (policy: over mandate) · `F-ATTEST` (WS-B: vendor attestation k/n) · `F-CALLBACK` (WS-A) ·
`F-DOMAIN` (domain vs registry, lookalike) · `F-DKIM` · `F-FIRSTSEEN` · `F-BANK` (bank from IBAN) ·
`F-DPH` (account published in ADIS / unreliable payer) · `F-VOP` · `F-DUP` · `F-SPLIT` · `F-Z`.
H ids: `H-AGENT` (agent's stated reason), `H-UI` (anything else from host). Executor creates H facts from
request `hints[]`; display_line = `agent: "<sanitized text>"`.

Default severities (WS-E may tune, must keep BLOCK semantics):
F-DOMAIN lookalike → BLOCK; F-DKIM fail → BLOCK; F-ATTEST in-network & no valid quorum for new IBAN → BLOCK;
F-CALLBACK off-network & not confirmed → BLOCK; F-BANK foreign/EMI for CZ vendor → WARN;
F-DPH account not published → WARN, unreliable payer → BLOCK; F-FIRSTSEEN < 72 h → WARN; F-VOP NMTC → BLOCK, CMTC → WARN.

### 2.2 Decision
```json
{"decision": "challenge", "rule_ids": ["I-PER"], "facts": [Fact], "mandate_id": "mnd_3",
 "policy_hash": "<64 hex>", "challenge": ChallengeRef}
```
- `decision`: `"allow"` | `"deny"` | `"challenge"`. `challenge` present iff decision is `challenge`.
- `rule_ids`: ids that **triggered** (violated I-* rules and the F-* ids of BLOCK/WARN facts that drove the
  outcome), sorted ascending. `allow` ⇒ `[]`.
- `mandate_id`: active mandate used, or `null`.
- Proposal decision (pure function `executor.policy.decide.decide()`):
  1. `deny` if vendor unknown, I-PAYEE fails, I-DUP fails, or any F fact is BLOCK.
  2. else `challenge` (PAY step-up) if no active mandate (I-MANDATE), I-EXP, I-PER, I-BUDGET, I-COUNT,
     I-SPLIT, I-Z fail, or any F fact is WARN.
  3. else `allow` (executed immediately, log-before-execute).
  H facts never change the outcome (S3).
- Change decision (POST /changes): `deny` if any F fact is BLOCK at creation, else `challenge`.
  A preview clerk challenge is returned in both cases (so the device can show the facts).

### 2.3 ChallengeRef (embedded) / Challenge (GET /challenges/{nonce})
```json
{"nonce": "4F2A9C", "purpose": "CHG", "role": "clerk", "subject_id": "chg_7",
 "exp": "2026-10-19T12:05:00Z", "text": "AIRGAP CHG #7 n:4F2A9C exp:14:05\n...",
 "text_sha256": "<64 hex of sha256(text ascii)>", "width": 32, "line_count": 8,
 "used": false, "created_at": "2026-10-19T12:00:00Z"}
```
`purpose`: `MANDATE` | `CHG` | `PAY` | `VENDOR_ATTEST`. `role`: `clerk` | `treasury` | `jednatel` | `ucetni` | `financni`.
ChallengeRef = same object; `used`/`created_at` optional.

### 2.4 Error body
```json
{"error": "vendor_attestation_missing", "message": "vendor ACME 0/3 signatures for new IBAN", "details": {}}
```
`details` optional object; may contain `decision` (for `egress_blocked`) or `state`.

---

## 3. DynamoDB

Table name = `${AIRGAP_TABLE_PREFIX}<name>` (default prefix `airgap-`). All tables on-demand, region `eu-central-1`.
Types: S string, N number (boto3 returns `Decimal` — convert to `int` at the store boundary), BOOL, M map, L list.
No DynamoDB TTL on any table (used nonces must persist forever).

### 3.1 Tables

| name | PK | SK | GSIs | attributes |
|---|---|---|---|---|
| `vendors` | `vendor_id` S | — | — | `ico` S, `name` S, `domain` S, `iban` S (current ACTIVE), `bic` S?, `country` S, `phone` S, `contact_email` S, `registered_since` S(date), `in_network` BOOL, `iban_history` L[M{`iban`,`from`,`to`,`change_id`}], `updated_at` S |
| `mandates` | `mandate_id` S | — | `by_status` (PK `status` S, SK `mandate_no` N) | `mandate_no` N, `status` S (`PENDING_SIG`\|`ACTIVE`\|`EXPIRED`\|`SUPERSEDED`), `max_per_payment_minor` N, `max_total_minor` N, `max_count` N, `payee_scope` S, `valid_until` S, `currency` S, `policy_hash` S, `signer_address` S?, `spent_minor` N, `count` N, `challenge_nonce` S, `created_at` S, `activated_at` S? |
| `proposals` | `proposal_id` S | — | `by_vendor` (PK `vendor_id`, SK `created_at`) | `proposal_no` N, `status` S (`EXECUTED`\|`DENIED`\|`PENDING_SIG`\|`EXPIRED`\|`REJECTED`), `invoice` M, `hints` L, `facts` L, `decision` M, `challenge_nonce` S?, `tx_id` S?, `created_at` S |
| `changes` | `change_id` S | — | `by_vendor` (PK `vendor_id`, SK `created_at`) | `change_no` N, `state` S, `vendor_ico` S, `old_iban` S, `new_iban` S, `email_id` S?, `in_network` BOOL, `facts` L, `not_before` S?, `expires_at` S, `callback` M{`status`,`code_hash`,`code_exp`}, `signatures` L[M{`role`,`address`,`nonce`,`signed_at`}], `pending_challenge_nonce` S?, `history` L[M{`from`,`to`,`at`,`reason`}], `created_at` S |
| `attestations` | `ico` S | `v` N | — | `status` S (`PENDING_SIGS`\|`PUBLISHED`\|`REVOKED`\|`SUPERSEDED`), `body` S (canonical JSON of attestation without `sigs`), `sigs` L[M{`role`,`address`,`sig`,`nonce`}], `policy_v` N, `commitment` S (hex), `commit_nonce` S (hex, 128 bit, private), `leaf_index` N?, `revoked` BOOL, `created_at` S |
| `vendor_policies` | `ico` S | `policy_v` N | — | `signers` L[M{`address`,`role`,`role_basis`}], `threshold` N, `status` S (`ACTIVE`\|`SUPERSEDED`), `or_extract_sha256` S, `created_at` S |
| `nonces` | `nonce` S | — | — | `purpose` S, `role` S, `subject_id` S, `template` S, `params` S (canonical JSON render params), `text` S, `text_sha256` S, `width` N, `exp` S, `used` BOOL, `used_at` S?, `used_by` S?, `result` S? (`accepted`\|error code), `created_at` S |
| `ledger` | `tx_id` S | — | `by_vendor` (PK `vendor_id`, SK `executed_at`) | `proposal_id` S, `iban` S, `amount_minor` N, `currency` S, `vs` S?, `authorization` M{`kind`:`mandate`\|`stepup`, `mandate_id`?, `nonce`?, `signer_address`?}, `leaf_index` N, `executed_at` S |
| `audit` | `log_id` S (`audit`\|`attest`) | `seq` N | — | `event` S (**exact canonical JSON bytes as UTF-8 string**), `leaf_hash` S (hex), `ts` S |
| `sth` | `log_id` S | `tree_size` N | — | `body` S (canonical JSON of STH body), `root_hash` S, `timestamp` N (ms), `executor_sig` S (b64 DER), `witness_sig` S? (b64 DER) |
| `counters` | `name` S | — | — | `value` N. Names: `mandate_no`, `proposal_no`, `change_no`, `seq#audit`, `seq#attest` |
| `enrolled_signers` | `address` S (lowercase) | — | — | `role` S (`clerk`\|`treasury`), `label` S, `device` S (`trezor`\|`emulator`), `derivation_path` S, `active` BOOL, `enrolled_at` S |
| `inbox` | `email_id` S | — | `by_domain` (PK `from_domain`, SK `received_at`) | `s3_key` S, `sha256` S, `from_addr` S, `from_domain` S, `subject` S, `received_at` S |
| `portal_notifications` | `ico` S | `notif_id` S (`<iso ts>#<6 hex>`) | — | `kind` S (`tripwire`\|`callback`), `change_id` S, `code` S? (plaintext only here, simulates phone call), `created_at` S |
| `witness_state` | `log_id` S | — | — | `tree_size` N, `root_hash` S (witness Lambda only) |

### 3.2 Atomicity
- Nonce consumption: `UpdateItem` with `ConditionExpression used = :false`.
- Execution: append audit leaf (`execution`) **first**, then `TransactWriteItems`:
  ledger `Put` (`attribute_not_exists(tx_id)`, carries `leaf_index`) + mandate `Update`
  (`ADD spent_minor :a, count :one` with condition `spent_minor <= :max_minus_a AND count < :max_count AND status = ACTIVE`)
  + proposal `Update` (`status = EXECUTED`). Step-up payments skip the mandate update.
- Audit seq: `ADD value :1` on `counters[seq#<log_id>]`, then `Put` leaf with `attribute_not_exists(seq)`.

### 3.3 Store interface (`executor/store/__init__.py`)
`get(table, key) -> dict|None` · `put(table, item)` · `put_if_absent(table, item, key_attr) -> bool` ·
`update_if(table, key, set_: dict, expect: dict) -> bool` (expect = attribute equality) ·
`increment(table, key, attr, by=1) -> int` · `query(table, pk: tuple[str, Any], index=None, sk_range=None, limit=None, reverse=False) -> list[dict]` ·
`scan(table) -> list[dict]` · `transact(ops: list[Op]) -> bool` (all-or-nothing, ops are Put/UpdateIf/IncrementBounded).
Backends: `memory` (dicts + one lock), `dynamo` (boto3; also used with `moto`).

---

## 4. HTTP API

Base: API Gateway HTTP API (AWS) or `http://127.0.0.1:8000` (`make dev`). JSON in/out, `Content-Type: application/json`.
Header `X-Client: agent|host|vendor_portal|auditor|ingest` is **informational only** (logged as `actor`);
authorization comes only from signatures and IAM (S1, S7). Schemas: `contracts/schemas/<name>.json`.

### 4.1 Endpoint table

| # | method + path | caller | request schema | 2xx response schema | errors |
|---|---|---|---|---|---|
| 1 | `POST /mandates` | host | `mandate_create.request` | 201 `mandate_create.response` | 400 |
| 2 | `GET /mandates/active` | any | — | 200 `mandate` | 404 `no_mandate` |
| 3 | `GET /mandates/{mandate_id}` | any | — | 200 `mandate` | 404 |
| 4 | `POST /proposals` | agent | `proposal_create.request` | 201 `proposal_create.response` | 400 |
| 5 | `GET /proposals` `?status=&vendor_id=&limit=` | any | — | 200 `{"proposals":[proposal]}` | |
| 6 | `GET /proposals/{proposal_id}` | any | — | 200 `proposal` | 404 |
| 7 | `POST /changes` | agent | `change_create.request` | 201 `change_create.response` | 400, 404 (vendor) |
| 8 | `GET /changes` / `GET /changes/{change_id}` | any | — | 200 `{"changes":[change]}` / `change` (lazily advanced, §6) | 404 |
| 9 | `POST /changes/{change_id}/reject` | host | `{"reason": str}` | 200 `change` | 409 `state_conflict` |
| 10 | `GET /challenges/{nonce}` | host | — | 200 `challenge` | 404 |
| 11 | `POST /signatures` | host / vendor signer | `signature_submit.request` | 200 `signature_submit.response` | 403 (see §4.3), 404 |
| 12 | `POST /callbacks/{change_id}` | vendor portal | `callback_submit.request` | 200 `change` | 403 `callback_code_invalid`, 409 |
| 13 | `GET /portal/notifications?ico=` | vendor portal | — | 200 `{"notifications":[...]}` | |
| 14 | `POST /attestations` | vendor portal | `attestation_create.request` | 201 `attestation_create.response` | 400, 404, 409 |
| 15 | `GET /attestations/{ico}` | anyone | — | 200 `attestation_get.response` | 404 |
| 16 | `POST /egress` | host egress gateway | `egress.request` | 200 `egress.response` (allow) | 403 `egress_blocked` (body `details.decision`) |
| 17 | `GET /audit/export?log_id=audit&from_seq=0` | auditor | — | 200 `audit_export.response` | |
| 18 | `GET /receipts/{tx_id}` | auditor | — | 200 `receipt` | 404 |
| 19 | `GET /vendors` / `GET /vendors/{vendor_id}` | any | — | 200 `{"vendors":[vendor]}` / `vendor` | 404 |
| 20 | `GET /ledger?vendor_id=` | any | — | 200 `{"txs":[ledger_tx]}` | |
| 21 | `POST /ingest` | ingest (simulated MX, seed tool) | `{"raw_b64": str, "received_at"?: date-time}` | 201 `{"email_id","from_domain","received_at"}` | 400 |
| 22 | `GET /inbox` / `GET /inbox/{email_id}/raw` | agent (read only) | — | 200 `{"emails":[...]}` / `message/rfc822` | 404 |
| 23 | `GET /health` | any | — | 200 `{"status":"ok","backend":"memory","policy_hash":str,"render_width":32}` | |
| 24 | `POST /bank/batch` | host (P1 stretch) | `{"proposal_ids":[str]}` | 201 `{"msg_id","xml_c14n_sha256","challenge":ChallengeRef}` | stretch, schema TBD by WS-A |

`received_at` override in `/ingest` is honoured only when `AIRGAP_BACKEND != aws`.

### 4.2 Request/response summary (full schemas in `contracts/schemas/`)

`mandate_create.request`: `max_per_payment_minor` int>0, `max_total_minor` int ≥ per, `max_count` int 1..1000,
`payee_scope` `"existing_only"`, `valid_until` date-time (> now, ≤ now+7 d), `currency` `"CZK"`.
→ `{"mandate": mandate(status PENDING_SIG), "challenge": ChallengeRef(purpose MANDATE, role clerk)}`.
Activation (signature accepted) sets `ACTIVE`, previous ACTIVE → `SUPERSEDED`. At most one ACTIVE.

`proposal_create.request`: `invoice` {`invoice_no` str, `issue_date` date, `due_date`? date, `vendor_ico` str,
`vendor_name` str, `iban` str, `amount_minor` int>0, `currency`, `vs`? `^[0-9]{1,10}$`, `email_id`? str,
`attachment_sha256`? hex}, `hints` [{`source` `"agent"`\|`"ui"`, `text` str ≤ 200}] (default []).
→ `{"proposal": proposal, "decision": Decision, "tx": ledger_tx|null}` (`tx` set iff allow → executed).

`change_create.request`: `vendor_ico`, `new_iban`, `email_id`? , `hints` [...].
→ `{"change": change, "decision": Decision}` (decision.challenge = preview clerk challenge).

`signature_submit.request`: `nonce`, `role`, `sig`, `address`? (claimed, diagnostic only), `displayed_text`? (what the host claims the device showed).
→ `{"nonce","purpose","subject_id","signer_address","effect": {"type": "mandate_activated"|"payment_executed"|"change_advanced"|"attestation_signed"|"attestation_published", "state"?: str, "tx_id"?: str}, "mandate"?, "proposal"?, "tx"?, "change"?, "attestation"?}`.

`callback_submit.request`: `code` `^[0-9]{6}$`, `outcome` `"confirm"`\|`"deny"`.

`attestation_create.request`: `action` `"propose"` (`ico`, `iban`, `valid_from`, `supersedes`) \| `"revoke"` (`ico`, `revokes_v`).
→ `{"attestation": attestation(status PENDING_SIGS), "challenges": [ChallengeRef per policy signer role]}`.
Key rotation (`rotate_policy`) is reserved; template and schema TBD by WS-B (see open questions).

`egress.request`: `tool` `"send_email"|"http_get"|"http_post"|"upload"`, `target` str (email or URL), `content` str,
`attachments`? [{`name`, `content_b64`}], `context_ref`? str. → 200 `{"decision":"allow","rule_ids":[],"findings":[]}`;
blocked → 403 error `egress_blocked` with `details.decision = {"decision":"block","rule_ids":[...],"findings":[{"rule_id","detail","count"}]}`.
Egress rule ids: `E-ALLOWLIST`, `E-DLP-IBAN`, `E-DLP-ICO`, `E-DLP-NAME`, `E-DLP-CARD` (Luhn), `E-DLP-COUNT`, `E-ENCODED` (base64/hex payloads), `E-URLDATA` (data in URL query/path, markdown image).

### 4.3 `POST /signatures` verification order (S2, S5)
1. Load challenge by nonce → 404 `not_found`.
2. `role` must equal challenge role → 403 `unknown_signer`.
3. Re-render text from stored `template`+`params` via `render.render()`; must equal stored `text` (else 500 `internal_error`).
4. If `displayed_text` given and ≠ re-rendered text → 403 `render_mismatch` (nonce **not** consumed).
5. `sig` malformed or recovery fails → 403 `bad_signature`.
6. Recovered address enrolled for `role` (bank roles: `enrolled_signers`; vendor roles: current `vendor_policies`, not revoked) → else 403 `unknown_signer`.
7. `now >= exp` → 403 `expired`.
8. Consume nonce (conditional) → 403 `nonce_reused`.
9. Purpose guards (state machine §6, re-check of hard rules for PAY) → 403 specific code. Nonce stays consumed.
10. Append `signature` leaf (and effect leaves), then apply effect (S6).
Every rejection at steps 4–9 appends a `signature` leaf with `accepted:false,error:<code>`.

### 4.4 Error codes

| code | HTTP | when |
|---|---|---|
| `invalid_request` | 400 | schema / validation failure |
| `not_found` | 404 | unknown id / nonce |
| `no_mandate` | 404 | `GET /mandates/active` with none ACTIVE |
| `render_mismatch` | 403 | host-claimed text ≠ executor render (S2) |
| `bad_signature` | 403 | malformed sig / recovery failure / missing sig |
| `unknown_signer` | 403 | recovered address not enrolled for role, or role ≠ challenge role |
| `nonce_reused` | 403 | challenge already used (S5) |
| `expired` | 403 | challenge past `exp` (S5) |
| `missing_callback_attestation` | 403 | off-network change signed before CALLBACK_CONFIRMED |
| `vendor_attestation_missing` | 403 | in-network change signed without valid 2/3 attestation for new IBAN |
| `attestation_quorum` | 403 | attestation sig set below threshold / foreign key / revoked key (S8) |
| `cooling_off` | 403 | signed during COOLING (`now < not_before`) |
| `sigs_insufficient` | 403 | treasury before clerk, same address for both, wrong order |
| `rule_violation:<ID>` | 403 | PAY step-up re-check fails a hard rule (`rule_violation:I-DUP`) |
| `egress_blocked` | 403 | `/egress` blocked (S9) |
| `callback_code_invalid` | 403 | wrong/expired callback code |
| `state_conflict` | 409 | operation not allowed in current state |
| `internal_error` | 500 | invariant breach inside executor (fail closed, no effect) |

---

## 5. Canonical display text (`executor/render.py`)

Shared, deterministic, pure. Executor renders; host has a copy for preview only (S2).

### 5.1 Global rules
- Lines joined with `\n` (LF). No trailing newline. Signed bytes = `text.encode("ascii")`.
- Every line: printable ASCII `0x20..0x7E` only, length ≤ `width`. Total lines ≤ **8** (`MAX_LINES`).
- `width` default **32** (`AIRGAP_RENDER_WIDTH`, `render.DEFAULT_WIDTH`); to be tuned at H0 for Trezor Safe 5. The width used is stored with the challenge.
- Free text (names, fact lines, hints) is sanitized: NFKD, drop combining marks, `\t\r\n` → space, collapse spaces, strip,
  any remaining non-printable/non-ASCII char → `?`. In `[H]` text additionally `[`/`]` → `(`/`)` (an H line can never look like `[F]`).
- Too-long free text is truncated to fit and ends with `~`. Structured lines that would exceed width raise `RenderError` (fail closed).
- IBAN always full, never truncated, grouped by 4 (`CZ65 0800 0000 1920 0014 5399`). If `label + IBAN` exceeds width it is
  wrapped **balanced**: groups per line `m = (width - indent + 1) // 5`, lines `k = ceil(groups / m)`, groups distributed as evenly as possible (earlier lines get the extra), continuation lines indented with spaces to the IBAN column.
- Title line: if `AIRGAP <TYPE> ...` exceeds width (e.g. `CHG #10` at width 32), the `AIRGAP ` prefix is dropped
  (`CHG #12 n:4F2A9C exp:14:05`). Width < 30 is unsupported for CHG titles with 5-digit numbers.
- No hashes except `policy` (first 8 lowercase hex of `policy_hash`). Nonce shown as `n:XXXXXX`.
- Times: `HH:MM` in `AIRGAP_TZ` (Europe/Prague). Dates: `YYYY-MM-DD`. Datetime: `YYYY-MM-DD HH:MM` local.
- Amounts: integer major units if `minor % 100 == 0` (`125000 CZK`), else `125000.50 CZK`. No thousands separators.
- Count noun (Czech, ASCII): 1 → `platba`, 2–4 → `platby`, else `plateb`.

### 5.2 Templates (width 32 shown)

MANDATE (`render_mandate`):
```
AIRGAP MANDATE m:3 n:91BC02
max/platba 80000 CZK
max/celkem 250000 CZK
max 20 plateb
jen existujici prijemci
plati do 2026-10-20 18:00
policy 1f3a9c0e
```
CHG (`render_change`) — title has exp; OLD wraps at width 32 (CZ IBAN + `OLD ` = 33 chars):
```
AIRGAP CHG #7 n:4F2A9C exp:14:05
ACME s.r.o. ICO 12345678
OLD CZ65 0800 0000
    1920 0014 5399
NEW LT48 3999 0000 0000 1234
[F] <fact lines ...>
```
PAY (`render_pay`) — `exp HH:MM` is always the last line; VS part omitted when no VS:
```
AIRGAP PAY #41 n:0C55A1
Beta Servis a.s.
CZ62 0300 0000 0001 2345 6789
125000 CZK VS 2026104
[F] nad mandat (max 80000)
[F] DPH ucet: ANO
exp 15:20
```
VENDOR ATTEST (`render_vendor_attest`) — one challenge per signer role (role line differs):
```
VENDOR ATTEST ACME s.r.o.
ICO 12345678 v:5 n:7D11E0
UCET CZ65 0800 0000
     1920 0014 5399
platne od 2026-10-20
podepisuje: jednatel (OR)
kvorum 2/3
```

### 5.3 Fact lines
Prefix `[F] ` or `[H] ` + sanitized `display_line`, truncated with `~` to width.
Fact slots = `8 - (fixed lines of the template)`. CHG at width 32 with a CZ old IBAN: 3 slots; PAY with a ≤ 32-char IBAN line: 3 slots.

### 5.4 Ordering and overflow (deterministic)
Sort key: `kind` (F before H) → severity (BLOCK, WARN, INFO) → position of `id` in `FACT_ORDER` (§2.1; unknown ids after, lexicographic) → `display_line`.
[H] lines therefore always come after all [F] lines. If not all facts fit:
- If only H facts are left over, they are dropped silently.
- If any F fact is left over, the last available slot becomes `[F] +N dalsi fakta (B BLOCK)` where N = number of
  omitted facts (F+H) and B = omitted BLOCK count.
Dropping never changes the decision; the full fact list is in the payload and the audit log.

### 5.5 Python API (frozen)
```python
DEFAULT_WIDTH = 32; MAX_LINES = 8
class RenderError(ValueError)
render_mandate(*, mandate_no, nonce, max_per_payment_minor, max_total_minor, max_count, payee_scope, valid_until, currency, policy_hash, width=DEFAULT_WIDTH) -> str
render_change(*, change_no, nonce, exp, vendor_name, vendor_ico, old_iban, new_iban, facts, width=DEFAULT_WIDTH) -> str
render_pay(*, proposal_no, nonce, exp, payee_name, iban, amount_minor, currency, vs, facts, width=DEFAULT_WIDTH) -> str
render_vendor_attest(*, vendor_name, ico, version, nonce, iban, valid_from, signer_role, role_basis, threshold, signer_count, width=DEFAULT_WIDTH) -> str
render(template: "MANDATE"|"CHG"|"PAY"|"VENDOR_ATTEST", params: dict, width=None) -> str   # used for re-render from nonces.params
text_sha256(text) -> str; format_iban(iban) -> str; format_amount(minor, currency) -> str; order_facts(facts) -> list
```
Datetime params accept ISO 8601 strings (`...Z`) or tz-aware `datetime`; date params accept `YYYY-MM-DD` or `date`.
Facts accept dicts (§2.1) or `render.Fact`. `nonces.params` stores exactly the kwargs (minus `width`) as canonical JSON.

---

## 6. Signatures and enrollment

- Primitive: EIP-191 `personal_sign` over the canonical text.
  Device: `trezorlib.ethereum.sign_message(client, parse_path("m/44'/60'/0'/0/0"), text)` → `.signature` (65 B), `.address`.
  Emulator (trezor-user-env) via `AIRGAP_TREZOR_PATH=udp:127.0.0.1:21324`.
- Verify: `eth_account.Account.recover_message(encode_defunct(text=text), signature=sig).lower()`; compare to enrolled address.
  Never trust the address the host sends.
- Bank roles enrolled in `enrolled_signers` from `data/enrollment.json` by `tools/enroll.py` (appends `enroll` leaf):
```json
{"version": 1, "signers": [
  {"address": "0x…", "role": "clerk", "label": "Klerk (Trezor Safe 5)", "device": "trezor", "derivation_path": "m/44'/60'/0'/0/0"},
  {"address": "0x…", "role": "treasury", "label": "Treasury (emulator)", "device": "emulator", "derivation_path": "m/44'/60'/0'/0/0"}]}
```
- Vendor roles (`jednatel`, `ucetni`, `financni`) live in `vendor_policies` (§3.1); initial policy created at enrollment from `or_snapshot.json`.
- Seeds: never in the repo (`*.seed` is git-ignored). Emulator seeds are generated locally.

### 6.1 Payee-change state machine (`executor/change/machine.py`)
States: `REQUESTED, FACTS_DONE, ATTESTATION_CHECK, TRIPWIRE_SENT, CALLBACK_PENDING, CALLBACK_CONFIRMED, CALLBACK_DENIED, COOLING, SIG_CLERK, SIG_TREASURY, ACTIVE, EXPIRED, REJECTED`.
Terminal: `ACTIVE, EXPIRED, REJECTED`. `SIG_CLERK` = awaiting clerk signature; `SIG_TREASURY` = awaiting treasury signature.

| from | to | trigger | guard |
|---|---|---|---|
| REQUESTED | FACTS_DONE | auto on create | facts computed and logged |
| FACTS_DONE | ATTESTATION_CHECK | auto | — |
| ATTESTATION_CHECK | COOLING | auto / attestation published for ico | `in_network` ∧ valid PUBLISHED attestation for `new_iban` with quorum under current policy ∧ no F BLOCK |
| ATTESTATION_CHECK | TRIPWIRE_SENT | auto | `¬in_network` |
| TRIPWIRE_SENT | CALLBACK_PENDING | auto | tripwire notification to registry contact recorded; callback code issued (6 digits, TTL) |
| CALLBACK_PENDING | CALLBACK_CONFIRMED | `POST /callbacks` confirm | code valid, not expired |
| CALLBACK_PENDING | CALLBACK_DENIED | `POST /callbacks` deny | code valid |
| CALLBACK_CONFIRMED | COOLING | auto | no F BLOCK after recompute |
| CALLBACK_DENIED | REJECTED | auto | — |
| COOLING | SIG_CLERK | lazy on any read/sign | `now >= not_before` (`not_before = entered + AIRGAP_COOLING_SECONDS`); fresh clerk challenge issued |
| SIG_CLERK | SIG_TREASURY | clerk signature on current challenge | signer enrolled `clerk`; fresh treasury challenge issued (same body, new nonce) |
| SIG_TREASURY | ACTIVE | treasury signature on current challenge | signer enrolled `treasury` ∧ address ≠ clerk signer; then `vendors.iban := new_iban`, history appended |
| any non-terminal | EXPIRED | lazy | `now >= expires_at` (`created + AIRGAP_CHANGE_TTL_SECONDS`) |
| any non-terminal | REJECTED | `POST /changes/{id}/reject`, callback denied, attestation revoked while in COOLING/SIG_* | — |

All other transitions are forbidden (property test, S4). Every transition appends a `state_transition` leaf.
Early CHG signature (preview challenge, or any state ≠ SIG_CLERK/SIG_TREASURY) → nonce consumed, 403 with:
in-network & no attestation → `vendor_attestation_missing`; off-network & not confirmed → `missing_callback_attestation`;
COOLING → `cooling_off`; treasury in SIG_CLERK or same address → `sigs_insufficient`.

---

## 7. Audit log (`executor/audit/`)

### 7.1 Canonical JSON
`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")`.
Floats are forbidden (raise). Integers, strings, bools, null, lists, objects only.

### 7.2 Leaf event (`contracts/schemas/audit_event.json`)
```json
{"v": 1, "log_id": "audit", "seq": 37, "ts": "2026-10-19T12:34:56.789Z", "type": "decision",
 "actor": "executor", "subject_id": "prp_41", "data": {...}}
```
`actor`: `executor|agent|host|vendor_portal|ingest|witness|tool`. `seq` monotonic per `log_id`, starts at 0, no gaps.

| type | data (required fields) |
|---|---|
| `enroll` | `address, role, device, label` |
| `ingest` | `email_id, sha256, from_domain, received_at` |
| `challenge` | `nonce, purpose, role, subject_id, text_sha256, exp` |
| `mandate_signed` | `mandate_id, mandate_no, policy_hash, signer_address, nonce, fields{max_per_payment_minor,max_total_minor,max_count,payee_scope,valid_until,currency}` |
| `proposal` | `proposal_id, invoice{...}, hints[...]` (agent input verbatim) |
| `facts` | `subject_id, facts[Fact]` |
| `decision` | `subject_id, decision, rule_ids, mandate_id, policy_hash` |
| `state_transition` | `change_id, from, to, reason` |
| `signature` | `nonce, purpose, role, signer_address (or null), text_sha256, sig, accepted, error (or null)` |
| `attestation` | `ico, v, action, status, commitment, attest_leaf_index (or null)` |
| `egress_block` | `tool, target, rule_ids, findings, content_sha256` |
| `execution` | `tx_id, proposal_id, vendor_id, iban, amount_minor, currency, authorization{kind, mandate_id?, nonce?, signer_address?}` |
| `anchor` | `log_id, tree_size, root_hash, s3_key, tsa_token_sha256` |

### 7.3 Hashing (RFC 9162 §2.1)
- `leaf_hash = SHA256(0x00 || canonical_json(event))`; node `= SHA256(0x01 || left || right)`; empty tree root = `SHA256("")`.
- MTH split: `k` = largest power of two `< n`. Inclusion and consistency proofs per RFC 9162 §2.1.3/§2.1.4. Hashes hex-encoded lowercase in JSON.
- Transparency log for attestations = same primitives, `log_id = "attest"`, leaf event `type = "attestation"` whose data carries
  `commitment = SHA256(canonical_json(attestation_body) || commit_nonce_128bit)` — never a bare IBAN hash.
- STH body: `{"log_id", "tree_size", "root_hash", "timestamp"}` (timestamp = ms int). Executor signs `canonical_json(body)`
  with KMS `ECDSA_SHA_256` (key `ECC_NIST_P256`) every `AIRGAP_STH_EVERY_N_LEAVES` leaves; witness cosigns the same bytes after
  verifying consistency with its last STH (refuses forks). Signatures: base64 DER.
- Anchor every `AIRGAP_ANCHOR_INTERVAL_SECONDS`: `s3://$AIRGAP_ANCHOR_BUCKET/audit-anchor/<log_id>/<tree_size:012d>.json`
  = `{sth_body, executor_sig, witness_sig, tsa_token_b64}` (Object Lock COMPLIANCE, 1 day) + RFC 3161 token over `canonical_json(sth_body)`.
- S6: `ledger.leaf_index` = seq of the `execution` leaf; written strictly after that leaf.

`audit_export.response`: `{"log_id", "leaves": [{"seq", "event": <object>, "leaf_hash"}], "sths": [{"body", "executor_sig", "witness_sig"}], "anchors": [...], "public_keys": {"executor": PEM, "witness": PEM}, "policy": <POLICY object>}`.
`tools/verify_audit.py` (offline): recompute leaf hashes, no seq gaps, roots match STHs, STH + witness sigs, anchors, consistency between consecutive STHs, ledger rows ↔ execution leaves, replay `decide()` from `proposal`/`facts` events and policy → must equal logged `decision`.

---

## 8. Invariants

### 8.1 Policy rules (`executor/policy/rules.py`, owner WS-E)
| id | rule | outcome on fail |
|---|---|---|
| I-MANDATE | an ACTIVE mandate exists | challenge |
| I-EXP | `now < mandate.valid_until` | challenge |
| I-PER | `amount_minor <= max_per_payment_minor` | challenge |
| I-BUDGET | `spent_minor + amount_minor <= max_total_minor` | challenge |
| I-COUNT | `count + 1 <= max_count` | challenge |
| I-PAYEE | vendor exists and `invoice.iban == vendors.iban` (ACTIVE) | deny |
| I-NONCE | challenge used once (enforced in /signatures) | 403 `nonce_reused` |
| I-DUP | same normalized `invoice_no` for vendor, or (vendor, amount ±50 bp, issue_date ±3 days) already EXECUTED/PENDING_SIG | deny |
| I-SPLIT | executed sum for vendor in last 24 h + amount > `max_per_payment_minor` | challenge |
| I-Z | robust z-score (median/MAD) of amount vs vendor history > 3.5 (stored as `z_threshold_milli: 3500`) | challenge |

`POLICY` = `{"policy_v": 1, "rules": [{"id": ..., "params": {...}}, ...]}` (ints only); `policy_hash = sha256(canonical_json(POLICY)).hex()`.
A mandate whose `policy_hash` ≠ current policy hash is treated as no mandate (I-MANDATE).
Normalized invoice no: uppercase, strip all non-alphanumerics, strip leading zeros of numeric runs.

### 8.2 Security invariants
| id | invariant | proving test (file::test) |
|---|---|---|
| S1 | no ledger write without executor-verified authorization | `tests/test_replay_swap.py::test_s1_no_sig_403` (sig missing/garbage → 403, ledger unchanged) + `test_invariants.py::test_s1_ledger_rows_have_authorization` |
| S2 | executor re-renders text from own data; never accepts host text | `test_replay_swap.py::test_s2_render_mismatch` (host text differs → 403 `render_mismatch`; sig over host text → `unknown_signer`) |
| S3 | [H] never unlocks a payment | `test_invariants.py::test_s3_hints_never_change_decision` (hypothesis over decide(): adding/removing H facts never changes decision) |
| S4 | payee change activates only via ACTIVE | `tests/test_change_machine.py::test_s4_forbidden_transitions` (all non-table transitions raise; ACTIVE reachable only via SIG_TREASURY) |
| S5 | nonce once, within TTL | `test_replay_swap.py::test_s5_replay`, `::test_s5_expired`, `::test_s5_swap` (sig for nonce A on nonce B → `unknown_signer`) |
| S6 | log-before-execute | `test_audit_fuzz.py::test_s6_crash_between` (inject failure after leaf/before ledger and vice versa: no ledger row without execution leaf) |
| S7 | agent role explicit IAM Deny on ledger, mandates, audit, KMS | `infra/iam/` + `tests/test_iam.py::test_s7_simulate_principal_policy` (skipped unless `AIRGAP_BACKEND=aws`) |
| S8 | vendor change in network needs valid 2/3 per current policy | `tests/test_attest.py::test_s8_one_of_three`, `::test_s8_foreign_key`, `::test_s8_revoked_key`, `::test_s8_rotation_without_old_quorum` |
| S9 | agent cannot exfiltrate | `tests/test_egress.py::test_s9_exfil_corpus_zero_success` (10 variants blocked) + `::test_s9_benign_pass` |

---

## 9. Environment and config (`executor/config.py`)

| env var | default | meaning |
|---|---|---|
| `AIRGAP_BACKEND` | `memory` | `memory` (in-process dicts, local keys) \| `moto` (boto3 against moto, tests) \| `aws` |
| `AWS_REGION` | `eu-central-1` | all resources; SSO region is eu-north-1 (login only) |
| `AIRGAP_TABLE_PREFIX` | `airgap-` | DynamoDB table prefix (§3) |
| `AIRGAP_INBOX_BUCKET` | `airgap-inbox` | raw .eml under `inbox-raw/<email_id>.eml`; write: ingest role only |
| `AIRGAP_ANCHOR_BUCKET` | `airgap-audit-anchor` | Object Lock bucket, prefix `audit-anchor/` |
| `AIRGAP_KMS_KEY_ID` | — | executor STH/receipt key (ECC_NIST_P256, SIGN_VERIFY) |
| `AIRGAP_WITNESS_KMS_KEY_ID` | — | witness key (only witness role may use) |
| `AIRGAP_WITNESS_URL` | `inproc` | witness endpoint; `inproc` = call `witness.witness` in-process |
| `AIRGAP_LOCAL_KEY_DIR` | `.local/keys` | memory/moto backend: generated P-256 PEMs for executor + witness (git-ignored) |
| `AIRGAP_TSA_URL` | `https://freetsa.org/tsr` | RFC 3161 TSA; `off` disables |
| `AIRGAP_RENDER_WIDTH` | `32` | display width (§5) |
| `AIRGAP_TZ` | `Europe/Prague` | display timezone |
| `AIRGAP_CHALLENGE_TTL_SECONDS` | `300` | challenge exp |
| `AIRGAP_COOLING_SECONDS` | `90` | change cooling-off (UI: "zkraceno z 24 h") |
| `AIRGAP_CHANGE_TTL_SECONDS` | `3600` | change expiry |
| `AIRGAP_CALLBACK_CODE_TTL_SECONDS` | `600` | callback code expiry |
| `AIRGAP_STH_EVERY_N_LEAVES` | `10` | STH cadence |
| `AIRGAP_ANCHOR_INTERVAL_SECONDS` | `300` | anchor cadence |
| `AIRGAP_DATA_DIR` | `data` | snapshots (dns, adis, or, bank_codes, vendors) |
| `AIRGAP_ADIS_MODE` | `cache` | `cache` \| `live` (one live read-only call allowed) |
| `AIRGAP_FAKE_NOW` | — | ISO datetime; freezes executor clock (tests, demo rehearsal; ignored when `aws`) |
| `AIRGAP_EXECUTOR_URL` | `http://127.0.0.1:8000` | host/agent/bench → executor |
| `AIRGAP_BEDROCK_MODEL_ID` | `eu.anthropic.claude-sonnet-4-5-20250929-v1:0` | agent model (inference profile id — **verify at runtime** with `aws bedrock list-inference-profiles --region eu-central-1`) |
| `AIRGAP_QWEN_BASE_URL`, `AIRGAP_QWEN_MODEL` | — | bench / generation model (OpenAI-compatible endpoint, per hackathon guide) |
| `AIRGAP_TREZOR_PATH` | — (USB autodetect) | e.g. `udp:127.0.0.1:21324` for emulator |

Local dev: `make dev` runs `AIRGAP_BACKEND=memory uvicorn executor.app:app --port 8000` — the full executor as a plain
Python process, local P-256 keys instead of KMS, in-process witness, TSA optional. `executor.app.create_app(settings)` and
`executor.handler.dispatch(...)` can be imported in-process (bench, tests) without HTTP.
