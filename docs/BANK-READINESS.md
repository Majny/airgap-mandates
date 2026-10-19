# AirGap Mandates: bank readiness

For a bank's architecture, security and operational-risk reviewers. This page says what exists today, what the bank
must provide, how the controls line up with the regulation, and what is missing before a production pilot. It
leaves out marketing. Where this page and the code disagree, the code and `docs/CONTRACTS.md` win. Design
rationale is in `docs/ARCHITECTURE.md`. The line between real and simulated is in `demo/REAL_VS_SIMULATED.md`.

Status: a hackathon build (19-20 Oct 2026). It runs end to end on AWS with synthetic data and one physical Trezor.
It has not had an external security review, a load test or a legal review.

## 1. What the system does, in one paragraph

An AI accounts-payable agent reads supplier email and proposes payments. It holds no credential that can move
money. An executor on AWS Lambda recomputes every fact from its own data (vendor master, DKIM verdicts, registries,
Verification of Payee) and decides with a Cedar policy. A payment executes in only two cases. Either it falls inside a
mandate that two people signed on hardware devices (Trezor), with caps on amount, count and validity and limited to
existing payees, or a person holds-to-confirm a text on the device that shows the exact amount and payee account. A
new payee account needs 2 of 3 independent supplier attestations, a cooling-off period, and then two people on two
devices. Every input, decision, signature and execution is appended to a transparency log. Two witnesses cosign the
log, and an auditor can verify it offline.

## 2. Deployment architecture (as deployed for the demo)

All in one AWS account, region **eu-central-1**, defined in `infra/airgap_stack.py` (CDK, Python). Evidence is in
`infra/evidence/`.

| Layer | What runs | Notes |
|---|---|---|
| API | API Gateway REST API, **regional endpoint, IAM (SigV4) auth** on every route except the C2SP witness route `POST /witness/add-checkpoint` (it carries its own log signature) | Stage throttling 50 req/s, burst 100. Witness route 5 req/s, burst 10. ARCHITECTURE §9 describes a private API; the deployed one is regional with IAM auth. For production, make it private behind VPC endpoints |
| Executor | Lambda `airgap-executor` (Python 3.12, arm64, 1 GB, 30 s). One `dispatch()` serves every route | Lambda is Firecracker isolation, **not a TEE**. ARCHITECTURE §9 describes the Nitro Enclaves path; it is not built |
| Checkpointer | Lambda `airgap-checkpointer`, run by EventBridge Scheduler every minute (checkpoint) and every 5 minutes (anchor to S3) | Holds the only `kms:Sign` permission on the log key |
| Witness W1 | Lambda `airgap-witness`, own role, own KMS key, own table | Same account as the executor, so W1 is not independent |
| Witness W2 | Unmodified upstream litewitness (Go) on its own EC2 `t4g.nano` in its own VPC, with its own key (not KMS) | Our own instance with a simulated operator. In production a separate organisation runs it |
| Agent | Lambda `airgap-agent` in a VPC with one AZ and **no IGW or NAT**. Interface endpoints for `bedrock-runtime` and `execute-api` only. Route 53 DNS Firewall resolves only those two names. VPC Flow Logs and DNS query logs go to CloudWatch | Probe evidence: `infra/evidence/s10_probe.json` |
| Tools / egress | Lambda `airgap-tools`: the agent's only API (`/tools/*`), with Cedar tool policies, every call logged, an egress allowlist and DLP for IBAN/IČO | Bedrock Guardrail (prompt-attack filter, IBAN/IČO regex) as a second opinion |
| State | DynamoDB on demand: `ledger`, `mandates`, `audit`, `registry`, `witness_state`, `portal`, plus single-table `main`. Separate tables so IAM can separate them | `RemovalPolicy.DESTROY`, no point-in-time recovery (see the gap list) |
| Exactly-once | One `TransactWriteItems` writes the audit leaf, the log head, the mandate debit, the ledger row and the proposal status together (ARCHITECTURE §5.4) | Crash recovery re-submits ledger rows that have no `rail_submitted` leaf |
| Log keys | KMS `ECC_NIST_EDWARDS25519` keys `alias/airgap-log` and `alias/airgap-w1`. The key policies name role ARNs directly: no IAM delegation, no `CreateGrant` | Verifiers use public keys only |
| Log anchor | S3 bucket with **Object Lock in governance mode, 1-day default retention**, versioned, TLS only, public access blocked | Production: compliance mode with a retention set by the bank's records policy |
| Inbox | S3 bucket for raw `.eml` files (SSE-S3). The DKIM/SPF verdict is computed in the executor as a fact | |
| Logs | CloudWatch with **1-week retention** for Lambda, Flow Logs and DNS logs | The stack does not create a CloudTrail trail; it relies on an account-level trail |

**IAM walls** (`infra/evidence/iam_simulate.txt` shows the live AccessDenied evidence):

| Role | May | Explicitly denied |
|---|---|---|
| `airgap-agent` | Bedrock InvokeModel (two model families); `execute-api` on `/tools/*` | All DynamoDB, all KMS on our keys, Secrets Manager, any call from outside the agent VPC, `/signatures`, `/mandates*` and other money routes |
| `airgap-host` (console, signer worker) | Read routes, `/challenges/*`, `POST /signatures`, `/mandates*`, `POST /changes/*/reject` | DynamoDB, `kms:Sign`, Secrets Manager |
| `airgap-auditor` | `GET /*` and reading the anchor bucket | DynamoDB, `kms:Sign`, Secrets Manager |
| `airgap-executor-api` | Executor tables, invoking the rail | `kms:Sign` on the W1 key |
| `airgap-checkpointer` | `kms:Sign` on the log key, writing to the anchor bucket | W1 key |
| `airgap-witness` | `witness_state`, `kms:Sign` on the W1 key | Everything that belongs to the executor |

Honest limit: in the hackathon account our laptops hold an admin SSO role, so an attacker on a laptop is an account
admin. The demo attacker uses only the `agent` and `host` credentials. Production needs separate AWS accounts for the
executor, the witness and the agent, with an SCP boundary between them.

## 3. Integration points: what the bank must provide

| Integration | Today | What the bank provides | Effort |
|---|---|---|---|
| **Core banking (payment initiation)** | Each execution produces an ISO 20022 **pain.001.001.09** file (`GET /export/pain001/{tx_id}`, auditor/host principals). Its C14N SHA-256 is written to the audit log as a `rail_submitted` leaf. The console offers each file for download and a per-day zip with a manifest. Each file is checked against the log leaf before it is offered. The mock rail answers ACTC and then DUPL (exactly-once) | A pain.001 import channel (SFTP/host-to-host) that accepts one file per payment, or a batch import of the zip. Ideally core banking also re-checks each file's hash against the exported audit log. A pain.002 status feed back is the next step | S for file import; M for pain.002 |
| Core banking via a direct API | Not built. The rail module is the integration point (`executor/rail/`, `rail` role) | API spec, sandbox, idempotency key semantics (we use `tx_id`) | M-L |
| **Corporate SSO for the console** | Streamlit's built-in OIDC (`st.login`) with operator and auditor roles from env (section 9) | An OIDC client (Entra ID, Okta, Keycloak or similar) and the lists of operator and auditor emails or domains | S |
| **Mail gateway → `POST /ingest`** | `ingest` role posts raw `.eml` files. The executor stores them in S3 and computes DKIM/SPF/ARC itself | A journaling or forward rule from the AP mailbox to an ingest job holding the `airgap-ingest` role. The raw message must arrive unmodified, or DKIM cannot be checked | S-M |
| **Supplier master import** | Vendor registry (`registry` table) seeded from `data/vendors.json`. Afterwards only the payee-change state machine changes IBANs | A one-off export from the ERP vendor master (IČO, name, IBAN, domains, registered contact for callbacks), then a reconciliation job. Changes made in the ERP must not bypass the change flow | M |
| **Device fleet: Trezor enrolment ceremony** | `tools/enroll.py`: Optiga certificate chain against the Trezor root, firmware hash against the official image, address per role path, EIP-191 enrolment signature. The tool writes `device=GENUINE` or `EMULATOR` into an `enroll` leaf | Devices bought through a controlled channel, an enrolment room and witnesses, a register of who holds which device, and seed backup handling (or no backup and re-enrolment on loss) | S per device; M for the process |
| **Supplier-bank attestation issuers** | Three issuer classes (supplier ERP, supplier bank, registry) issue SD-JWT VCs bound to the change nonce. The issuers are simulated and their keys are DEMO-ONLY files in the repo | Real issuers: at least the supplier's bank, or a bank consortium trust list. Each vendor pins its own ERP key at enrolment | L (an ecosystem question, not just code) |
| **Verification of Payee provider** | Mock responder with EPC codes (`data/vop_mock.json`) | A VoP connection (EPC VoP scheme for EUR; for CZK when the domestic scheme exists) | M |

## 4. Control mapping ("aligned with", never "compliant with")

| Control objective | Regulation | How AirGap addresses it | Limits |
|---|---|---|---|
| **Four-eyes / dual control** for new payee accounts and mandates | Internal control frameworks; common supervisory expectation for payment master-data changes | A payee change reaches ACTIVE only after ≥2 attestations from distinct pinned issuer classes (or break-glass with a callback to a contact registered beforehand), cooling-off, then a clerk signature and a treasury signature from **two different enrolled addresses** (`executor/change/machine.py`, invariant S4, property-tested). Mandates above the threshold need 2 of 2 distinct keys (S1) | Two addresses are not proven to be two devices (known gap 2 in REAL_VS_SIMULATED). Collusion or coercion of both approvers is out of scope |
| **Dynamic linking**: the approver sees the amount and payee, and the authentication code is bound to them | PSD2 RTS on SCA, Commission Delegated Regulation (EU) 2018/389, **Art. 5** | For a step-up payment the device shows the amount, the payee name and the full payee IBAN, rendered by the executor from facts. The EIP-191 signature covers exactly those bytes (S2: signed bytes == `render(stored params)`). The executor recovers the signer and rejects any change of amount or payee (single-use nonce bound to the subject, S5) | Payments **inside a mandate** are not linked one by one: the mandate signature covers caps, validity, payee scope and policy hash. Whether that counts as a pre-authorised limit or needs per-payment SCA is a legal question (gap list). The device approval is not presented as an SCA solution of the bank |
| **Logging**: tamper-evident logging of ICT and decision events, protected against change, reviewable | DORA, Commission Delegated Regulation (EU) 2024/1774 (RTS on ICT risk management), **Art. 12** | An append-only C2SP transparency log of every input, decision (with `policy_hash`), signature, execution and rail submission. Checkpoints signed with KMS Ed25519 and cosigned by two witnesses. S3 Object Lock anchor. Offline verification with unmodified upstream Go (`sumdb/note`) plus `tools/verify_audit.py`, which also replays every decision (S12) | Retention is set for the demo (1-day Object Lock, 1-week CloudWatch). The bank's retention and clock-synchronisation requirements are not mapped yet. W1 shares the account; independence rests on W2 |
| **Data minimisation** | GDPR Art. 5(1)(c) | This build uses **synthetic data only**: fictitious companies, people, inboxes and invoices. The audit log holds business identifiers (IBAN, IČO, invoice numbers), not personal data beyond supplier contacts | A redacted export (IBAN → salted commitment) is specified but not implemented (`executor/audit/log.py` raises on `redact=1`). A DPIA and a retention and erasure policy for the log are needed before real data is used. An append-only log and erasure requests pull in opposite directions: keep personal data out of leaves and in erasable side tables |
| Human oversight of the AI agent | EU AI Act, Regulation (EU) 2024/1689, Art. 14 (analogy only) | The agent proposes; it cannot move money, approve or change a mandate. Its claims are hints and can only push a decision toward deny (S3) | We do not claim the agent is a high-risk system |

## 5. Threat model summary

Trust boundaries (ARCHITECTURE §2): TB0 the person and the device; TB1 the executor; TB2 the witnesses; TB3
everything untrusted (the agent and its models, the operator laptop and console, email, PDFs, phone calls); TB4 the
supplier-side issuers; TB5 the offline auditor.

Attacker levels used by the bench (ARCHITECTURE §11), with what stops each one:

| Level | Attacker can | Stopped by |
|---|---|---|
| **H0** | Inject content: email body, hidden PDF text, ISDOC note, filename. A business-email-compromise lookalike domain, or a real mailbox taken over | The agent never supplies the IBAN (proposals carry `vendor_id`). Executor facts (lookalike domain, DKIM, VoP, attestations) BLOCK, and a BLOCK means no challenge reaches the device (R0). A takeover from the real domain still has 0 of 3 attestations and trips the "not us" wire to the registered contact |
| **H1** | Make the console lie | The device shows text rendered by the executor from facts; the person confirms the device, not the screen. The console has no key that moves money |
| **H2** | Send a false `displayed_text` with a signature | The executor ignores the host's text. It re-renders from stored parameters and verifies the signature over its own bytes (S2) |
| **H3** | Swap nonce or subject between live challenges | Nonces are single-use, have a TTL and are bound to `(deployment, purpose, subject)` (S5) |

H4-H6 (different text sent to the device, the agent's own AWS credentials, egress bypass) are covered in
ARCHITECTURE §11 and by the IAM, VPC and DNS controls above.

**Out of scope, stated:** a malicious executor operator with deploy rights (mitigated only by the witnesses,
CloudTrail and the code hash in each checkpoint); compromised Trezor firmware or supply chain (mitigated by the
enrolment ceremony); coercion or collusion of both approvers; fraud inside a valid mandate (an inflated invoice to an
existing payee within the caps). The last one is bounded by caps, duplicate and split checks and an anomaly score,
and the bench reports its residual rate.

## 6. Operating model

| Topic | Proposal for a pilot |
|---|---|
| Who holds which device | One Trezor per approver role per person: the AP clerk holds a `clerk` device; treasury holds a `treasury` device. The two roles must be different people on different devices. A device register (person, role, address, enrolment leaf seq, firmware) is kept by security operations. The production profile refuses emulator keys |
| Mandate lifecycle | Treasury and the AP lead sign a mandate (caps per payment, total and count, validity, existing payees only, required VoP result) on their devices, for example weekly. Anything outside it is a step-up on the clerk's device |
| Incident response | Alerts: `python -m host.alerts` posts every blocked attempt (denied proposal, rejected payee change, tripwire, refused signature, forbidden tool call) to the security channel, and says so when it loses contact with the executor. Lost or stolen device: revoke the enrolled address (the store function in `executor/store/signers.py` writes an `enroll` leaf with `active=false`; there is no API route for it, so the executor operator runs it), re-sign the active mandate without it, enrol a replacement. Suspected compromise of the agent or the laptop: no money-side action is needed (TB3); rotate the host credentials and review the log. Suspected compromise of the executor: freeze the deployment, export the log and verify it offline against keys held out of band, and compare witness checkpoints for a split view |
| Key rotation | Log and W1 keys: create a new KMS Ed25519 key, publish its public key out of band (the verifier pins keys), and start a new log origin. Old checkpoints stay verifiable with the old public key. Approver keys: re-enrol (new address), then re-sign the mandates. Supplier issuer keys: update the pinned trust list per vendor. The rotation runbook is not written yet (gap list) |
| Policy changes | The Cedar policies, schema, transliteration table, fact severities and parameters hash to `policy_hash`. It is written in every decision leaf, returned by `/health`, and **pinned by every mandate**. A change follows the bank's change process: a reviewed pull request, a deliberate update of `FROZEN_POLICY_HASH` in `tests/test_policy_freeze.py`, deploy. Then every active mandate stops working (I-MANDATE) until people re-sign it under the new hash. An auditor can replay any old decision against the policy text stored in the export |
| Console access | Operators and auditors sign in through corporate SSO. One JSON `console_access` line per session goes to stdout for log shipping |

## 7. What is simulated today

From `demo/REAL_VS_SIMULATED.md` and ARCHITECTURE §12.

| Real | Simulated or missing |
|---|---|
| Physical Trezor Safe 3 as clerk, GENUINE at enrolment, hold to confirm, signature recovered by the executor | Treasury approver on the Trezor emulator (labelled EMULATOR). The production profile refuses it |
| Executor on AWS Lambda with IAM split, AccessDenied evidence, agent VPC with no route out | Companies, domains, accounts, inbox, invoices and the DKIM DNS snapshot are fictitious |
| KMS Ed25519 log and W1 keys; every checkpoint cosigned by W1 and W2; S3 Object Lock | W2's operator is simulated (our instance of upstream code); W1 is in the same account |
| Offline verification with unmodified upstream Go and our replaying verifier | Supplier ERP and bank issuers: real SD-JWT VC cryptography, simulated organisations, shared DEMO-ONLY keys |
| Facts from public-data snapshots (licence registers, VoP participant lists, sanctions and warning lists, legal-entity data) | VoP responder is a mock; tripwire and callback go through a vendor-portal mock, no SMS provider |
| pain.001.001.09 files with logged hashes | Rail is a mock ledger; no live payment rail |
| Bench numbers from frozen runs | Bench humans are a model of a human, not a user study |

Known gaps already found by our own adversarial review (unsalted callback-code hash, two addresses ≠ two devices,
shared issuer keys, cross-email reminders) are listed with their production fixes in REAL_VS_SIMULATED.

## 8. Gap list to a production pilot

S = under 2 weeks, M = 2-6 weeks, L = over 6 weeks or depends on outside parties. Rough estimates for one small team.

| # | Gap | Why it matters | Effort |
|---|---|---|---|
| 1 | **Independent penetration test** of the API, IAM, console and signer, plus a red team on the agent | Nothing here has had an external review | M (external) |
| 2 | **Real Verification of Payee** provider integration | VoP is a key fact for payee changes and mandates; today it is a mock | M |
| 3 | **Real attestation issuers** (supplier bank at least) and per-vendor pinned keys; revocation through status lists | 2-of-3 attestations are the core of the payee-change control; today the organisations are simulated and the keys are shared | L |
| 4 | **HSM-backed enrolment and device-identity binding**: the enrolment ceremony signed by an HSM-held bank key; compare device identity across roles; periodic re-attestation | Attestation proves a genuine device at enrolment only; two roles could share one device | M |
| 5 | **SOC 2 Type II / ISO 27001** for the operator of the executor (the bank itself or a vendor) | Outsourcing and third-party ICT risk requirements | L |
| 6 | **Multi-tenant** separation (per-client tables or accounts, per-tenant keys, policy and mandates) | The build serves one corporate client | L |
| 7 | **DR and backup**: DynamoDB point-in-time recovery, cross-region copy of the log anchor, Object Lock in compliance mode with the bank's retention, tested restore, RTO/RPO | Today tables are destroy-on-delete with no PITR; log retention is 1 day (Object Lock) and 1 week (CloudWatch) | M |
| 8 | **Rate limits and quotas** per principal and per vendor (beyond API Gateway stage throttling), and a WAF on any public route | Abuse and cost control; the witness route is unauthenticated by design | S |
| 9 | **Load test** and capacity plan (Lambda concurrency, DynamoDB hot keys on the log head, checkpoint lag under load) | The single log head serialises appends; throughput is unmeasured | S-M |
| 10 | **Legal review of liability and the mandate model** under the PSR/PSD3 package and PSD2 SCA: who bears the loss for payments inside a mandate, whether a mandate is an acceptable pre-authorisation, what the bank's contract with the corporate client says | Today only "aligned with" claims; the liability position is unverified | M (external) |
| 11 | Separate AWS accounts for executor, witness and agent with SCPs; a private API; the Nitro Enclaves path for the log key | Removes the "laptop is account admin" limit | M |
| 12 | Redacted audit export, DPIA, and a retention and erasure design for personal data | Needed before any real supplier contact data enters the system | M |
| 13 | pain.002 status feed from core banking and reconciliation against the ledger | Closes the loop on rejected or returned payments | M |
| 14 | Runbooks: key rotation, device loss, policy change, incident, witness outage | Section 6 describes them; they are not written as tested runbooks | S |

## 9. Running the console

The operator console (`host/ui.py`) is a Streamlit app. It only reads from the executor; approvals happen on the
devices. It holds no key that moves money.

### Console sign-in (OIDC)

When `.streamlit/secrets.toml` contains an `[auth]` section, the console requires sign-in through Streamlit's
built-in OIDC (`st.login`, Streamlit ≥ 1.42 with the `streamlit[auth]` extra, i.e. Authlib). Without `[auth]` it runs
in **"local, no SSO"** mode (development, the stage laptop) and says so in the header. Set
`AIRGAP_UI_REQUIRE_SSO=1` (the container default) to refuse to start in local mode.

Sample `.streamlit/secrets.toml`. **Never commit the real file**: it is in `.gitignore` and
`Dockerfile.console.dockerignore`. Mount it at run time.

```toml
[auth]
redirect_uri = "https://airgap-console.corp.example/oauth2callback"   # external URL + /oauth2callback
cookie_secret = "<32+ random bytes, e.g. python -c 'import secrets;print(secrets.token_urlsafe(48))'>"

[auth.corp]                       # any name without "_"; the console picks the first named provider
client_id = "<client id from the bank's identity provider>"
client_secret = "<client secret>"
server_metadata_url = "https://login.corp.example/<tenant>/v2.0/.well-known/openid-configuration"
client_kwargs = { scope = "openid profile email", prompt = "select_account" }
```

Roles come from the environment, never from claims the identity provider lets users edit:

```sh
AIRGAP_UI_OPERATORS="ap-lead@corp.example, treasury.corp.example"   # emails, or whole domains
AIRGAP_UI_AUDITORS="internal-audit.corp.example"
```

- **Operators** see every tab: Overview, Payments, Payee changes, Approvals, Mandate, Audit and Reports.
- **Auditors** see Audit and Reports only. The console reads for them with the `airgap-auditor` principal and does
  not fetch vendors, proposals or payee changes at all.
- Domain entries match the exact domain only. A subdomain needs its own entry, and `evil-corp.example` does not
  match `corp.example`.
- Anyone signed in but on neither list is refused, and so is everyone if both lists are empty. An email the provider
  marks `email_verified = false` is refused.
- The "compromised host" demo switch (`AIRGAP_UI_DEMO_TOOLS=1`) only appears in local mode.

### Container

`Dockerfile.console`: `python:3.12-slim`, the executor package plus `streamlit[auth]` and `segno` (no trezorlib, no
playwright), a non-root user (uid 10001), port 8501, headless, and a `HEALTHCHECK` on `/_stcore/health`. No secrets
in the image.

```sh
docker build -f Dockerfile.console -t airgap-console .
docker run --rm -p 8501:8501 \
  -v "$PWD/secrets.toml:/app/.streamlit/secrets.toml:ro" \
  -e AIRGAP_EXECUTOR_URL=https://<api-id>.execute-api.eu-central-1.amazonaws.com/prod \
  -e AIRGAP_UI_OPERATORS=... -e AIRGAP_UI_AUDITORS=... \
  -e AWS_REGION=eu-central-1 airgap-console      # + credentials from the task role / instance profile
```

AWS credentials: the console signs its calls with SigV4 as `airgap-host` (operators) or `airgap-auditor` (auditors),
assumed from the container's own role. Give that role `sts:AssumeRole` on those two roles only. A stricter setup runs
two deployments: an auditor console whose role can assume only `airgap-auditor`, and an operator console.

### Behind the bank's reverse proxy and SSO

- **TLS ends at the proxy**; the container listens on 8501 on a private network only.
- **WebSockets**: Streamlit's UI runs over a WebSocket at `/_stcore/stream`. The proxy must pass `Upgrade` and
  `Connection` headers and allow long-lived connections (idle timeout ≥ 60 s; the console refreshes every 10 s).
  With more than one replica, use sticky sessions.
- **Redirect URI**: `redirect_uri` must be the external URL plus `/oauth2callback`, registered with the identity
  provider. If the console lives under a path, set `STREAMLIT_SERVER_BASE_URL_PATH` and include it in the URI.
- With `[auth]` configured, Streamlit forces XSRF protection and CORS checks on. Do not embed the console in an iframe;
  Streamlit does not support auth in embedded apps.
- **SSO at the proxy as well** (for example the bank's access gateway in front of the hostname) is fine and
  recommended as defence in depth. The console still does its own OIDC sign-in and role check; it does not trust
  identity headers set by a proxy.
- Health checks: `GET /_stcore/health` returns `ok`. It needs no sign-in and shows no data.
- Logs: stdout carries one `{"event": "console_access", ...}` JSON line per session; ship it with the container logs.

### Alerts

```sh
python -m host.alerts --url <executor> --webhook https://hooks.example/... --state-file alerts.json [--interval 10]
make alerts WEBHOOK=https://hooks.example/...      # without WEBHOOK it prints (--dry-run)
```

The watcher reads the audit export with the auditor principal and posts one Slack/Teams-compatible `{"text": ...}`
message per blocked attempt. Delivery is at least once (`--state-file` survives restarts). It posts one message when
it loses contact with the executor and one when contact is back.
