# AirGap Mandates

> AI may propose. Policy may block. Only a human-held key may move money — and the supervisor can prove it offline.

The FinTechers Hackathon 2026 · Track 3 "Securing the agentic bank".

A bank back-office AI agent proposes payments but holds no write credential. An executor outside the operator's laptop pays only within a mandate signed on a hardware device (Trezor Safe 3), or after a human holds-to-confirm exactly what the device display shows — and the display shows only facts the executor verified itself. A new payee account needs 2-of-3 independent supplier attestations (SD-JWT VCs bound to the change) and dual control on two devices. Every input, decision, signature and execution lands in a C2SP-format transparency log, cosigned by witnesses and verifiable offline (log signatures with unmodified upstream Go; entries and cosignatures with our open verifier).

The demo runs on AWS eu-central-1 (executor, store, KMS, Object Lock, Bedrock, witnesses). The local `memory`/`moto` backends exist for development and CI only.

**For a bank's architecture and risk teams:** [`docs/BANK-READINESS.md`](docs/BANK-READINESS.md) covers the deployment, what the bank must integrate (pain.001 handoff, SSO, mail, supplier master, devices, issuers, VoP), the control mapping, the threat model, the operating model, what is simulated, and the gap list to a pilot. It also explains how to run the console behind corporate SSO (`Dockerfile.console`) and the alert watcher (`make alerts`).

## For contributors

- Design (what and why): [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
- Shared contracts v2 (API, storage, device display bytes, audit log, Cedar rules, invariants, env): [`docs/CONTRACTS.md`](docs/CONTRACTS.md), machine-readable in `contracts/` (`make contracts`).
- `make venv`, `make test`, `make ci` (contracts up to date → ruff → pytest), `make dev` (local executor, development only).

## Pre-existing work

None. The repository starts at the `hackathon-start` tag, an empty commit made at kickoff (Mon 19 Oct 2026, 12:02 CEST). Before kickoff we only prepared a written plan outside the repository (not code). Everything in this repository was written during the hackathon. Open-source libraries and datasets we build on are credited below.

## Built during the hackathon

Everything after the `hackathon-start` tag. This list is updated as modules land:

- [x] Architecture v2 and shared contracts v2 (schemas, fixtures, Cedar policy sets, FSM v2 table)
- [x] `safe3-mono-16x4` device renderer for the Trezor Safe 3 with byte-exact goldens (WS-C); `safe5-mono-18x7` kept as a non-default profile
- [ ] WS-A executor core: dispatch, store (memory/moto/DynamoDB), Cedar `decide()`, mandates 2/2, single-use nonces, single `TransactWriteItems` execution, pain.001 rail, receipts API
- [ ] WS-B transparency log: leaves v2, signed-note checkpoints (KMS Ed25519), W1 `add-checkpoint` witness, W2 litewitness relay, receipts/QR, export, `verify_audit.py` with decision replay, `noteverify` (Go)
- [ ] WS-C device: Safe 3 (USB) + T3B1 emulator signer worker, screen oracle, enrolment ceremony, camera rig
- [ ] WS-D payee change: FSM v2, facts engine on content-hashed snapshots (incl. Mostly Right), VoP mock, 3 SD-JWT VC issuers + verifier, vendor portal (callback, tripwire, break-glass)
- [ ] WS-E agent and perimeter: AP-Clerk (naive + quarantined), tools λ with Cedar tool policies / AgentCore Gateway, egress λ + DLP, VPC without NAT, IAM split, IaC
- [ ] WS-F bench and demo: H0–H6 attackers, arms A0–A3, simulated humans, Wilson CIs, dashboard, demo scenes, fallback video

## Open source / data we build on

- Libraries: `eth-account`, `trezor` (trezorlib), `cedarpy` (Cedar), `sd-jwt`, `cryptography`, `pynacl`, `boto3`, `dkimpy`, `dnspython`, `schwifty`, `rapidfuzz`, `confusable_homoglyphs`, `lxml`, `zeep`, `jsonschema`, `fastapi`, `uvicorn`, `streamlit`, `pytest`, `hypothesis`, `moto`, `ruff`.
- Specifications and verifiers: C2SP signed-note / tlog-checkpoint / tlog-witness / tlog-cosignature, Go `golang.org/x/mod/sumdb/note`, litewitness (filippo.io/torchwood), RFC 6962/9162, RFC 8785 (JCS), EIP-191, SD-JWT (RFC 9901) and SD-JWT VC (draft), ISO 20022 pain.001, EPC VoP codes.
- Data: the **Mostly Right** dataset provided at the hackathon (CNB and ESMA licence registers, SEPA Instant and VoP participant lists, EU sanctions, regulator warning lists) feeds the F-PSP, F-WARNLIST and F-SANCTION facts; the ČNB synthetic transactions dataset (thresholds, benign traffic); the Tapaya KYB pack (supplier enrolment examples).

## AI assistance

We use AI coding assistants (Claude Code) during the hackathon.

## Data

Synthetic and fictitious only (companies, people, inbox, invoices). The hardware wallet uses a dedicated demo seed holding no funds.
