# AirGap Mandates

> AI may propose. Policy may block. Only a human-held key may move money — and the supervisor can prove it offline.

The FinTechers Hackathon 2026 · Track 3 "Securing the agentic bank".

A bank back-office AI agent proposes payments but holds no write credential. An executor outside the operator's laptop pays only within a mandate signed on a hardware device (Trezor Safe 5), or after a human signs exactly what the device display shows — and the display shows only facts the executor verified itself. Payee changes require a supplier attestation (2-of-3) and dual control on our side. Every decision lands in an offline-verifiable Merkle audit log.

## For contributors

Shared contracts (API, DynamoDB, canonical display text, audit log, invariants): [`docs/CONTRACTS.md`](docs/CONTRACTS.md), machine-readable in `contracts/`. `make venv test dev`.

## Pre-existing work

None. The repository starts empty at the `hackathon-start` tag. Before kickoff we only prepared a written plan (not code). Open-source libraries we build on are credited below.

## Built during the hackathon

Everything after the `hackathon-start` tag (Mon 19 Oct 2026, 12:00 CEST). This section is updated as modules land:

- [ ] M0 executor core (canonical render, signature recovery, nonce/TTL, mandate, ledger)
- [ ] M1 executor-verified facts [F] vs host hints [H]
- [ ] M2 payee-change protocol (state machine)
- [ ] M3 supplier account attestation (2-of-3) + transparency log + witness
- [ ] M4 in-mandate invariants + "Replay a month"
- [ ] M5 audit log with completeness (RFC 9162, KMS, anchors, offline verify)
- [ ] M6 egress gateway against data exfiltration
- [ ] M7 AgentPayBench

## Open source we build on

To be listed as dependencies are added.

## AI assistance

We use AI coding assistants (Claude Code) during the hackathon.

## Data

Synthetic only. The hardware wallet uses a dedicated demo seed holding no funds.
