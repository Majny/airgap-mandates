# Stage runbook (Tue 20 Oct, 4:00 demo)

One page for the stage laptop. Every command below was run on 2026-10-19 unless marked **TBD** (owner named).
Beat timings follow ARCHITECTURE §14. Owner: WS-C (device and runbook); scene owners as marked.

```
API=https://ehhxkpbfcc.execute-api.eu-central-1.amazonaws.com/prod      # regional API, SigV4 (airgap-host)
export AWS_PROFILE=hackathon
```

## People and hands

| Role | Does | Never does |
|---|---|---|
| **Presenter** | narrates, points at line 1 `AG1/DEMO ...` on projector + device | touches the laptop during a device beat |
| **Device operator** | Safe 3 only: RIGHT = next page, hold RIGHT ~1 s on the last page (CONFIRM). Reads each page ~1 s for the camera | presses anything when the script says "device stays dark" |
| **Laptop driver** | runs the commands below, watches for the `-->` prompt lines | types a passphrase or PIN on the host (the PIN is entered on the device) |
| **AWS owner** (WS-E) | reset, `make checkpoint-now`, SSO re-login | runs a reset during the demo |

## T-60 min: reset routine (Tue 11:00, after the 06:00 policy freeze)

1. AWS owner: `make demo-reset` (= `python -m infra.reset_state --yes`; wipes 7 tables, seeds registry +
   `data/enrollment.json` signers with their `enroll` leaves, resets W2's litewitness state for our origin, first
   checkpoint; ~72 s). Add `--fallback-clerk` only
   if the fallback switch is decided before the demo. Then `python -m infra.load_inbox --url $API` (8 emails, 5 s).
   Nobody else resets. W2 cosigns every checkpoint automatically (checkpointer tick -> `witness.relay_w2.after_tick`
   over SSM); manual fallback: `python -m witness.relay_w2 --executor-url $API --aws-role airgap-relay --read-role
   airgap-auditor --w2-ssm i-0bc5865c1ddae7b1d` with `AIRGAP_W2_VKEY` set.
2. **While online:** `make .local/bin/noteverify` (Go build; the offline beat cannot build it with Wi-Fi off).
3. Re-seal the stage bundle once the freeze build is deployed: `make demo-bundle` (refuses unless green), then
   `make offline-demo` once to see ALL PASS.
4. Device operator: Safe 3 auto-lock to max (Settings -> Auto-lock), short data cable seated and taped, no hub.
5. Laptop: `tests/device/tenv.sh` (T3B1 emulator = treasury, homescreen reads `EMULATOR`).
6. `make preflight` -> **PREFLIGHT GREEN**. Fix any FAIL row with the recovery table below. Re-run at T-10 min.
7. Camera rig per `docs/device/demo-rig.md` (phone over the Safe 3, mirrored by cable, exposure locked low).

## Beats

Wall times are measured (WS-E dress rehearsal #1 on AWS with software keys; WS-C device runs). Human holds add
~20 s per device prompt (4 pages read + 1 s hold; measured 11-24 s on the physical Safe 3).

| Time | Beat | Command (laptop driver) | Device operator | Notes |
|---|---|---|---|---|
| 0:00-0:15 | Hook + disclosure | - | - | "This agent is compromised right now. It still can't move a koruna." |
| 0:15-0:45 | **S1 normal day** | `.venv/bin/python -m host.signer s1 --url $API` | 2 holds: MANDATE (4 pages), then PAY 125000.50 CZK (4 pages) | 7 s machine time + 2 holds (~45 s with the human; physical run on AWS twice, green bundle). Single shot per reset (I-DUP / I-SPLIT within 24 h). Treasury = emulator, auto-confirm, labelled "simulated human". Then `make checkpoint-now` for the witness tick. Agent variant: `make agent-s1` (42 s, Sonnet; run it on a fresh reset or ACME/Beta step up after S1) |
| 0:45-1:35 | **S2 lookalike BEC + escalation + exfil** | `.venv/bin/python -m host.signer scene s2 --url $API` (software keys: `make demo-s2`, 4 s) | **device stays dark** for the change; one PAY hold inside the escalation step (the replay re-sends it, no second hold) | `make agent-s2` (14 s): the agent declines the BEC email. Rehearsal #1 failed at step 3 (F-AMOUNT-DOC); fixed on main (`8428c3b`), re-verify in rehearsal #2. IAM AccessDenied / VPC no-route evidence is WS-E's |
| 1:35-2:30 | **S3 takeover + deepfake, then legit change** | `.venv/bin/python -m host.signer scene s3 --url $API` (software keys: `make demo-s3`, 52 s incl. the 20 s cooling-off) | device dark through the takeover (ATT 0/3 = BLOCK, "there is no button"); then CHG clerk 1/2: 4 pages, `ATT 2/3 ERP BANK` is always on page 3 (pinned), hold | treasury 2/2 on the emulator. Talk over the 20 s cooling-off |
| 2:30-3:20 | **S5 offline audit** | before Wi-Fi off: `make demo-s5` (seals the AWS export + a tampered copy, 3 s); Wi-Fi off: `bash tools/offline_demo.sh .local/demo/s5` (1 s) | - | stock Go `noteverify` + `verify_audit` green, one-byte flip red at `seq N`. Lines to say: `docs/audit/DEMO-LINES.md`. Backup: `make offline-demo` on the pre-sealed `docs/audit/demo` |
| 3:20-4:00 | Bench + real-vs-simulated | `bench/results/REPORT.md` on screen | - | WS-F |

Every device prompt prints `--> CLERK on Safe 3 GENUINE: read every page, then HOLD the right button` on the
laptop: that is the operator's cue. The host UI (`make ui`, WS-F) is the projector's left side;
**TBD WS-F:** it calls the API without SigV4 today, so on AWS it needs a SigV4 client (see `host.signer.executor_call`).
Keep AWS runs serialized: Lambda concurrency in this account is 10 in total.

## Fallback switch (emulator clerk)

Flip it when the physical Safe 3 cannot be brought back within 60 s (see "USB drop"), or before the demo if
`make preflight` shows the device row red and cannot be fixed:

```
export AIRGAP_TREZOR_PATH=udp:127.0.0.1:21324     # the one switch; unset to go back
```

- Every signer then prints `*** FALLBACK MODE: CLERK SIGNS ON THE EMULATOR (T3B1), NOT THE PHYSICAL DEVICE ***`;
  say it out loud. The emulator screen goes on the projector from http://127.0.0.1:9001.
- In-process scenes (`host.signer s1` without `--url`, `scene s2|s3`) work in fallback (rehearsed green).
- **On AWS** the fallback clerk `0x73d0385f4d8e00c5e6504c6030f47bf6212736a8` is enrolled **inactive** by default.
  It becomes active only through a reset with `--fallback-clerk` (AWS owner; a new, logged `enroll` leaf), so the
  decision to fall back on AWS is made **before** the demo reset, never live. Without it, the AWS fallback is the
  recorded video. `host.signer ... --url` refuses to run if a device address is not active (says which reset).
- **Rehearsed on AWS** (Mon, WS-C, after `reset_state --fallback-clerk`, emulator clerk + treasury, auto-confirm):
  `scene s2 --url $API` GREEN in 29 s, `scene s3 --url $API` GREEN in 67 s; CHG shows the pinned `ATT 2/3 ERP BANK`
  (logs: `docs/device/rehearsal/aws_fallback_s*.log`). **Open (WS-B):** the audit bundle of a `--fallback-clerk`
  deployment is RED ("approver 0x73d0...: does not match an enroll leaf"): the re-enrolment writes a second enroll
  leaf and the export/verifier assume one per address. The S5 beat after a fallback run must use the pre-sealed
  `docs/audit/demo` until that is fixed.
- Last resort for any beat: the pre-recorded video (WS-F). First real-device take: `docs/device/photos/`.

## Recovery

| Symptom | Cause | Fix (in order) |
|---|---|---|
| Command prints nothing for >20 s before the first `-->` prompt | Safe 3 dropped off USB or auto-locked (seen at H0: silent stall) | Ctrl-C. Re-plug, enter PIN on the device, `.venv/bin/python -m host.signer info` must show `GENUINE`. Re-run the beat. On AWS a half-finished S1 needs a reset (AWS owner, ~3 min) or the video |
| `TimeoutError: no confirmation on the device within 300s` | nobody held CONFIRM | the host already cancelled; device is back home. Re-run the beat (in-process) or reset (AWS) |
| `Cancelled` | operator pressed back on page 1 | re-run |
| `trezorctl list` shows only `udp:` | Trezor Suite holds USB, or charge-only cable | quit Suite, swap to the taped data cable |
| Emulator `udp device not found` | tenv container down | `tests/device/tenv.sh` (30-60 s) |
| `ExpiredToken` / preflight "AWS credentials" red | SSO session expired (re-login was Tue 01:00) | `aws sso login --profile hackathon` (browser), then `make preflight` |
| `/health` policy_hash or code_sha256 red | laptop checkout != deployed build | `git checkout <deployed rev>` (the freeze tag), or ask WS-E which rev is deployed |
| Bedrock `ThrottlingException` | team-wide 50 req/min shared | stop bench/other sessions 10 min before stage; wait 60 s and retry once; else show the recorded agent run (S2 does not need a live LLM call to show the gate) |
| `offline verify` red | wrong or stale `docs/audit/demo` | `make demo-bundle` (online), then `make offline-demo` |
| 403 `unknown_signer` on a device signature | the device address is not enrolled/active in this deployment | check the reset seeded `data/enrollment.json`; never "fix" it on stage by enrolling ad hoc |

## What we say about the device (true, with proof)

- "A genuine Trezor Safe 3: its secure element's certificate chain checks out against Trezor's root, and its firmware
  hash equals the official 2.12.0 release." Proof: `docs/device/measurements.md` "Device evidence".
- "The device shows exactly the bytes it signs: 16 columns, 4 lines per page, ASCII only; the confirm button exists
  only on the last page." Proof: `tests/device/test_screens.py` (emulator PNG goldens), `docs/device/h0/`.
- "Last night we ran S1 on AWS with this device and sealed the audit bundle; it verifies offline." Proof:
  `docs/audit/aws-physical-mon/README.md`.
- Say "the treasury signer is an emulator in this demo; production refuses emulator keys".

## Rehearsal log

**Mon 19 Oct, AWS dress rehearsal #1** (WS-E conducting; software keys, no device; deployed bundle `48ff9166`).
Raw logs: `infra/evidence/rehearsal/`.

| Step | Command | Result | Wall time |
|---|---|---|---|
| reset | `make demo-reset` | PASS (log size 13, no stale checkpoint) | 72 s |
| inbox | `python -m infra.load_inbox --url $API` (ingest role) | PASS 8/8 | 5 s |
| S1 software | `make demo-s1` | PASS: mandate 2/2, 3 paid, 125000.50 step-up executed, replay 403 | 7 s |
| agent S1 | `make agent-s1` (agent λ in no-NAT VPC, Sonnet, quarantined) | PASS: 3 proposals; after S1, ACME and Beta step up (F-SPLIT / I-SPLIT on the 24 h vendor sum), Gamma allowed | 42 s |
| agent S2 | `make agent-s2` | PASS: agent declines the BEC email (no proposal) | 14 s |
| S2 | `make demo-s2` | **FAIL at step 3**: change REJECTED device dark + BEC proposal deny OK; the escalation PAY was a deny [F-DUP, F-MANDATE, F-SPLIT, I-BLOCK, I-DUP] instead of a challenge: it reused S1's Beta 125000.50 amount on the same ledger (diagnosed by WS-A; my first guess, F-AMOUNT-DOC, was wrong). Fixed on ws-a-executor (step 3 = Beta 91200.00 BS-2026-1201) | 4 s |
| S3 | `make demo-s3` | PASS: takeover REJECTED (ATT 0/3), legit change ACTIVE after the 20 s cooling-off | 52 s |
| S5 | `make demo-s5` then `bash tools/offline_demo.sh .local/demo/s5` | PASS (ALL PASS offline, tamper caught at seq 70) after `make .local/bin/noteverify` (Go, online) | 3 s + 1 s |
| reset | `make demo-reset` | PASS | 73 s |

Total wall time 276 s (beats only: about 2 min; the two resets dominate). Order note: running the agent S1 beat
after the S1 scene makes ACME/Beta step up (24 h vendor sum); on stage, run the agent beat on a fresh reset or accept
the challenges as part of the story. Build `noteverify` while online before the stage (`make .local/bin/noteverify`).
Lambda concurrency in this account is **10 in total** (all functions, all teams): keep AWS runs serialized.
