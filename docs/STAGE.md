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

1. AWS owner: `python -m infra.reset_state --yes` (wipes 7 tables, seeds registry + `data/enrollment.json`
   signers with their `enroll` leaves, first checkpoint). Nobody else resets.
2. Re-seal the stage bundle once the freeze build is deployed: `make demo-bundle` (refuses unless green), then
   `make offline-demo` once while online (builds `noteverify`).
3. Device operator: Safe 3 auto-lock to max (Settings -> Auto-lock), short data cable seated and taped, no hub.
4. Laptop: `tests/device/tenv.sh` (T3B1 emulator = treasury, homescreen reads `EMULATOR`).
5. `make preflight` -> **PREFLIGHT GREEN**. Fix any FAIL row with the recovery table below. Re-run at T-10 min.
6. Camera rig per `docs/device/demo-rig.md` (phone over the Safe 3, mirrored by cable, exposure locked low).

## Beats

| Time | Beat | Command (laptop driver) | Device operator | Notes |
|---|---|---|---|---|
| 0:00-0:15 | Hook + disclosure | - | - | "This agent is compromised right now. It still can't move a koruna." |
| 0:15-0:45 | **S1 normal day** | `.venv/bin/python -m host.signer s1 --url $API` | 2 holds: MANDATE (4 pages), then PAY 125000.50 CZK (4 pages) | single shot per reset (I-DUP / I-SPLIT within 24 h). Treasury = emulator, auto-confirm, labelled "simulated human". Then `make checkpoint-now` for the witness tick |
| 0:45-1:35 | **S2 lookalike BEC + escalation + exfil** | today: `.venv/bin/python -m host.signer scene s2` (memory backend, device signers) | **device stays dark** for the change; one PAY hold inside the escalation step (the replay re-sends it, no second hold) | **TBD WS-F/WS-A:** AWS version of the scene. IAM AccessDenied / VPC no-route evidence is WS-E's (AWS only) |
| 1:35-2:30 | **S3 takeover + deepfake, then legit change** | today: `.venv/bin/python -m host.signer scene s3` | device dark through the takeover (ATT 0/3 = BLOCK, "there is no button"); then CHG clerk 1/2: 4 pages, `ATT 2/3 ERP BANK` is always on page 3 (pinned), hold | treasury 2/2 on the emulator. **TBD WS-F/WS-A:** AWS version |
| 2:30-3:20 | **S5 offline audit** | Wi-Fi off, then `make offline-demo` | - | stock Go `noteverify` + `verify_audit` green, one-byte flip red at `seq N`. Lines to say: `docs/audit/DEMO-LINES.md` |
| 3:20-4:00 | Bench + real-vs-simulated | `bench/results/REPORT.md` on screen | - | WS-F |

Every device prompt prints `--> CLERK on Safe 3 GENUINE: read every page, then HOLD the right button` on the
laptop: that is the operator's cue. The host UI (`make ui`, WS-F) is the projector's left side;
**TBD WS-F:** it calls the API without SigV4 today, so on AWS it needs a SigV4 client (see `host.signer.executor_call`).
**TBD WS-E:** a one-command entry point for the agent beat (`agent.agent.run_agent` has no CLI yet).

## Fallback switch (emulator clerk)

Flip it when the physical Safe 3 cannot be brought back within 60 s (see "USB drop"), or before the demo if
`make preflight` shows the device row red and cannot be fixed:

```
export AIRGAP_TREZOR_PATH=udp:127.0.0.1:21324     # the one switch; unset to go back
```

- Every signer then prints `*** FALLBACK MODE: CLERK SIGNS ON THE EMULATOR (T3B1), NOT THE PHYSICAL DEVICE ***`;
  say it out loud. The emulator screen goes on the projector from http://127.0.0.1:9001.
- In-process scenes (`host.signer s1` without `--url`, `scene s2|s3`) work in fallback today (rehearsed green).
- **On AWS** the fallback clerk `0x73d0385f4d8e00c5e6504c6030f47bf6212736a8` is enrolled but **inactive**
  (`data/enrollment.json`). **TBD WS-E/WS-D:** a reset variant that activates it; until then the AWS fallback is the
  recorded video, not a live emulator signature.
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
