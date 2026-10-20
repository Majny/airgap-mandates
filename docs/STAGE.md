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

1. AWS owner: `.venv/bin/python -m infra.reset_state --yes --stage` (stage: the software e2e keys are NOT enrolled, so the
   sealed bundle lists only the physical clerk (GENUINE), the emulator treasury and the inactive fallback; rehearsals
   use `make demo-reset` = without `--stage`; wipes 7 tables, seeds registry +
   `data/enrollment.json` signers with their `enroll` leaves, resets W2's litewitness state for our origin, first
   checkpoint; ~72 s). Add `--fallback-clerk` only
   if the fallback switch is decided before the demo. Then `.venv/bin/python -m infra.load_inbox --url $API` (9 emails, 5 s).
   Nobody else resets. W2 cosigns every checkpoint automatically (checkpointer tick -> `witness.relay_w2.after_tick`
   over SSM); manual fallback: `python -m witness.relay_w2 --executor-url $API --aws-role airgap-relay --read-role
   airgap-auditor --w2-ssm i-0bc5865c1ddae7b1d` with `AIRGAP_W2_VKEY` set.
2. **While online:** `make .local/bin/noteverify` (Go build; the offline beat cannot build it with Wi-Fi off) and
   `make data` (rebuilds `data/mostlyright/snapshot.sqlite` to the committed `snapshot.sha256`; stale after any
   rebase that changes it, ~22 tests and the facts go wrong otherwise; `make preflight` checks it).
3. Re-seal the stage bundle once the freeze build is deployed: `make demo-bundle` (refuses unless green), then
   `make offline-demo` once to see ALL PASS.
4. Device operator: Safe 3 auto-lock to max (Settings -> Auto-lock), short data cable seated and taped, no hub.
5. Laptop: `tests/device/tenv.sh` (T3B1 emulator = treasury, homescreen reads `EMULATOR`).
6. `make preflight` -> **PREFLIGHT GREEN**. Fix any FAIL row with the recovery table below. Re-run at T-10 min.
7. Camera rig per `docs/device/demo-rig.md` (phone over the Safe 3, mirrored by cable, exposure locked low).

## Tue 11:00 human session (after the 06:00 freeze): stage bundle + fallback video, one run

One run of the one-beat S1 with the **physical** Safe 3 produces both the pre-sealed stage bundle and the re-shot
fallback video, so the recorded screens match what the judges see live (the Monday take shows the pre-freeze screen).

1. Laptop on the frozen rev (`git checkout` the deployed main), `make data`, `make preflight` GREEN (hash rows match
   the deploy; the agent builds its task from this checkout's `data/emails/manifest.json`).
2. AWS owner: `make demo-reset` (normal, no `--fallback-clerk`) + `.venv/bin/python -m infra.load_inbox --url $API` (9 emails).
3. Camera rig recording (docs/device/demo-rig.md). Device operator ready, Safe 3 unlocked.
4. `.venv/bin/python -m host.signer s1 --with-agent --url $API`: hold 1 = MANDATE, then the agent pays ACME, Beta and
   Gamma (no taps, ~40-75 s), hold 2 = the Delta 125000.50 CZK step-up; replay refused. Stop recording.
5. `make checkpoint-now`, then `make stage-bundle` (seals the AWS export into `docs/audit/demo`, W2 pinned,
   refuses unless green) and `make offline-demo` (strict log + W1 + W2 quorum, ALL PASS). Commit the bundle + video (`docs/device/photos/`).
6. AWS owner resets again for the stage itself (S1 is single-shot per reset).

## Beats

Wall times are measured (WS-E dress rehearsal #1 on AWS with software keys; WS-C device runs). Human holds add
~20 s per device prompt (4 pages read + 1 s hold; measured 11-24 s on the physical Safe 3).

| Time | Beat | Command (laptop driver) | Device operator | Notes |
|---|---|---|---|---|
| 0:00-0:15 | Hook + disclosure | - | - | "This agent is compromised right now. It still can't move a koruna." |
| 0:15-0:45 | **S1 normal day (one beat, real agent)** | one command: `.venv/bin/python -m host.signer s1 --with-agent --url $API`, or the three parts: (1) `host.signer mandate --url $API`, (2) `make agent-s1`, (3) `host.signer payup --url $API` | 2 holds: (1) MANDATE, 4 pages; (3) PAY step-up of the 4th vendor's over-cap invoice, 4 pages. Nothing to press while the agent pays the 3 legit invoices | (1) mandate 80000/payment, 250000 total, clerk device + treasury emulator 2/2. (2) the agent λ (no-NAT VPC, Sonnet) pays ACME, Beta and Gamma under the mandate (no taps). (3) the 4th vendor's invoice (WS-D fixture `09_delta_invoice_overcap.eml`, due 2026-10-18) is over the per-payment cap and is not paid by the agent: device step-up -> executed; replay -> 403 `nonce_reused`. The 4th vendor has no other payment that day, so no F-SPLIT carry-over. Single shot per reset. Then `make checkpoint-now`. **Rehearsed green on AWS** (fallback, deploy `0b41856`, 79 s): 3 ALLOW + Delta CHALLENGE `[F-MANDATE, I-PER, I-WARN]` -> executed, replay 403; bundle sealed green (log+W1+W2), offline ALL PASS (`docs/device/rehearsal/aws_stage_s1_fallback.log`) |
| 0:45-1:35 | **S2 lookalike BEC + escalation + exfil** | `.venv/bin/python -m host.signer scene s2 --url $API` (software keys: `make demo-s2`, 4 s) | **device stays dark** for the change; one PAY hold inside the escalation step (the replay re-sends it, no second hold) | `make agent-s2` (14 s): the agent declines the BEC email. Rehearsal #1 failed at step 3 (reused S1's 125000.50 amount -> F-DUP/I-DUP deny); fixed on main (`8428c3b`, step 3 = Beta 91200.00), re-verified on AWS 2026-10-19 20:45 (SCENE S2 OK). IAM AccessDenied / VPC no-route evidence is WS-E's |
| 1:35-2:30 | **S3 takeover + deepfake, then legit change** | `.venv/bin/python -m host.signer scene s3 --url $API` (software keys: `make demo-s3`, 52 s incl. the 20 s cooling-off) | device dark through the takeover (ATT 0/3 = BLOCK, "there is no button"); then CHG clerk 1/2: 4 pages, `ATT 2/3 ERP BANK` is always on page 3 (pinned), hold | treasury 2/2 on the emulator. Talk over the 20 s cooling-off |
| 2:30-3:20 | **S5 offline audit** | before Wi-Fi off: `make demo-s5` (seals the AWS export + a tampered copy, 3 s); Wi-Fi off: `QUORUM=log,w1,w2 bash tools/offline_demo.sh .local/demo/s5` (1 s; every checkpoint must carry log + W1 + W2) | - | stock Go `noteverify` + `verify_audit` green, one-byte flip red at `seq N`. Lines to say: `docs/audit/DEMO-LINES.md`. Backup: `make offline-demo` on the pre-sealed `docs/audit/demo` (only once it shows policy `d33008c4`, i.e. after Tue 11:00 `make stage-bundle`) |
| 3:20-4:00 | Bench + real-vs-simulated | `bench/results/REPORT.md` on screen | - | WS-F |

Every device prompt prints `--> CLERK on Safe 3 GENUINE: read every page, then HOLD the right button` on the
laptop: that is the operator's cue. The host UI (`make ui`, WS-F) is the projector's left side;
The UI calls the API with SigV4 via `host.signer.executor_call`.
Keep AWS runs serialized: Lambda concurrency in this account is 10 in total.

## Attack h beat: the Trezor exposes malware on the clerk's PC (two screens + device)

Projector: bank console `make ui` (:8501) left, attacker workstation `make attacker` (:8502) right, Safe 3 on camera.
The attacker is a separate app on another port: nothing in the bank console triggers it.

Three screens, in this order: supplier `make supplier` (:8503) sends an invoice email (pick Delta Stavby, 118 750 CZK,
"Send invoice"; nobody keys a payment into the bank), the bank console (:8501) shows it under Payments waiting for the
Trezor (up to the 80 000 CZK cap it would be paid automatically), then the attacker (:8502) attacks it with h. The
supplier's "Sent invoices" list follows the bank's decision live. Locally: `make local-stack` and point all three at
`http://127.0.0.1:8000` (`SUPPLIER_URL=`, `ATTACK_URL=`, `UI_URL=`); `make attack-visual` runs this whole flow.

The 300 s rule: a PAY approval request dies 300 s after the payment was proposed, it is never re-issued, and a reject
does not restart the clock (executor `challenge_ttl_seconds`; confirmed by WS-A). Propose right before the beat.

1. Laptop: `.venv/bin/python -m host.signer s1 --with-agent --leave-pending --url $API`: hold 1 = MANDATE, the agent
   pays ACME/Beta/Gamma, Delta 125000.50 CZK is left waiting (prints `--> WAITING ... dies at`). The bank console shows
   it under Payments with "Approve within m:ss". If it died: `make overcap` (fresh legitimate Delta invoice, 118750.00;
   `AMOUNT=` to change) and `make pending` to see what waits.
2. Attacker screen: attack h "Malware on the clerk's PC" -> Launch. It shows "waiting for the clerk to approve".
   The bank console shows nothing new: the malware is invisible there.
3. Bank console, Payments, Delta: "Approve on Trezor". The device shows the attacker's account
   (`LT48 3999 0000 / 0000 1234`) where the screen shows `CZ52 0100 0000 / 0077 8899 0011`.
4. Device operator REJECTS: press LEFT until the first screen ("Signing address"), then LEFT once more (5 presses from
   the hold page). One LEFT on the hold page only goes back a page. One button at a time.
   Bank: "You rejected it on the Trezor. Nothing was paid." Attacker: outcome + money to attacker 0.00 CZK.
   (If someone holds CONFIRM instead: executor 403 `render_mismatch`, "Tampered approval stopped", still 0.00 CZK.)
5. "Approve on Trezor" again (the implant was one-shot): the device shows Delta's real account, hold -> "Paid ·
   confirmed on Trezor". Line to say: "The screen was owned. The Trezor showed what was really being signed, and the
   executor only accepts its own text."

The console waits 90 s for the device (`AIRGAP_UI_SIGN_TIMEOUT_S`), so a missed reject still leaves time for step 5.

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
  (logs: `docs/device/rehearsal/aws_fallback_s*.log`). `--fallback-clerk` now activates the clerk before seeding,
  so each address has exactly one `enroll` leaf (WS-E); the verifier also accepts re-enrolments (WS-B `f5cbe7b`).
- **Fallback S5 seal confirmed on AWS** (deploy `03d1b55`, `reset_state --fallback-clerk`, S2 29 s + S3 67 s, then
  `make checkpoint-now`): `tools.demo_bundle --from-aws` SEALED green (60 leaves, 6 checkpoints, cosigned by log +
  W1 + W2; one `enroll` leaf per address with `active`), and `tools/offline_demo.sh` ALL PASS offline. Logs:
  `docs/device/rehearsal/aws_fallback2_s*.log`. The fallback path can therefore seal its own S5 bundle on stage.
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

## Reading the logs

Track 3 asks for "a live attack that fails, and logs that show why". Every attack line, card and alert says it the
same way (`executor/audit/explain.py`): **threat** in the brief's words · what happened · **stopped by** which defence
layer, **because** of which evidence · money at stake vs moved.

| threat | examples | layer that stops it |
|---|---|---|
| `PROMPT INJECTION` | instruction hidden in an invoice (attack c), decoy tool `mandate.write` (`T-DECOY`), `T-TAINT`, `F-ANOM` | input sanitisation (agent hints never evidence) · permission scoping · anomaly detection on agent actions |
| `DATA EXFILTRATION` | `T-MAIL-*`, egress `E-ALLOWLIST` / DLP | permission scoping (tool policy) · egress gateway |
| `PRIVILEGE ESCALATION` | stolen agent credentials (`caller_not_allowed`, attack d), an IBAN smuggled into a request, IAM deny | permission scoping |
| `PAYMENT FRAUD (BEC)` | lookalike domain (attack a), VoP no match, sanctions / warn list | executor facts + policy |
| `ACCOUNT TAKEOVER` | real supplier mailbox asks for a new account (attack b, held), "not us" tripwire | executor facts + policy |
| `REPLAY / FORGERY` | replayed approval (e), foreign key (f), fake supplier attestation (g) | hardware signature · executor facts + policy |
| `HOST TAMPERING` | malware on the clerk's PC swaps the account sent to the Trezor (h) | hardware signature (`render_mismatch`) |
| `LOG TAMPERING` | witness refuses to cosign / log fork | transparency log |

Three screens show it while the attack runs:

- **Attacker console** (`:8502`): under every attack, a white box "THE BANK'S LOG": the bank's own lines for that
  attack, read back from the executor (audit export + explain, plus the refused-at-the-door ring below), threat
  label, layer, evidence, audit seq. Attack h's box fills in when the clerk approves on the bank console.
- **Bank console, Security tab** (`:8501`, refreshes every `AIRGAP_UI_REFRESH_S`): one row of tiles (prompt injection ·
  data exfiltration · privilege escalation · fraud & tampering · **0.00 CZK moved to attackers**), then the **newest
  live incident as one big card** (threat, what happened, who / from where, what they tried, stopped by <layer>
  because <evidence>, money at stake vs moved, "✔ deterministic · verifiable offline", audit seq and policy hash), older
  incidents as one-liners that open on click, and the seeded S2/S3 scenes collapsed at the bottom as "Demo backdrop"
  (never counted in the tiles, the red banner or the "Incidents blocked" KPI: a fresh stack opens calm; one incident
  groups the attempts on one payment, change or agent session, so 8 attack runs give more incidents than runs). "Your next
  step" on a card never vouches for a payment: verify with the supplier on the contact registered in the vendor
  master, and the Trezor screen is the only truth. **Audit → Event log**: every audit entry in plain words.
- **Executor ops log** (terminal of `make local-stack` / `make dev`; CloudWatch on AWS):

  ```
  2026-10-20T10:31:05.019Z 🛑 ATTACK  PRIVILEGE ESCALATION · Stolen agent credentials? The AI agent's account (agent) tried to submit an approval (only a person on a Trezor can) → stopped by permission scoping: caller_not_allowed: role 'agent' is not on the caller allowlist of POST /signatures · 0 CZK moved — refused: that role may not do it; nothing happened [caller_not_allowed]  | kind="stolen agent credentials" rule=caller_not_allowed principal=agent status=403 req=r5a58ad threat="PRIVILEGE ESCALATION" layer="permission scoping"
  2026-10-20T10:31:05.083Z 🛑 ATTACK  PAYMENT FRAUD (BEC) · Payment blocked: ACME s.r.o. · 48 900.00 CZK (invoice email from acme-cz.com) → stopped by executor facts + policy: F-DOMAIN: Sender domain acme-cz.com imitates vendor domain acme.cz · 48 900.00 CZK at stake, 0 CZK moved — …  | seq=41 subject=prp_3 kind="lookalike domain (BEC)" …
  ```

  Level tags: `🛑 ATTACK` hostile and stopped · `⛔ BLOCKED` refused, not necessarily hostile (a duplicate invoice; it
  still names layer and evidence) · `✋ HUMAN` waiting for a person / Trezor (`⚠ Linked to an attack` when the payment
  came from one) · `💸 PAID` · `✅ OK` · `•  INFO` · `💥 ERROR` the system failed (a 500, an order that did not reach
  the bank, a bank rejection: not attacks). The `key=value` tail: `seq=` audit entry, `subject=`, `kind=`, `rule=`,
  `principal=`, `status=`, `req=` one id per API request (grep it), `threat=`, `layer=`, `scene=` + `[demo replay]`
  for the seeded backdrop (everything after "ready on ..." is live). A 500 logs its traceback under `error_id=err_…`,
  also in the response `details`. IBANs are masked (`LT48 …1234`); signatures, callback codes, VCs and e-mail bodies
  are never logged. Env: `AIRGAP_LOG_FORMAT=text|json`, `AIRGAP_LOG_LEVEL=INFO|DEBUG|WARNING`.

**Explainability (responsible AI).** No LLM sits in the decision path: facts, Cedar policy and the signature checks
are deterministic, so every decision replays offline: `python -m tools.verify_audit <export.json>` re-runs `decide()`
at the logged policy hash (`policy sha256:d33008c4…`, shown on the cards whose entries include a decision). A card
without a decision (a refused signature, a fake attestation) says what the verifier does re-check for it: the
signatures, or the hash chain and witness checkpoints. The agent's own words ("CFO approved") are
logged as ignored hints, never as evidence.

**Requests refused at the door** (attack d: `caller_not_allowed`, an IBAN field in a request) write **no audit
entry**. That is deliberate: CONTRACTS §7.2 defines `iam_deny_mirror` as a mirror of an AWS IAM decision (`source`
simulate | boto3 | cloudtrail, role ARNs), not of the executor's own caller check, and a leaf per refused request would
let any credential holder grow the signed log at will. Instead the executor keeps them in a small in-memory ring
(`executor.oplog.recent()`), served read-only by the loopback stack at `/_local/recent-attacks` (`make local-stack`,
`make dev`; never on AWS, no contract change). The bank console, the attacker console and `make alerts` read it, so
locally they show these attacks too. On AWS (one ring per Lambda instance, no such route) they are CloudWatch lines;
the attacker console then explains the executor's own refusal response with the same `explain.refusal`.

### Tailing the log

```
make local-stack                      # the terminal IS the ops log (colour on a TTY, NO_COLOR=1 to turn it off)
make local-stack 2>&1 | grep --line-buffered ATTACK              # only the attacks
AIRGAP_LOG_FORMAT=json make -s local-stack | jq -R 'fromjson? | select(.level=="ATTACK") | {threat, title, layer, evidence}'
curl -s localhost:8000/_local/recent-attacks | jq .              # the refused-at-the-door ring
aws logs tail /aws/lambda/<executor function> --follow --filter-pattern ATTACK --profile hackathon
```

(`aws logs describe-log-groups --log-group-name-prefix /aws/lambda/airgap --profile hackathon` lists the executor and
tools log groups.)

### CloudWatch Logs Insights

Select the executor and the tools log groups, then:

```
fields @timestamp, @message
| filter @message like /ATTACK/
| sort @timestamp desc
```

Per threat class (text format):

```
fields @timestamp, @message
| filter @message like /ATTACK/
| parse @message /threat="(?<threat>[^"]+)"/
| stats count() by threat
```

Only the refused-at-the-door attempts: `| filter @message like /ATTACK/ and @message like /status=4/`. With
`AIRGAP_LOG_FORMAT=json` the fields are direct: `filter level = "ATTACK" | stats count() by threat, layer`.

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
| inbox | `.venv/bin/python -m infra.load_inbox --url $API` (ingest role) | PASS 8/8 | 5 s |
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
