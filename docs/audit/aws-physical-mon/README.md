# AWS + physical Safe 3 evidence bundle (Mon 2026-10-19)

2026-10-19, git rev `fcd98c6` (host side; executor deployed from main `c60b6ae`), AWS eu-central-1 regional API,
sealed read-only as `airgap-auditor` with `python -m tools.demo_bundle --from-aws <api> --out docs/audit/aws-physical-mon`:
**verifies green** (51 leaves, 7 checkpoints, log + W1 cosigned). Clerk device **GENUINE**: physical Trezor Safe 3 (T2B1,
fw 2.12.0, Optiga chain verified, firmware hash = official 2.12.0 image; `docs/device/enroll_clerk_physical.json`).

Demo beat S1 driven by `python -m host.signer s1 --url <api>` (run log: `docs/device/s1_aws_device_take2.log`):

| seq | leaf | signer |
|---|---|---|
| 0 | `enroll` clerk `0x6a7438740dc3289067175efda02459170dc1317d`, device GENUINE | physical Safe 3 |
| 1 | `enroll` treasury `0xfa01a39f8abaeb660c3137f14a310d0b414b2a15`, device EMULATOR | T3B1 emulator |
| 2 | `enroll` clerk `0x73d0385f4d8e00c5e6504c6030f47bf6212736a8`, EMULATOR, inactive fallback | T3B1 emulator |
| 21-22 | mandate signed 1/2 (human held on the device) | physical Safe 3 |
| 24-25 | mandate signed 2/2 -> ACTIVE | T3B1 emulator, auto-confirm (simulated human) |
| 46-48 | PAY 125000.50 CZK step-up exact-signed -> execution `tx_2eb98a78b7a2d1b9` -> rail | physical Safe 3 |
| 49 | replay of the same signature refused `nonce_reused` (`accepted: false`) | - |

Files: `bundle.json` (leaves, checkpoints, policies, approvers), `checkpoint.txt`, `receipt.json` (inclusion proof for
the PAY execution), `trust-keys.json` (log + W1 verifier keys pinned from KMS).

Honest notes:
- Leaves 11-12 enrol WS-E's two **software** test keys (labels say "software key, aws e2e") left by `reset_state`; leaf 11
  carries `device: GENUINE` although it is a software key (seeding default in `infra/aws_e2e.py`, reported to WS-E).
  They sign nothing in this run.
- The treasury is an emulator by design (demo profile); `prod` would refuse it.
- This is not the stage bundle: `docs/audit/demo` is re-sealed Tue after the 06:00 policy freeze.
