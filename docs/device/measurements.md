# H0 device measurements (WS-C)

**Device change.** The physical approver device is a **Trezor Safe 3** (`internal_model` T2B1), not a Safe 5. This
file records what its `ethereum.sign_message` screen does, so the render profile can follow it.

| | Physical | Emulator |
|---|---|---|
| Model | Safe 3, T2B1 | Safe 3, T3B1 (tenv has no T2B1 build; T3B1 is the newer Safe 3 revision, same Caesar UI) |
| Firmware | 2.12.0, vendor `Trezor`, revision `4d89c11d…` | 2.12.5-arm, vendor `EMULATOR` |
| Transport | WebUSB via libusb (`webusb:002:1`), Codec v1 (not THP), no Bridge needed | UDP `127.0.0.1:21324`, debuglink 21325 |
| Security | bootloader locked, PIN on, **passphrase protection on**, `optiga_sec 0`, auto-lock 10 min | no PIN, no passphrase |

Legend: [E] measured on the emulator with debuglink + framebuffer PNG; [P] confirmed on the physical device;
[P pending] not yet confirmed physically.

## Message screen (`ethereum.sign_message`, "Confirm message")

| Fact | Value | Status | Evidence |
|---|---|---|---|
| Columns per line | **18**, monospace: `W`, `i`, `M`, `0`, `O`, `1`, `l` all take one cell; the device auto-wraps at 18 with no hyphen | [E] | `h0/emu_wrap25_01.png`, `h0/emu_mixed_01.png` |
| Lines per page | **4** (128x64 OLED: title bar + 4 text lines + button bar) | [E] | `h0/emu_pay_golden_*.png` |
| LF | honoured; empty lines are shown as empty lines; leading/trailing spaces kept | [E] | `h0/emu_blank_*.png` |
| Page-break markers | page end: a "⇣" glyph after the last line; next page start: a "⇒" glyph before the first line. Debuglink spells both as `...` | [E] | `h0/emu_lines20_02.png`, `_03.png` |
| Columns the markers take | **2 each**. A page-end line and a page-start line hold at most **16** characters. An 18-char line there is split: 16 chars, marker, then the remaining 2 on the next page after the "⇒" | [E] | `lines20`: `04ABCDEFGHIJKLMN⇣` / `⇒ OP` |
| Last line of the last page | no end marker, full 18 | [E] | `h0/emu_pay_golden_04.png` (`H 9b1e…` = 18) |
| Navigation | RIGHT = next page (`v`), LEFT = back (`^`; on page 1 `<` = cancel). **CONFIRM exists only on the last page**: the human has to page through everything | [E] | all `h0/` shots |
| More than N pages | **no truncation and no preview mode** (unlike the Safe 5's ">5 pages" preview): 1300 chars = 24 pages, all shown, confirm on page 24 | [E] | `h0/emu_long1300_02.png`, `_25.png` |
| Non-ASCII | **renders as boxes** while debuglink reports the correct characters (the diacritics trap exists on the Safe 3 too) | [E] | `h0/emu_diacritics_01.png` |
| Non-UTF-8 bytes | shown as `hex(fffe204142)` | [E] | `h0/emu_nonutf8_01.png` |
| Hold to confirm | **about 1.0 s**: a hold under 0.9 s does not sign, 1.1 s does. A tap does nothing | [E] | debuglink `hold_ms` sweep |
| Timeout | the device waits indefinitely (until auto-lock, 10 min). The host sends `Cancel` after its own timeout; the device goes back to the homescreen at once; trezorlib raises `Cancelled` | [E] | `host/signer.py` timeout test |
| Before the message | a "Signing address 0x…" screen (the approver sees which identity signs), RIGHT to continue | [E] | `h0/emu_pay_golden_00.png` |
| Title bar | "CONFIRM MESSAGE" with page dots; long titles are clipped | [E] | |

## Device evidence (Q&A slide)
The approver key lives on a **genuine Trezor Safe 3**: its Optiga authenticity proof verifies against the Trezor
production root ("Trezor Company / Trezor Safe 3", leaf CN `T2B1 Trezor Safe 3`, chain sha256 `7d363795…`), and its
challenge-keyed firmware hash equals the hash computed from the official `trezor-t2b1-2.12.0.bin` (blake2s keyed with
our random challenge over the 13x128 KiB firmware area), with the bootloader locked. Five EIP-191 signatures made on it
(4-page PAY, 7-page test text, diacritics, ENROLL, one more) each recover with stock `eth_account` to the enrolled
address `0x6a7438740dc3289067175efda02459170dc1317d`. A host timeout cancels cleanly (Cancel at 20.0 s, device
back to its homescreen). Czech diacritics render wrongly on the hardware too, which is why the device only ever gets
ASCII and the golden tests compare screenshots, not debuglink text. Limit: attestation proves the genuine device at
enrolment, not that later signatures came from it (the seed could be restored elsewhere; ARCHITECTURE §3.3).
Records: `enroll_clerk_physical.json` (GENUINE), `enroll_treasury_emulator.json` (EMULATOR, T3B1).

## Physical device results
| Check | Result | Status |
|---|---|---|
| Authenticity (`device.authenticate` + chain verify) | verified; on-device allow; 8.9 s | [P] |
| Firmware hash vs official 2.12.0 image | match (blake2s keyed, 13x128 KiB area, 0xFF pad) | [P] |
| EIP-191 → `eth_account` recovery | 5/5 match; human time per sign 11-24 s (PAY 4 pages: 19.5 s; 7 pages: 24 s) | [P] |
| Paging, 4 lines, CONFIRM only on the last page | as on the emulator (human operated the same flows) | [P] |
| Diacritics | rendered wrongly (operator report) | [P] |
| Host timeout | `Cancelled` at 20.0 s, device not busy and still unlocked afterwards | [P] |
| Enrolment ceremony (`tools/enroll.py clerk`) | GENUINE, `fw_official_match: true` | [P] |
| Photos | pending: operator to copy into `photos/` | [P pending] |
| Hold under 1 s does not sign | pending operator answer (emulator: yes, see above) | [P pending] |
| USB autodetect | with the emulator running, trezorlib enumerates UDP first; the signer's `usb` therefore matches `webusb` only | [P] |

## Render profile (decided after H0)
- `safe5-mono-18x7` texts are **not safe on the Safe 3**: an 18-char line at line 4k or 4k+1 reflows across the page
  break (the old CHG and MANDATE goldens did).
- Default profile is now **`safe3-mono-16x4`**: 16 columns (title line 18), 4-line device pages, at most 14 lines
  (4 pages), H/P lines 14 hex, deterministic short forms (`ROLE TREAS`, `PAYEES n Vv`, `OLD ..xxxx YY-MM`,
  `SIGNER ROLE BASIS`, `NEW IBAN` label line for long IBANs). No line can ever reflow. CONTRACTS §5.
- `tests/device/test_screens.py` checks every fixture challenge on the emulator: debuglink text paged every 4 lines
  with no reflow, plus pixel-equal PNG goldens in `emulator/`.

## Reproduce
```
tests/device/tenv.sh T3B1 2.12.5-arm      # trezor-user-env + Safe 3 emulator on udp:127.0.0.1:21324
AIRGAP_TREZOR_PATH=udp:127.0.0.1:21324 .venv/bin/pytest -q tests/device
.venv/bin/python -m tools.enroll clerk --official-fw .local/fw/trezor-t2b1-2.12.0.bin   # physical, USB
```
