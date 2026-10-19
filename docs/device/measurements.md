# H0 device measurements (WS-C)

**Device change.** The physical approver device is a **Trezor Safe 3** (`internal_model` T2B1), not a Safe 5. This
file records what its `ethereum.sign_message` screen does, so the render profile can follow it.

| | Physical | Emulator |
|---|---|---|
| Model | Safe 3, T2B1 | Safe 3, T3B1 (tenv has no T2B1 build; T3B1 is the newer Safe 3 revision, same Caesar UI) |
| Firmware | 2.12.0, vendor `Trezor`, revision `4d89c11d…` | 2.12.5-arm, vendor `EMULATOR` |
| Transport | WebUSB via libusb (`webusb:002:1`), Codec v1 (not THP), no Bridge needed | UDP `127.0.0.1:21324`, debuglink 21325 |
| Security | bootloader locked, PIN on, **passphrase protection on**, `optiga_sec 0`, auto-lock 10 min | no PIN, no passphrase |

Legend: [E] measured on the emulator with debuglink + framebuffer PNG; [P] confirmed on the physical device
(photo in `photos/`); [P pending] not yet confirmed physically.

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

## Consequences for the render profile
- `safe5-mono-18x7` texts are **not safe on the Safe 3**: any line of 17-18 chars at line 4k or 4k+1 reflows across
  the page break. With today's goldens, PAY, ENROLL and CHG_REJECT display exactly; **CHG** (`OLD ..5399 2024-03` at
  line 4, `NEW CZ.. ` at line 5, `ROLE TREASURY 2/2` at line 12) and **MANDATE** (`P 1f3a…` at line 13) reflow
  (`tests/device/test_screens.py`, xfail until the profile lands).
- 14 lines = 4 pages on the Safe 3. The "5-page trap" does not exist here (confirm only on the last page), but we
  keep a hard cap anyway.
- Proposed profile and trade-offs: see the WS-C report / `docs/CONTRACTS.md` proposal (`safe3-mono-16x4`).

## Physical device
- [P pending] Authenticity proof (Optiga chain) and challenge-keyed firmware hash vs the official 2.12.0 image.
- [P pending] Photos of the same screens (PAY golden 4 pages, 20 numbered lines, diacritics), hold timing,
  host timeout.
- [P pending] EIP-191 signature → `eth_account` recovery round trip.

## Reproduce
```
tests/device/tenv.sh T3B1 2.12.5-arm      # trezor-user-env + Safe 3 emulator on udp:127.0.0.1:21324
AIRGAP_TREZOR_PATH=udp:127.0.0.1:21324 .venv/bin/pytest -q tests/device
```
