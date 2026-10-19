# Demo camera rig (WS-C)

The approver's device is a **Trezor Safe 3** (T2B1, 128x64 mono OLED, two buttons, about 1.5 cm high). The
audience must be able to read the 16-18 character lines on the projector and see the hold on CONFIRM.

## Hardware
- A phone on a gooseneck or tripod arm, **directly above** the device (lens parallel to the screen, 8-12 cm away).
  Use 2x optical zoom if the phone has it, not digital. Lock exposure and focus on the OLED (tap and hold on iOS,
  "AE/AF lock"). OLED is self-lit: **reduce exposure** until the black background is black and the glyphs do not bloom.
- Device on a matte dark mat, taped down (orientation fixed), USB-C cable routed away from the buttons.
- The operator's hand comes in from below the frame; the right button (CONFIRM / next) stays visible.
- No glossy surface under a ceiling light (the OLED glass reflects); a small piece of black card as a hood works.

## Mirroring to the projector
- iPhone: wired USB-C/Lightning to HDMI adapter into the projector switch (preferred, no Wi-Fi dependency), or
  macOS QuickTime "New Movie Recording" with the iPhone as camera source over USB (the demo laptop shows it in a
  window next to the executor UI). Android: scrcpy over USB (`scrcpy --video-source=camera --camera-facing=back`).
- Not AirPlay or Wi-Fi casting: the venue Wi-Fi is not part of the demo path.

## Scene layout on the projector
- Left 2/3: the host UI (renderer preview of the exact challenge text, split into the device's 4-line pages).
- Right 1/3: the camera feed of the device. The narrator says "character for character" and points at line 1
  (`AG1/DEMO ...`) on both.
- R0 beat (S2): the camera stays on the dark device, which shows its homescreen: "there is nothing to approve".

## Operator script (Safe 3 button flow, measured at H0)
1. "Signing address 0x..." screen: RIGHT.
2. "Confirm message" pages: RIGHT advances one page (4 lines). The page dots top right show progress.
3. Last page only: **hold RIGHT (CONFIRM) for about 1 s** until the loader completes. A tap does not sign
   (measured: hold under 0.9 s does not confirm, 1.1 s does).
4. The device returns to its homescreen; the executor UI shows the receipt.

## Fallbacks
- Physical device not enumerating: close Trezor Suite (it holds the USB interface), re-plug, check the cable
  carries data (`.venv/bin/trezorctl list` must print `webusb:...`). No Bridge is needed.
- **Fallback kit (one switch):** `AIRGAP_TREZOR_PATH=udp:127.0.0.1:21324` moves the clerk onto the T3B1 emulator
  (path `m/44'/60'/0'/0/0`; treasury stays on `.../1`). Everything that signs prints
  `*** FALLBACK MODE: CLERK SIGNS ON THE EMULATOR (T3B1), NOT THE PHYSICAL DEVICE ***`, the emulator homescreen
  reads `EMULATOR`, enrolment marks it `device = EMULATOR`, and emulator signers auto-confirm only as a labelled
  "simulated human" (debuglink pages through at 1.2 s per page, then holds). The emulator screen goes on the
  projector from the trezor-user-env dashboard (http://127.0.0.1:9001). The `prod` profile refuses EMULATOR keys.
  Fallback clerk address `0x73d0385f4d8e00c5e6504c6030f47bf6212736a8` (demo seed), so it must be enrolled
  (`python -m tools.enroll clerk --transport udp:127.0.0.1:21324`) before the AWS demo can use it.
- Last resort: the pre-recorded video of the same beat (WS-F owns the fallback video).

## Rehearsal commands
```
tests/device/tenv.sh                                   # emulator up (treasury, and clerk in fallback)
.venv/bin/python -m host.signer info                   # which devices are connected, which mode
.venv/bin/python -m host.signer s1                     # S1 in-process: physical clerk holds twice (MANDATE, PAY)
AIRGAP_TREZOR_PATH=udp:127.0.0.1:21324 .venv/bin/python -m host.signer s1   # fallback: emulator only, auto
.venv/bin/python -m host.signer sign <NONCE> clerk --url $AIRGAP_EXECUTOR_URL  # one challenge on a live executor
```
The replay step of S1 re-sends the captured signature; the human is not asked to sign twice.

## Checklist (T-30 min)
- [ ] Auto-lock set to the maximum on the demo device (Settings -> Auto-lock). Measured at H0: a USB drop or
      auto-lock mid-flow blocks the host silently before the first prompt (the S1 rehearsal stalled ~3 min until
      the device was re-plugged and unlocked).
- [ ] Short USB-C data cable, firmly seated, strain-relieved with tape; no hub.
- [ ] Re-plug if in doubt, unlock (PIN), homescreen visible, then `python -m host.signer info` shows `GENUINE` before
      EACH beat.
- [ ] `trezorctl list` shows the device; Suite closed.
- [ ] Phone: Do Not Disturb, auto-lock off, exposure locked, zoom set, mirroring live on the projector.
- [ ] One dry run of S1 end to end, then wipe nothing (the demo seed stays).
