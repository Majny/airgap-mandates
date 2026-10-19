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
- Still failing: switch the clerk to the emulator (`AIRGAP_TREZOR_PATH=udp:127.0.0.1:21324`); the treasury
  emulator screen goes on the projector via the trezor-user-env dashboard (http://127.0.0.1:9001), labelled EMULATOR.
- Last resort: the pre-recorded video of the same beat (WS-F owns the fallback video).

## Checklist (T-30 min)
- [ ] Device charged/plugged, unlocked (PIN), on the homescreen; auto-lock is 10 min, so unlock again just before.
- [ ] `trezorctl list` shows the device; Suite closed.
- [ ] Phone: Do Not Disturb, auto-lock off, exposure locked, zoom set, mirroring live on the projector.
- [ ] One dry run of S1 end to end, then wipe nothing (the demo seed stays).
