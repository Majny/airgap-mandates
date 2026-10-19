"""Emulator screen oracle (S2): drive ethereum.sign_message on a trezor-user-env emulator page by page and capture,
for every page, the debuglink layout text AND the framebuffer PNG. Owner: WS-C.

Why both: debuglink reports the *intended* text, the PNG shows what the font actually draws. Non-ASCII renders as
boxes on the Safe 3 / Safe 5 while debuglink still reports the correct characters (docs/device/measurements.md).

Requires trezor-user-env with the emulator started with `save_screenshots: true` (see docs/device/emulator.md).
"""
from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass, field

CONTROLLER = os.environ.get("AIRGAP_TENV_URL", "ws://127.0.0.1:9001/")
MARK = "..."  # debuglink spells the page-break glyphs as "..." (end of page / start of next page)


@dataclass
class Page:
    title: str
    index: int
    count: int
    raw: str  # debuglink screen_content(), markers included
    png: bytes | None = None

    @property
    def lines(self) -> list[str]:
        """Screen lines with the page-break markers removed."""
        ls = self.raw.split("\n")
        if ls and ls[-1].endswith(MARK) and self.index < self.count - 1:
            ls[-1] = ls[-1][: -len(MARK)]
        if ls and ls[0].startswith(MARK) and self.index > 0:
            ls[0] = ls[0][len(MARK):]
        return ls


@dataclass
class Capture:
    address_page: Page | None
    pages: list[Page] = field(default_factory=list)
    address: str | None = None
    sig: str | None = None
    error: str | None = None


def tenv(*cmds: dict, url: str = CONTROLLER) -> list[dict]:
    import websocket

    ws = websocket.create_connection(url, timeout=300)
    try:
        ws.recv()  # hello
        out = []
        for i, cmd in enumerate(cmds):
            ws.send(json.dumps(dict(cmd, id=i)))
            while True:
                r = json.loads(ws.recv())
                if r.get("id") == i:
                    break
            if not r.get("success", False):
                raise RuntimeError(f"tenv {cmd['type']}: {r}")
            out.append(r)
        return out
    finally:
        ws.close()


def start_emulator(model: str = "T3B1", version: str = "2.12.5-arm",
                   mnemonic: str = "all all all all all all all all all all all all") -> None:
    """(Re)start a wiped emulator with a demo seed and screenshot capture on."""
    tenv({"type": "emulator-start", "model": model, "version": version, "wipe": True, "save_screenshots": True},
         {"type": "emulator-setup", "mnemonic": mnemonic, "pin": "", "passphrase_protection": False,
          "label": "AG DEMO EMU", "needs_backup": False})


def screenshot() -> bytes:
    return base64.b64decode(tenv({"type": "emulator-get-screenshot"})[0]["response"])


def capture(text: str | bytes, path: str = "m/44h/60h/0h/0/0", *, udp: str = "127.0.0.1:21324",
            hold_ms: int = 1500, confirm: bool = True, settle: float = 0.4) -> Capture:
    """Sign `text` on the emulator, walking every page with the right button; hold CONFIRM on the last page."""
    from trezorlib import ethereum, tools
    from trezorlib.debuglink import TrezorTestContext
    from trezorlib.transport.udp import UdpTransport

    data = text.encode("utf-8") if isinstance(text, str) else text
    ctx = TrezorTestContext(UdpTransport(udp), auto_interact=True)
    cap = Capture(address_page=None)

    def snap(lay) -> Page:
        time.sleep(settle)
        try:
            png = screenshot()
        except Exception:  # screenshots off: text-only oracle
            png = None
        return Page(lay.title(), lay.active_page(), lay.page_count(), lay.screen_content(), png)

    def flow():
        d = ctx.debug
        yield  # signing address
        cap.address_page = snap(d.read_layout(wait=True))
        d.press_right(wait=True)
        yield  # message pages
        lay = d.read_layout(wait=True)
        for _ in range(64):
            cap.pages.append(snap(lay))
            if lay.active_page() < lay.page_count() - 1:
                d.press_right(wait=True)
                lay = d.read_layout(wait=True)
                continue
            if confirm:
                d.press_right(hold_ms=hold_ms, wait=False)
            else:
                d.press_left(wait=False)
            break

    with ctx:
        ctx.set_input_flow(flow())
        try:
            r = ethereum.sign_message(ctx.get_session(), tools.parse_path(path), data)
            cap.address, cap.sig = r.address.lower(), "0x" + r.signature.hex()
        except Exception as e:
            cap.error = repr(e)
    return cap


def page_split(text: str, lines_per_page: int) -> list[list[str]]:
    ls = text.split("\n")
    return [ls[i : i + lines_per_page] for i in range(0, len(ls), lines_per_page)]


def png_equal(a: bytes, b: bytes) -> bool:
    """Pixel equality (PNG encoders may differ in metadata)."""
    if a == b:
        return True
    from io import BytesIO

    from PIL import Image, ImageChops

    ia, ib = Image.open(BytesIO(a)).convert("L"), Image.open(BytesIO(b)).convert("L")
    return ia.size == ib.size and ImageChops.difference(ia, ib).getbbox() is None
