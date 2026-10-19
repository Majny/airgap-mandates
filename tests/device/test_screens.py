"""Emulator screen oracle (S2): render() == debuglink screen_content(), screenshot diff vs docs/device/emulator/*.png.

Runs only with a trezor-user-env emulator (AIRGAP_TREZOR_PATH=udp:...). Owner: WS-C.
AIRGAP_UPDATE_GOLDENS=1 (re)writes the PNG goldens instead of comparing.
"""
import json
import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("AIRGAP_TREZOR_PATH"), reason="needs trezor-user-env emulator")

ROOT = Path(__file__).resolve().parents[2]
GOLDEN_DIR = ROOT / "docs" / "device" / "emulator"
FIXTURES = ROOT / "contracts" / "fixtures" / "challenges_get"
UPDATE = os.environ.get("AIRGAP_UPDATE_GOLDENS") == "1"
# Safe 3 (T2B1/T3B1) message screen, measured at H0: 4 lines x 18 columns per page.
LINES_PER_PAGE = int(os.environ.get("AIRGAP_DEVICE_LINES_PER_PAGE", "4"))


def _udp() -> str:
    return os.environ["AIRGAP_TREZOR_PATH"].removeprefix("udp:")


def _fixture_texts() -> dict[str, str]:
    return {p.stem: json.loads(p.read_text())["response"]["text"] for p in sorted(FIXTURES.glob("*.json"))}


@pytest.fixture(scope="module")
def oracle():
    from tests.device import oracle as o

    o.start_emulator()
    return o


@pytest.mark.parametrize("name", sorted(_fixture_texts()))
def test_goldens_match_emulator_screen(oracle, name):
    text = _fixture_texts()[name]
    cap = oracle.capture(text, udp=_udp())
    assert cap.error is None, cap.error
    from executor.sig import verify_eip191

    assert verify_eip191(text, cap.sig) == cap.address
    # Text oracle: the device shows exactly our lines, broken every LINES_PER_PAGE lines, with no reflow.
    assert [p.lines for p in cap.pages] == oracle.page_split(text, LINES_PER_PAGE)
    assert all(p.title == "Confirm message" for p in cap.pages)
    # Pixel oracle.
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    for p in cap.pages:
        assert p.png, "emulator screenshots are off (start it with save_screenshots)"
        golden = GOLDEN_DIR / f"{name}_{p.index + 1}of{p.count}.png"
        if UPDATE or not golden.exists():
            golden.write_bytes(p.png)
        else:
            assert oracle.png_equal(p.png, golden.read_bytes()), f"screen differs from {golden.name}"


def test_diacritics_trap(oracle):
    """debuglink reports the diacritics correctly while the font draws boxes: text-only goldens would pass."""
    ascii_cap = oracle.capture("AG1/DEMO\nPRILIS", udp=_udp())
    utf_cap = oracle.capture("AG1/DEMO\nPŘÍLIŠ", udp=_udp())
    assert utf_cap.pages[0].lines == ["AG1/DEMO", "PŘÍLIŠ"]  # debuglink "looks right"
    assert not oracle.png_equal(ascii_cap.pages[0].png, utf_cap.pages[0].png)
    from executor import render

    with pytest.raises(render.RenderError):
        render.check_text("AG1/DEMO\nPŘÍLIŠ")


def test_long_line_reflows_at_page_break(oracle):
    """An 18-char line at a page break is split by the marker glyph: why break lines must be <= 16 on the Safe 3."""
    text = "\n".join(f"{i:02d}ABCDEFGHIJKLMNOP" for i in range(1, 6))
    cap = oracle.capture(text, udp=_udp())
    assert [p.lines for p in cap.pages] != oracle.page_split(text, LINES_PER_PAGE)
