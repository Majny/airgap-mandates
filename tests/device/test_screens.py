"""Emulator screen oracle (S2): render() == debuglink screen_content(), screenshot diff vs docs/device/*.png.

Runs only with a trezor-user-env emulator (AIRGAP_TREZOR_PATH=udp:...). Owner: WS-C.
"""
import os

import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("AIRGAP_TREZOR_PATH"), reason="needs trezor-user-env emulator")


def test_goldens_match_emulator_screen():
    pytest.skip("TODO WS-C (H0)")
