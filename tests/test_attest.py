"""S4 supplier attestation (SD-JWT VC + KB-JWT) tests (CONTRACTS.md v2 §11, §8.2). Owner: WS-D."""
import pytest


def test_s4_one_vc_insufficient():
    pytest.skip("TODO WS-D")


def test_s4_same_class_twice_insufficient():
    pytest.skip("TODO WS-D")


def test_s4_kb_jwt_wrong_nonce_or_aud():
    pytest.skip("TODO WS-D")


def test_s4_kb_jwt_stale():
    pytest.skip("TODO WS-D")


def test_s4_issuer_not_pinned():
    pytest.skip("TODO WS-D")


def test_s4_disclosed_iban_must_match_change():
    pytest.skip("TODO WS-D")
