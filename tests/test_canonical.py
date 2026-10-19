"""canonical_json == RFC 8785 JCS for our domain (CONTRACTS.md v2 §7.1, C-19)."""
import pytest

from executor.canonical import canonical_json, sha256_hex

# (input, expected JCS bytes). Vectors restricted to our domain: ints, strings, bools, null, ASCII keys.
JCS_VECTORS = [
    ({"b": 2, "a": 1}, b'{"a":1,"b":2}'),
    ({"a": [3, {"z": None, "y": True}], "B": "x"}, b'{"B":"x","a":[3,{"y":true,"z":null}]}'),
    ({"s": "€\n\t\"\\/"}, '{"s":"€\\n\\t\\"\\\\/"}'.encode()),
    ({"c": "\u0001\u001f\u007f"}, b'{"c":"\\u0001\\u001f\x7f"}'),
    ([], b"[]"),
    ({}, b"{}"),
    ({"n": -9007199254740991, "m": 0}, b'{"m":0,"n":-9007199254740991}'),
    ({"key_10": 1, "key_2": 2, "Key": 3}, b'{"Key":3,"key_10":1,"key_2":2}'),
]


@pytest.mark.parametrize("obj,expected", JCS_VECTORS)
def test_jcs_vectors(obj, expected):
    assert canonical_json(obj) == expected


@pytest.mark.parametrize("bad", [1.0, {"a": 0.5}, [float("nan")], {1: "x"}])
def test_floats_and_non_string_keys_rejected(bad):
    with pytest.raises((TypeError, ValueError)):
        canonical_json(bad)


def test_sha256_hex():
    assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
