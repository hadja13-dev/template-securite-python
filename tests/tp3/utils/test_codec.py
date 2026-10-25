"""Unit tests for tp3.codec — pure decoding primitives."""

from __future__ import annotations

import base64

import pytest

from tp3.utils.codec import b64_decode, decode_token, xor


# ---------------------------------------------------------------------------
# xor
# ---------------------------------------------------------------------------


def test_xor_roundtrip():
    data = b"Hello, ESGI!"
    key = b"secret"
    cipher = xor(data, key)
    assert cipher != data
    plain = xor(cipher, key)
    assert plain == data


def test_xor_empty_key_raises():
    with pytest.raises(ValueError, match="empty"):
        xor(b"data", b"")


def test_xor_key_longer_than_data():
    data = b"ab"
    key = b"longkey"
    result = xor(data, key)
    assert len(result) == 2
    assert result == bytes([ord("a") ^ ord("l"), ord("b") ^ ord("o")])


def test_xor_repeating_key():
    data = b"ABCDEFGH"
    key = b"XY"
    expected = bytes(
        [
            ord("A") ^ ord("X"),
            ord("B") ^ ord("Y"),
            ord("C") ^ ord("X"),
            ord("D") ^ ord("Y"),
            ord("E") ^ ord("X"),
            ord("F") ^ ord("Y"),
            ord("G") ^ ord("X"),
            ord("H") ^ ord("Y"),
        ]
    )
    assert xor(data, key) == expected


# ---------------------------------------------------------------------------
# b64_decode
# ---------------------------------------------------------------------------


def test_b64_decode_bytes():
    raw = b"hello"
    token = base64.b64encode(raw)
    assert b64_decode(token) == raw


def test_b64_decode_str():
    raw = b"hello"
    token = base64.b64encode(raw).decode("ascii")
    assert b64_decode(token) == raw


def test_b64_decode_missing_padding():
    # "hello" → "aGVsbG8=" ; strip the padding
    token = b"aGVsbG8"
    assert b64_decode(token) == b"hello"


def test_b64_decode_invalid_raises():
    with pytest.raises(ValueError):
        b64_decode(b"!!!not-base64!!!")


# ---------------------------------------------------------------------------
# decode_token
# ---------------------------------------------------------------------------


def test_decode_token_roundtrip():
    plaintext = b"ESGI{test_flag_123}"
    key = b"mykey42"
    # Simulate server: XOR then base64
    cipher = xor(plaintext, key)
    token = base64.b64encode(cipher)
    assert decode_token(token, key) == plaintext


def test_decode_token_with_str_key_bytes():
    plaintext = b"flag"
    key = b"k"
    token = base64.b64encode(xor(plaintext, key))
    assert decode_token(token, key) == plaintext
