"""

Provides XOR (symmetric), base64 decode and the combined token decoder
used by the network phase.
"""

from __future__ import annotations

import base64


def xor(data: bytes, key: bytes) -> bytes:
    """Apply byte-wise XOR with a repeating key.

    The same function both encrypts and decrypts because XOR is its own
    inverse.  The key is cycled with ``i % len(key)``.

    Args:
        data: Input bytes to (de)cipher.
        key:  Non-empty key bytes.

    Returns:
        Resulting bytes (same length as ``data``).

    Raises:
        ValueError: if ``key`` is empty.
    """
    if not key:
        raise ValueError("XOR key must not be empty")
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def b64_decode(token: bytes | str) -> bytes:
    """Typed wrapper around ``base64.b64decode``.

    Accepts either a ``str`` or ``bytes`` token.  If a string is given it
    is first encoded to ASCII.  Standard base64 padding (``=``) is
    handled by the underlying library; missing padding is tolerated by
    adding it when necessary.

    Args:
        token: Base64-encoded payload (str or bytes).

    Returns:
        Raw decoded bytes.

    Raises:
        ValueError / binascii.Error: on malformed base64.
    """
    if isinstance(token, str):
        token = token.encode("ascii")
    # Tolerate missing padding (common in challenge tokens)
    missing = len(token) % 4
    if missing:
        token += b"=" * (4 - missing)
    return base64.b64decode(token)


def decode_token(token: bytes, key: bytes) -> bytes:
    """Decode a network token: base64 first, then XOR with the key.

    Order confirmed against the local target: the server sends
    base64(XOR(plaintext, key)).  Therefore we reverse the operations:
    b64_decode → xor.

    Args:
        token: Base64-encoded ciphertext (bytes).
        key:   XOR key (bytes).

    Returns:
        Plaintext bytes (expected to be UTF-8 text).
    """
    raw = b64_decode(token)
    return xor(raw, key)
