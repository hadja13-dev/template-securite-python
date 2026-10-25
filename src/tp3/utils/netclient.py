"""
netclient.py — TCP phase: connect, timed decode rounds, retrieve final flag.

Protocol (confirmed against server.py):
  1. One intro line (instructions, contains spaces)
  2. ROUNDS=3 lines of base64(xor(token, key))
  3. Final line: OK ESGI{...}
"""

from __future__ import annotations

import re
import socket

from tp3.utils.codec import decode_token

try:
    from pwn import remote as pwn_remote  # type: ignore

    _HAS_PWN = True
except ImportError:
    _HAS_PWN = False


SOCKET_TIMEOUT = 8

# Pure base64 line (no spaces / words) — avoids matching the intro sentence
TOKEN_RE = re.compile(r"^([A-Za-z0-9+/]{16,}={0,2})$")
FLAG_RE = re.compile(r"(ESGI\{[^}]+\})")
ERROR_RE = re.compile(r"\b(WRONG|TIMEOUT)\b", re.IGNORECASE)


def connect(host: str, port: int):
    """Open a TCP connection (pwntools remote or stdlib socket)."""
    if _HAS_PWN:
        return pwn_remote(host, port, timeout=SOCKET_TIMEOUT)
    sock = socket.create_connection((host, port), timeout=SOCKET_TIMEOUT)
    sock.settimeout(SOCKET_TIMEOUT)
    return sock


def _recvline(conn) -> bytes:
    """Read one newline-terminated line."""
    if _HAS_PWN and hasattr(conn, "recvline"):
        return conn.recvline(timeout=SOCKET_TIMEOUT)

    buf = b""
    while True:
        chunk = conn.recv(1)
        if not chunk:
            break
        buf += chunk
        if chunk == b"\n":
            break
        if len(buf) > 8192:
            break
    return buf


def _sendline(conn, data: bytes) -> None:
    """Send data followed by newline."""
    payload = data if data.endswith(b"\n") else data + b"\n"
    if _HAS_PWN and hasattr(conn, "sendline"):
        conn.sendline(data.rstrip(b"\n"))
    elif _HAS_PWN and hasattr(conn, "send"):
        conn.send(payload)
    else:
        conn.sendall(payload)


def _close(conn) -> None:
    if hasattr(conn, "close"):
        conn.close()


def solve_round(conn, key: bytes) -> str | None:
    """One receive → decide: flag / error / token / ignore.

    - Flag line   → return the flag
    - WRONG/TIMEOUT → raise
    - Pure base64 line → decode + send answer, return None
    - Anything else (intro, empty…) → ignore, return None
    """
    line = _recvline(conn)
    if not line:
        return None

    text = line.decode("utf-8", errors="replace").strip()

    # Final flag
    m = FLAG_RE.search(text)
    if m:
        return m.group(1)

    # Server error
    if ERROR_RE.search(text):
        raise RuntimeError(f"Server rejected round: {text}")

    # Only accept a pure base64 token (no spaces / words)
    token_match = TOKEN_RE.match(text)
    if not token_match:
        return None  # intro line or garbage → skip

    token = token_match.group(1).encode("ascii")
    plaintext = decode_token(token, key)
    _sendline(conn, plaintext)
    return None


def run_rounds(host: str, port: int, key: bytes, max_rounds: int = 30) -> str:
    """Connect and solve rounds until the final flag appears."""
    conn = connect(host, port)
    try:
        for _ in range(max_rounds):
            flag = solve_round(conn, key)
            if flag is not None:
                return flag
        raise RuntimeError(f"Final flag not received after {max_rounds} rounds")
    finally:
        _close(conn)
