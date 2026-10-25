"""
netclient.py — TCP phase: connect, timed decode rounds, retrieve final flag.

Protocol hypothesis (to be confirmed against the live target):
  - server speaks line-oriented messages terminated by ``\\n``
  - each round consists of one line containing a base64 token
  - after the last successful answer the server sends a line with the flag
"""

from __future__ import annotations

import re
import socket
from typing import Optional

from tp3.utils.codec import decode_token

# Prefer pwntools when available, fall back to stdlib socket
try:
    from pwn import remote as pwn_remote  # type: ignore

    _HAS_PWN = True
except ImportError:
    _HAS_PWN = False


# Generous socket timeout (how long we wait for data).
# The actual answer must still be sent well under 5 s; decoding is µs.
SOCKET_TIMEOUT = 8

# Hypothesis: token is base64-looking and reasonably long.
# Fragile if the prompt itself contains long alphanum strings — refine
# after observing the real server output.
TOKEN_RE = re.compile(r"([A-Za-z0-9+/]{16,}={0,2})")
FLAG_RE = re.compile(r"(ESGI\{[^}]+\})")


def connect(host: str, port: int):
    """Open a TCP connection to the challenge service.

    Uses pwntools ``remote`` when available, otherwise a plain
    ``socket.create_connection``.

    Args:
        host: Target hostname or IP.
        port: Target TCP port.

    Returns:
        A connection object (pwntools tube or stdlib socket).
    """
    if _HAS_PWN:
        return pwn_remote(host, port, timeout=SOCKET_TIMEOUT)
    sock = socket.create_connection((host, port), timeout=SOCKET_TIMEOUT)
    sock.settimeout(SOCKET_TIMEOUT)
    return sock


def _recvline(conn) -> bytes:
    """Read one newline-terminated line.

    This is far more robust than a fixed-size ``recv`` because TCP is a
    stream: a single ``recv(4096)`` may return a partial token or several
    messages glued together.  Line-oriented reading matches the most
    common challenge protocol.
    """
    if _HAS_PWN and hasattr(conn, "recvline"):
        return conn.recvline(timeout=SOCKET_TIMEOUT)

    # stdlib socket: accumulate until \\n
    buf = b""
    while True:
        chunk = conn.recv(1)
        if not chunk:
            break
        buf += chunk
        if chunk == b"\n":
            break
        if len(buf) > 8192:  # safety
            break
    return buf


def _sendline(conn, data: bytes) -> None:
    """Send *data* followed by a newline."""
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


def solve_round(conn, key: bytes) -> Optional[str]:
    """Handle one challenge round (single receive point).

    Protocol per round:
      1. Receive one line (token or final flag).
      2. If the line contains the flag → return it.
      3. Otherwise extract the token, decode, send the answer.
      4. Return None so the caller loops for the next line.

    Having only **one** receive per call avoids the classic
    desynchronisation where a second recv consumes the next token.

    Args:
        conn: Active connection.
        key:  XOR key from the web phase.

    Returns:
        The final flag if present on this line, else ``None``.
    """
    line = _recvline(conn)
    if not line:
        return None

    text = line.decode("utf-8", errors="replace").strip()

    # Flag may arrive instead of a token
    m = FLAG_RE.search(text)
    if m:
        return m.group(1)

    token_match = TOKEN_RE.search(text)
    if not token_match:
        return None

    token = token_match.group(1).encode("ascii")
    plaintext = decode_token(token, key)
    _sendline(conn, plaintext)
    return None


def run_rounds(host: str, port: int, key: bytes, max_rounds: int = 30) -> str:
    """Connect and solve rounds until the final flag is obtained.

    Args:
        host:       Target host.
        port:       Target port.
        key:        XOR key (bytes).
        max_rounds: Safety limit.

    Returns:
        The final flag string (``ESGI{...}``).

    Raises:
        RuntimeError: if the flag is not received within *max_rounds*.
    """
    conn = connect(host, port)
    try:
        for _ in range(max_rounds):
            flag = solve_round(conn, key)
            if flag is not None:
                return flag
        raise RuntimeError(f"Final flag not received after {max_rounds} rounds")
    finally:
        _close(conn)
