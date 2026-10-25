"""Unit tests for tp3.netclient."""

from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import pytest

from tp3.utils.codec import xor
from tp3.utils.netclient import connect, run_rounds, solve_round


def _make_token(plaintext: bytes, key: bytes) -> bytes:
    """Build a server-style token: base64(XOR(plaintext, key))."""
    return base64.b64encode(xor(plaintext, key))


# ---------------------------------------------------------------------------
# connect
# ---------------------------------------------------------------------------


@patch("tp3.utils.netclient._HAS_PWN", False)
@patch("tp3.utils.netclient.socket.create_connection")
def test_connect_uses_socket(mock_create):
    mock_sock = MagicMock()
    mock_create.return_value = mock_sock
    conn = connect("127.0.0.1", 9090)
    mock_create.assert_called_once_with(("127.0.0.1", 9090), timeout=8)
    assert conn is mock_sock


# ---------------------------------------------------------------------------
# solve_round (single-recv design)
# ---------------------------------------------------------------------------


def test_solve_round_sends_decoded_returns_none():
    """Token line → decode + send, no flag yet → None."""
    key = b"secret"
    plaintext = b"round1_answer"
    token = _make_token(plaintext, key)

    conn = MagicMock()
    with (
        patch("tp3.utils.netclient._recvline", return_value=token + b"\n"),
        patch("tp3.utils.netclient._sendline") as mock_send,
    ):
        result = solve_round(conn, key)
        assert result is None
        mock_send.assert_called_once()
        sent = mock_send.call_args[0][1]
        assert plaintext in sent


def test_solve_round_flag_in_line():
    conn = MagicMock()
    with patch("tp3.utils.netclient._recvline", return_value=b"Done ESGI{final_flag}\n"):
        assert solve_round(conn, b"key") == "ESGI{final_flag}"


def test_solve_round_no_token_returns_none():
    conn = MagicMock()
    with patch("tp3.utils.netclient._recvline", return_value=b"nothing useful\n"):
        assert solve_round(conn, b"key") is None


# ---------------------------------------------------------------------------
# run_rounds
# ---------------------------------------------------------------------------


@patch("tp3.utils.netclient.connect")
@patch("tp3.utils.netclient.solve_round")
def test_run_rounds_returns_flag(mock_solve, mock_connect):
    mock_conn = MagicMock()
    mock_connect.return_value = mock_conn
    mock_solve.side_effect = [None, None, "ESGI{the_final}"]

    result = run_rounds("localhost", 9090, b"k")
    assert result == "ESGI{the_final}"
    assert mock_solve.call_count == 3
    mock_conn.close.assert_called_once()


@patch("tp3.utils.netclient.connect")
@patch("tp3.utils.netclient.solve_round")
def test_run_rounds_raises_when_no_flag(mock_solve, mock_connect):
    mock_connect.return_value = MagicMock()
    mock_solve.return_value = None

    with pytest.raises(RuntimeError, match="not received"):
        run_rounds("localhost", 9090, b"k", max_rounds=3)
