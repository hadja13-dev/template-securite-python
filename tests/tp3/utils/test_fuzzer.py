"""Unit tests for tp3.fuzzer."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from tp3.utils.fuzzer import check_path, find_hidden_endpoint, load_wordlist

# ---------------------------------------------------------------------------
# load_wordlist
# ---------------------------------------------------------------------------


def test_load_wordlist_reads_packaged_file(tmp_path: Path):
    wl = tmp_path / "wordlist.txt"
    wl.write_text("# comment\nadmin\n\nsecret\n", encoding="utf-8")
    words = load_wordlist(wl)
    assert words == ["admin", "secret"]


def test_load_wordlist_missing_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_wordlist(tmp_path / "does_not_exist.txt")


# ---------------------------------------------------------------------------
# check_path
# ---------------------------------------------------------------------------


@patch("tp3.utils.fuzzer.requests.Session")
def test_check_path_200(mock_session_cls):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_sess = MagicMock()
    mock_sess.get.return_value = mock_resp
    mock_session_cls.return_value = mock_sess

    assert check_path("http://localhost:8080", "admin") is True
    mock_sess.get.assert_called_once()


@patch("tp3.utils.fuzzer.requests.Session")
def test_check_path_404(mock_session_cls):
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_sess = MagicMock()
    mock_sess.get.return_value = mock_resp
    mock_session_cls.return_value = mock_sess

    assert check_path("http://localhost:8080", "missing") is False


@patch("tp3.utils.fuzzer.requests.Session")
def test_check_path_timeout(mock_session_cls):
    mock_sess = MagicMock()
    mock_sess.get.side_effect = requests.Timeout
    mock_session_cls.return_value = mock_sess

    assert check_path("http://localhost:8080", "slow") is False


# ---------------------------------------------------------------------------
# find_hidden_endpoint
# ---------------------------------------------------------------------------


@patch("tp3.utils.fuzzer.check_path")
def test_find_hidden_endpoint_returns_first_hit(mock_check):
    mock_check.side_effect = [False, False, True, False]
    words = ["a", "b", "secret", "c"]
    result = find_hidden_endpoint("http://localhost:8080", words)
    assert result == "secret"
    assert mock_check.call_count == 3


@patch("tp3.utils.fuzzer.check_path")
def test_find_hidden_endpoint_none(mock_check):
    mock_check.return_value = False
    result = find_hidden_endpoint("http://localhost:8080", ["x", "y"])
    assert result is None
