"""
fuzzer.py — discovery of the hidden web endpoint.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional
from urllib.parse import urljoin

import requests

DEFAULT_WORDLIST = Path(__file__).parent / "wordlist.txt"
TIMEOUT = 5
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def load_wordlist(path: Path = DEFAULT_WORDLIST) -> List[str]:
    """Load the embedded wordlist.

    Always open relative to the package (``Path(__file__).parent``), never
    the current working directory.

    Args:
        path: Path to the wordlist file. Defaults to the packaged one.

    Returns:
        List of non-empty, non-comment lines.
    """
    if not path.exists():
        raise FileNotFoundError(f"Wordlist not found: {path}")
    words: List[str] = []
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = line.strip()
            if w and not w.startswith("#"):
                words.append(w)
    return words


def check_path(base_url: str, path: str, session: Optional[requests.Session] = None) -> bool:
    """Probe a single path and return True if it looks valid.

    Considers HTTP 200 and 302 as positive hits; 404 (and connection
    errors) as negative.  A short timeout prevents hanging on dead hosts.

    Args:
        base_url: Target base URL (e.g. ``http://localhost:8080``).
        path:     Relative path or word to append.
        session:  Optional shared ``requests.Session`` for connection reuse.

    Returns:
        True when the endpoint responds with 200 or 302.
    """
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    sess = session or requests.Session()
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = sess.get(url, timeout=TIMEOUT, allow_redirects=False, headers=headers)
        return resp.status_code in (200, 302)
    except requests.RequestException:
        return False


def find_hidden_endpoint(base_url: str, words: List[str]) -> Optional[str]:
    """Walk the wordlist and return the first path that exists.

    Args:
        base_url: Target base URL.
        words:    Wordlist previously loaded by ``load_wordlist``.

    Returns:
        The matching path (as given in the wordlist) or ``None`` if nothing
        was found.
    """
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    for word in words:
        if check_path(base_url, word, session=session):
            return word
    return None
