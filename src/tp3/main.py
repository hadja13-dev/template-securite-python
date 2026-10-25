"""
main.py — TP3 orchestrator: web phase → network phase → flags.
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from tp3.utils.captcha import solve_captcha
from tp3.utils.fuzzer import find_hidden_endpoint, load_wordlist
from tp3.utils.netclient import run_rounds

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

TIMEOUT = 8
MAX_CAPTCHA_ATTEMPTS = 15

logger = logging.getLogger("tp3")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments. --target is mandatory."""
    parser = argparse.ArgumentParser(
        description="TP3 orchestrator — Web and network phases",
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Base URL of the web target (e.g. http://localhost:8080)",
    )
    return parser.parse_args()


def setup_logging() -> logging.Logger:
    """Configure and return the module logger."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        stream=sys.stdout,
    )
    return logging.getLogger("tp3")


def parse_server_response(
    payload: Any,
) -> tuple[str, str, int, bytes]:
    """Validate and extract metadata from a successful JSON response."""

    if not isinstance(payload, dict):
        raise TypeError("La réponse doit être un objet JSON.")

    required = ("flag1", "host", "port", "key")
    missing = [name for name in required if name not in payload]

    if missing:
        raise ValueError(f"Champs manquants dans la réponse : {', '.join(missing)}")

    flag1 = payload["flag1"]
    host = payload["host"]

    if not isinstance(flag1, str) or not isinstance(host, str):
        raise TypeError("Les champs flag1 et host doivent être des chaînes.")

    if not host.strip():
        raise ValueError("Le champ host est vide.")

    try:
        port = int(payload["port"])
    except (TypeError, ValueError) as exc:
        raise ValueError("Le port doit être un entier.") from exc

    if not 1 <= port <= 65535:
        raise ValueError(f"Port invalide : {port}")

    key_hex = payload["key"]

    if not isinstance(key_hex, str):
        raise TypeError("La clé doit être une chaîne hexadécimale.")

    try:
        key = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise ValueError("La clé ne contient pas un hexadécimal valide.") from exc

    return flag1, host, port, key


def _solve_web_phase(
    base_url: str,
    endpoint: str,
    log: logging.Logger,
) -> tuple[str, str, int, bytes]:
    """Retrieve the hidden page, solve the CAPTCHA (with retries), parse JSON."""

    with requests.Session() as session:
        session.headers.update({"User-Agent": USER_AGENT})
        page_url = urljoin(base_url.rstrip("/") + "/", endpoint.lstrip("/"))
        log.info("[*] Fetching hidden page: %s", page_url)

        for attempt in range(1, MAX_CAPTCHA_ATTEMPTS + 1):
            # --- GET page (régénère un nouveau CAPTCHA à chaque tour) ---
            resp = session.get(page_url, timeout=TIMEOUT)
            resp.raise_for_status()
            html = resp.text

            # --- Localiser l'image CAPTCHA ---
            img_m = re.search(
                r'<img[^>]+src=["\']([^"\']*(?:captcha|challenge|verify)[^"\']*)["\']',
                html,
                re.IGNORECASE,
            )
            if not img_m:
                img_m = re.search(r'<img[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
            if not img_m:
                raise RuntimeError("CAPTCHA image not found on page")  # structurel → raise

            img_url = urljoin(page_url, img_m.group(1))
            img_resp = session.get(img_url, timeout=TIMEOUT)
            img_resp.raise_for_status()

            # --- OCR + validation longueur ---
            captcha_text = solve_captcha(img_resp.content).strip().upper()
            if len(captcha_text) != 5:
                log.warning("[-] Essai %d: OCR longueur %d ≠ 5, on retente…", attempt, len(captcha_text))
                continue  # ← mauvais OCR → on repart (nouveau GET)

            # --- Détecter form action + champ (comme avant) ---
            form_m = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', html, re.IGNORECASE)
            action = form_m.group(1) if form_m else page_url
            action_url = urljoin(page_url, action)

            field = "captcha"
            for name in ("captcha", "code", "answer", "solution", "response", "verify"):
                if re.search(rf'name=["\']{name}["\']', html, re.IGNORECASE):
                    field = name
                    break

            data = {field: captcha_text}
            for hidden in re.finditer(
                r'<input[^>]+type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
                html,
                re.IGNORECASE,
            ):
                data[hidden.group(1)] = hidden.group(2)

            # --- POST ---
            post = session.post(action_url, data=data, timeout=TIMEOUT, allow_redirects=True)

            try:
                payload = post.json()
            except requests.exceptions.JSONDecodeError:
                log.warning("[-] Essai %d: réponse non-JSON, on retente…", attempt)
                continue

            # --- Échec CAPTCHA → on retente ---
            if post.status_code == 403 or not isinstance(payload, dict) or "flag1" not in payload:
                err = (
                    payload.get("error", "captcha refusé")
                    if isinstance(payload, dict)
                    else "réponse inattendue"
                )
                log.warning("[-] Essai %d refusé (OCR lu: %s) — %s, on retente…", attempt, captcha_text, err)
                continue

            # --- Succès ---
            try:
                result = parse_server_response(payload)
            except (ValueError, TypeError) as exc:
                raise RuntimeError(f"Invalid server response: {exc}") from exc

            log.info("[+] CAPTCHA accepté (essai %d)", attempt)
            return result

        # --- Toutes les tentatives épuisées ---
        raise RuntimeError(f"CAPTCHA non résolu après {MAX_CAPTCHA_ATTEMPTS} essais")


def main() -> None:
    """Orchestrate the TP3 workflow."""

    args = parse_args()
    log = setup_logging()

    target = args.target.rstrip("/")
    log.info("[*] Target: %s", target)

    # 1. Discover the hidden endpoint.
    words = load_wordlist()
    endpoint = find_hidden_endpoint(target, words)

    if not endpoint:
        log.error("[-] Hidden endpoint not found")
        sys.exit(1)

    log.info("[+] Hidden endpoint: %s", endpoint)

    # 2. Web phase: CAPTCHA → FLAG1 + network metadata.
    flag1, host, port, key = _solve_web_phase(
        target,
        endpoint,
        log,
    )

    log.info("[+] FLAG1: %s", flag1)
    log.info("[*] Network target: %s:%s", host, port)

    # Rewrite localhost to the web-target hostname when necessary.
    parsed = urlparse(target)

    if host in ("localhost", "127.0.0.1"):
        host = parsed.hostname or "localhost"
        log.info(
            "[*] Rewrote network target → %s:%s",
            host,
            port,
        )

    # 3. Network phase.
    final = run_rounds(host, port, key)
    log.info("[+] FLAG_FINAL: %s", final)


if __name__ == "__main__":
    try:
        main()
    except (requests.RequestException, RuntimeError, ValueError, TypeError) as exc:
        logger.error("[-] %s", exc)
        sys.exit(1)
