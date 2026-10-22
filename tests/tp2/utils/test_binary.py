"""Tests du module binary."""

import sys
from pathlib import Path

from tp2.utils.binary import find_suspicious_apis, get_overlay, parse_binary


def test_get_overlay_fichier_non_binaire() -> None:
    """Un fichier non PE/ELF est renvoyé en entier, sans perte."""
    data = b"pas un binaire"
    assert get_overlay(data) == data


def test_get_overlay_binaire_reel() -> None:
    """Les octets ajoutés après un vrai exécutable sont isolés comme overlay."""
    data = Path(sys.executable).read_bytes() + b"DONNEES_AJOUTEES"
    assert get_overlay(data).endswith(b"DONNEES_AJOUTEES")


def test_parse_binary_executable_reel() -> None:
    """L'interpréteur Python est reconnu, avec ses sections."""
    result = parse_binary(sys.executable)
    assert result["format"] in {"PE", "ELF", "MACHO"}
    assert result["sections"]


def test_parse_binary_fichier_texte(tmp_path: Path) -> None:
    """Un fichier texte est signalé comme format inconnu, sans exception."""
    fichier = tmp_path / "note.txt"
    fichier.write_text("bonjour")
    assert parse_binary(fichier)["format"] == "unknown"


def test_find_suspicious_apis() -> None:
    """Les API sont classées par capacité ; une sous-chaîne ne suffit pas."""
    strings = ["urlmon.dll", "URLDownloadToFileA", "WinExec", "sendmail_config"]
    assert find_suspicious_apis(strings) == {
        "download": ["URLDownloadToFileA"],
        "execution": ["WinExec"],
    }
