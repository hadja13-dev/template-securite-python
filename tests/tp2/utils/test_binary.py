import sys
from pathlib import Path

from tp2.utils.binary import find_suspicious_apis, get_overlay, parse_binary


def test_get_overlay_fichier_non_binaire() -> None:
    data = b"pas un binaire"
    assert get_overlay(data) == data


def test_get_overlay_binaire_reel() -> None:
    data = Path(sys.executable).read_bytes() + b"DONNEES_AJOUTEES"
    assert get_overlay(data).endswith(b"DONNEES_AJOUTEES")


def test_parse_binary_executable_reel() -> None:
    result = parse_binary(sys.executable)
    assert result["format"] in {"PE", "ELF", "MACHO"}
    assert result["sections"]


def test_parse_binary_fichier_texte(tmp_path: Path) -> None:
    fichier = tmp_path / "note.txt"
    fichier.write_text("bonjour")
    assert parse_binary(fichier)["format"] == "unknown"


def test_find_suspicious_apis() -> None:
    strings = ["urlmon.dll", "URLDownloadToFileA", "WinExec", "sendmail_config"]
    assert find_suspicious_apis(strings) == {
        "download": ["URLDownloadToFileA"],
        "execution": ["WinExec"],
    }
