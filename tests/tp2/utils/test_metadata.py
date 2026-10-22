"""Tests du module metadata."""

import hashlib

from tp2.utils.metadata import detect_file_type, get_file_metadata, shannon_entropy


def test_shannon_entropy_uniforme() -> None:
    """Un fichier rempli d'un seul octet a une entropie nulle."""
    assert shannon_entropy(b"A" * 100) == 0.0


def test_shannon_entropy_maximale() -> None:
    """Les 256 valeurs d'octet présentes une fois donnent l'entropie maximale (8)."""
    assert shannon_entropy(bytes(range(256))) == 8.0


def test_shannon_entropy_vide() -> None:
    """Un contenu vide a une entropie nulle, sans division par zéro."""
    assert shannon_entropy(b"") == 0.0


def test_detect_file_type_texte() -> None:
    """libmagic reconnaît un contenu texte."""
    assert "text" in detect_file_type(b"hello world\n").lower()


def test_get_file_metadata() -> None:
    """Empreintes, taille et entropie sont correctement calculées."""
    data = b"echantillon de test"
    meta = get_file_metadata(data)
    assert meta["sha256"] == hashlib.sha256(data).hexdigest()
    assert meta["md5"] == hashlib.md5(data).hexdigest()
    assert meta["size"] == len(data)
    assert 0 <= meta["entropy"] <= 8
