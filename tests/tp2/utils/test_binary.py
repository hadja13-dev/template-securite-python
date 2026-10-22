from tp2.utils.binary import get_overlay


def test_get_overlay_fichier_non_binaire() -> None:
    data = b"pas un binaire"
    assert get_overlay(data) == data
