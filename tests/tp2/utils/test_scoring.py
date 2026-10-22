"""Tests du module scoring."""

from tp2.utils.scoring import (
    clamp,
    combine_scores,
    compute_score,
    guess_family,
    is_packed,
    map_mitre,
)

IOCS = {
    "domains": ["c2.evil.test"],
    "ips": ["185.1.2.3"],
    "urls": ["http://c2.evil.test/gate.php"],
    "mutex": ["Global\\abc"],
    "registry": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svc"],
}
EMPTY_IOCS = {k: [] for k in IOCS}


def test_is_packed() -> None:
    """Le packing est signalé par la règle High_Entropy_Tail."""
    assert is_packed(["High_Entropy_Tail"])
    assert not is_packed([])


def test_guess_family_priorite() -> None:
    """Le téléchargement prime sur la simple exécution : c'est un dropper."""
    caps = {"download": ["URLDownloadToFileA"], "execution": ["WinExec"]}
    assert guess_family(caps, []) == "dropper"


def test_guess_family_packed_et_inconnu() -> None:
    """Sans capacité visible : packed si l'entropie l'indique, sinon unknown."""
    assert guess_family({}, ["High_Entropy_Tail"]) == "packed"
    assert guess_family({}, []) == "unknown"


def test_map_mitre() -> None:
    """Capacités, IOC et packing sont traduits en techniques MITRE triées."""
    caps = {"keylogging": ["GetAsyncKeyState"]}
    result = map_mitre(caps, IOCS, ["High_Entropy_Tail"])
    assert result == ["T1027", "T1056", "T1071", "T1547"]


def test_clamp() -> None:
    """Le score est borné entre 0 et 10."""
    assert clamp(-3) == 0
    assert clamp(42) == 10
    assert clamp(5) == 5


def test_compute_score() -> None:
    """5 types d'IOC + 1 capacité + 1 injection = 7 ; rien du tout = 0."""
    assert compute_score(EMPTY_IOCS, {}, []) == 0
    caps = {"network": ["connect"]}
    assert compute_score(IOCS, caps, ["Prompt_Injection_Text"]) == 7


def test_combine_scores_resiste_a_l_injection() -> None:
    """Un LLM manipulé qui répond 0 ne retire qu'un point au score déterministe."""
    assert combine_scores(7, 0) == 6
    assert combine_scores(7, 10) == 8
    assert combine_scores(7, None) == 7
