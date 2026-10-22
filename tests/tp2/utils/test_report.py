"""Tests du module report."""

import json
from pathlib import Path

from tp2.utils.report import (
    build_report,
    generate_report,
    output_names,
    report_lines,
    to_latin1,
    write_json,
    write_pdf,
)

SHA = "ab" * 32
META = {
    "sha256": SHA,
    "md5": "cd" * 16,
    "size": 10,
    "entropy": 4.2,
    "file_type": "data",
}
IOCS = {
    "domains": ["c2.bad.test"],
    "ips": [],
    "urls": [],
    "mutex": [],
    "registry": [],
    "paths": ["/tmp/x"],
}
SAMPLE = Path("sample1.bin")


def make_report() -> dict:
    """Construit un rapport type pour les tests."""
    return build_report(
        META,
        IOCS,
        ["WinExec"],
        ["Rule_A"],
        "dropper",
        ["T1105"],
        "Résumé.",
        8,
        "ESGI{vrai_1}",
    )


def test_build_report_format_exact() -> None:
    """Les 13 clés sont présentes dans l'ordre, sans la clé paths."""
    report = make_report()
    assert list(report) == [
        "sha256",
        "md5",
        "size",
        "entropy",
        "file_type",
        "iocs",
        "imports",
        "yara_matches",
        "family_guess",
        "mitre_attack",
        "llm_summary",
        "score",
        "flag",
    ]
    assert "paths" not in report["iocs"]


def test_output_names() -> None:
    """Les trois noms attendus sont produits, sans doublon."""
    assert output_names(SAMPLE, SHA) == [
        f"{SHA}.json",
        "sample1.bin.triage.json",
        "sample1.triage.json",
    ]


def test_write_json(tmp_path: Path) -> None:
    """Le JSON est écrit sous chaque nom, avec le bon contenu."""
    paths = write_json(make_report(), tmp_path, SAMPLE)
    assert len(paths) == 3
    for path in paths:
        assert json.loads(path.read_text(encoding="utf-8"))["flag"] == "ESGI{vrai_1}"


def test_to_latin1() -> None:
    """Les caractères hors latin-1 sont remplacés, les accents conservés."""
    assert to_latin1("été ‹x›") == "été ?x?"


def test_report_lines() -> None:
    """Le PDF affiche le score, les IOC et le résumé."""
    lines = dict(report_lines(make_report()))
    assert lines["Score"] == "8/10"
    assert lines["IOC domains"] == "c2.bad.test"
    assert lines["Résumé"] == "Résumé."


def test_write_pdf(tmp_path: Path) -> None:
    """Un vrai fichier PDF est produit."""
    path = write_pdf(make_report(), tmp_path)
    assert path.read_bytes().startswith(b"%PDF")


def test_generate_report(tmp_path: Path) -> None:
    """Trois JSON et un PDF sont produits par échantillon."""
    paths = generate_report(make_report(), tmp_path / "out", SAMPLE)
    assert [p.suffix for p in paths] == [".json", ".json", ".json", ".pdf"]
