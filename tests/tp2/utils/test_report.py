import json
from pathlib import Path

from tp2.utils.report import (
    build_report,
    generate_report,
    to_latin1,
    write_json,
    write_pdf,
)

META = {"sha256": "ab" * 32, "md5": "cd" * 16, "size": 10, "entropy": 4.2, "file_type": "data"}
IOCS = {"domains": ["c2.bad.test"], "ips": [], "urls": [], "mutex": [], "registry": [], "paths": ["/tmp/x"]}


def make_report() -> dict:
    return build_report(
        META, IOCS, ["WinExec"], ["Rule_A"], "dropper", ["T1105"], "Résumé.", 8, "ESGI{vrai_1}"
    )


def test_build_report_format_exact() -> None:
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


def test_write_json(tmp_path: Path) -> None:
    path = write_json(make_report(), tmp_path)
    assert path.name == f"{'ab' * 32}.json"
    assert json.loads(path.read_text(encoding="utf-8"))["flag"] == "ESGI{vrai_1}"


def test_to_latin1() -> None:
    assert to_latin1("été ‹x›") == "été ?x?"


def test_write_pdf(tmp_path: Path) -> None:
    path = write_pdf(make_report(), tmp_path)
    assert path.read_bytes().startswith(b"%PDF")


def test_generate_report(tmp_path: Path) -> None:
    paths = generate_report(make_report(), tmp_path / "out")
    assert [p.suffix for p in paths] == [".json", ".pdf"]
