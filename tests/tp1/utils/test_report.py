"""Tests des classes JsonReport et PdfReport."""

import json
from pathlib import Path

from tp1.utils.detection.base import Attack
from tp1.utils.report import JsonReport, PdfReport

PROTOCOLS = {"TCP": 10, "ARP": 2, "DNS": 3}
ATTACKS = [Attack(type="port_scan", attacker="10.0.0.5")]


def test_json_write(tmp_path: Path) -> None:
    """Le JSON respecte le format attendu."""
    out = tmp_path / "sub" / "report.json"
    JsonReport().write(out, PROTOCOLS, ATTACKS, "ESGI{x}")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["protocols"] == PROTOCOLS
    assert data["attacks"] == [{"type": "port_scan", "attacker": "10.0.0.5"}]
    assert data["flag"] == "ESGI{x}"


def test_build_chart(tmp_path: Path) -> None:
    """Le graphique est un vrai fichier PNG."""
    png = PdfReport().build_chart(PROTOCOLS, tmp_path / "chart.png")
    assert png.read_bytes()[:4] == b"\x89PNG"


def test_pdf_write(tmp_path: Path) -> None:
    """Le PDF est créé et le PNG temporaire supprimé."""
    out = tmp_path / "report.pdf"
    PdfReport().write(out, PROTOCOLS, ATTACKS)
    assert out.read_bytes()[:4] == b"%PDF"
    assert not out.with_suffix(".png").exists()


def test_pdf_write_no_attack(tmp_path: Path) -> None:
    """Le PDF se génère aussi sans aucune attaque."""
    out = tmp_path / "report.pdf"
    PdfReport().write(out, PROTOCOLS, [])
    assert out.exists()
