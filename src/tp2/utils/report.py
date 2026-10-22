"""Génération des rapports : JSON machine-lisible et PDF lisible."""

import json
import logging
from pathlib import Path

from fpdf import FPDF

logger = logging.getLogger(__name__)

IOC_KEYS = ("domains", "ips", "urls", "mutex", "registry")


def build_report(
    meta: dict,
    iocs: dict[str, list[str]],
    imports: list[str],
    yara_matches: list[str],
    family: str,
    mitre: list[str],
    summary: str,
    score: int,
    flag: str,
) -> dict:
    """Assemble le rapport au format exact attendu par la correction."""
    return {
        "sha256": meta["sha256"],
        "md5": meta["md5"],
        "size": meta["size"],
        "entropy": meta["entropy"],
        "file_type": meta["file_type"],
        "iocs": {key: iocs.get(key, []) for key in IOC_KEYS},
        "imports": imports,
        "yara_matches": yara_matches,
        "family_guess": family,
        "mitre_attack": mitre,
        "llm_summary": summary,
        "score": score,
        "flag": flag,
    }


def output_names(sample: Path, sha256: str) -> list[str]:
    """Noms des JSON : <nom>.triage.json (correction) et <sha256>.json (énoncé)."""
    names = {
        f"{sample.stem}.triage.json",
        f"{sample.name}.triage.json",
        f"{sha256}.json",
    }
    return sorted(names)


def write_json(report: dict, out_dir: Path, sample: Path) -> list[Path]:
    """Écrit le rapport JSON sous chacun des noms attendus."""
    content = json.dumps(report, indent=2, ensure_ascii=False)
    paths = []
    for name in output_names(sample, report["sha256"]):
        path = out_dir / name
        path.write_text(content, encoding="utf-8")
        paths.append(path)
    logger.info("JSON écrits : %s", [p.name for p in paths])
    return paths


def to_latin1(text: str) -> str:
    """Convertit en latin-1, seul jeu géré par les polices standard de fpdf2."""
    return text.encode("latin-1", errors="replace").decode("latin-1")


def report_lines(report: dict) -> list[tuple[str, str]]:
    """Prépare les lignes (libellé, valeur) affichées dans le PDF."""
    lines = [
        ("SHA-256", report["sha256"]),
        ("Type", report["file_type"]),
        ("Taille / entropie", f"{report['size']} octets / {report['entropy']}"),
        ("Famille", report["family_guess"]),
        ("Score", f"{report['score']}/10"),
        ("MITRE ATT&CK", ", ".join(report["mitre_attack"]) or "-"),
        ("YARA", ", ".join(report["yara_matches"]) or "-"),
    ]
    for key, values in report["iocs"].items():
        lines.append((f"IOC {key}", ", ".join(values) or "-"))
    lines.append(("Résumé", report["llm_summary"]))
    return lines


def write_pdf(report: dict, out_dir: Path) -> Path:
    """Écrit un rapport PDF lisible dans out_dir/pdf/."""
    pdf_dir = out_dir / "pdf"
    pdf_dir.mkdir(parents=True, exist_ok=True)
    path = pdf_dir / f"{report['sha256']}.pdf"

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Rapport de triage", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=10)
    for label, value in report_lines(report):
        text = to_latin1(f"{label} : {value}")
        pdf.multi_cell(0, 6, text, new_x="LMARGIN", new_y="NEXT")

    pdf.output(str(path))
    logger.info("PDF écrit : %s", path)
    return path


def generate_report(report: dict, out_dir: Path, sample: Path) -> list[Path]:
    """Écrit les JSON et le PDF d'un échantillon."""
    out_dir.mkdir(parents=True, exist_ok=True)
    return [*write_json(report, out_dir, sample), write_pdf(report, out_dir)]
