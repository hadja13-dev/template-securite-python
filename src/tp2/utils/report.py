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


def write_json(report: dict, out_dir: Path) -> Path:
    path = out_dir / f"{report['sha256']}.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("JSON écrit : %s", path)
    return path


def to_latin1(text: str) -> str:
    return text.encode("latin-1", errors="replace").decode("latin-1")


def write_pdf(report: dict, out_dir: Path) -> Path:
    pdf_dir = out_dir / "pdf"
    pdf_dir.mkdir(parents=True, exist_ok=True)
    path = pdf_dir / f"{report['sha256']}.pdf"

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Rapport de triage", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=10)

    lines = [
        ("SHA-256", report["sha256"]),
        ("Type", report["file_type"]),
        ("Taille / entropie", f"{report['size']} octets / {report['entropy']}"),
        ("Famille", report["family_guess"]),
        ("Score", f"{report['score']}/10"),
        ("MITRE ATT&CK", ", ".join(report["mitre_attack"]) or "-"),
        ("YARA", ", ".join(report["yara_matches"]) or "-"),
    ]
    lines += [(f"IOC {k}", ", ".join(v) or "-") for k, v in report["iocs"].items()]
    lines.append(("Résumé", report["llm_summary"]))

    for label, value in lines:
        pdf.multi_cell(0, 6, to_latin1(f"{label} : {value}"), new_x="LMARGIN", new_y="NEXT")

    pdf.output(str(path))
    logger.info("PDF écrit : %s", path)
    return path


def generate_report(report: dict, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    return [write_json(report, out_dir), write_pdf(report, out_dir)]
