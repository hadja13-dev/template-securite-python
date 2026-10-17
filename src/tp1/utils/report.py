"""Génération des rapports JSON et PDF."""

import contextlib
import json
import logging
from dataclasses import asdict
from pathlib import Path

from fpdf import FPDF
from matplotlib.figure import Figure

from .blocking import blocking_rule
from .detection.base import Attack

logger = logging.getLogger(__name__)


class JsonReport:
    def write(
        self,
        path: Path,
        protocols: dict[str, int],
        attacks: list[Attack],
        flag: str | None,
    ) -> None:
        """Sérialise le rapport."""
        data = {
            "protocols": protocols,
            "attacks": [asdict(a) for a in attacks],
            "flag": flag,
        }
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info("Rapport JSON écrit : %s", path)


class PdfReport:
    def build_chart(self, protocols: dict[str, int], out: Path) -> Path:
        out = Path(out)
        out.parent.mkdir(parents=True, exist_ok=True)

        fig = Figure(figsize=(8, 4))
        ax = fig.subplots()
        ax.bar(list(protocols.keys()), list(protocols.values()), color="steelblue")
        ax.set_xlabel("Protocole")
        ax.set_ylabel("Nombre de paquets")
        ax.set_title("Répartition des protocoles")
        ax.tick_params(axis="x", labelrotation=45)
        fig.tight_layout()
        fig.savefig(out, dpi=120)
        logger.info("Graphique enregistré : %s", out)
        return out

    def write(self, path: Path, protocols: dict[str, int], attacks: list[Attack]) -> None:
        """Assemble le PDF : titre, graphique, protocoles, attaques."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        chart_path = path.with_suffix(".png")
        self.build_chart(protocols, chart_path)

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # Titre
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "Rapport d'analyse reseau", align="C")
        pdf.ln(12)

        # Graphique
        pdf.image(str(chart_path), x=10, w=190)
        pdf.ln(5)

        # Tableau des protocoles
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Protocoles")
        pdf.ln(8)
        pdf.set_font("Helvetica", size=10)
        pdf.cell(80, 7, "Protocole", border=1)
        pdf.cell(40, 7, "Nombre", border=1)
        pdf.ln(7)
        for name, count in sorted(protocols.items()):
            pdf.cell(80, 7, str(name), border=1)
            pdf.cell(40, 7, str(count), border=1)
            pdf.ln(7)
        pdf.ln(8)

        # Attaques et règles de blocage
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Attaques detectees")
        pdf.ln(8)
        pdf.set_font("Helvetica", size=9)
        if not attacks:
            pdf.cell(0, 7, "Aucune attaque detectee.")
            pdf.ln(7)
        else:
            pdf.cell(35, 7, "Type", border=1)
            pdf.cell(40, 7, "Attaquant", border=1)
            pdf.cell(115, 7, "Regle de blocage proposee", border=1)
            pdf.ln(7)
            for a in attacks:
                pdf.cell(35, 7, a.type, border=1)
                pdf.cell(40, 7, a.attacker, border=1)
                pdf.cell(115, 7, blocking_rule(a), border=1)
                pdf.ln(7)

        pdf.output(str(path))
        logger.info("Rapport PDF écrit : %s", path)

        # Nettoyage du PNG temporaire
        with contextlib.suppress(OSError):
            chart_path.unlink(missing_ok=True)
