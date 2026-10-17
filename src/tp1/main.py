"""Point d'entrée CLI du TP1."""

import argparse
import logging
from pathlib import Path

from tp1.utils.blocking import blocking_rule
from tp1.utils.capture import PacketCapture
from tp1.utils.detection import run_all_detectors
from tp1.utils.flag import FlagFinder
from tp1.utils.report import JsonReport, PdfReport
from tp1.utils.stats import ProtocolStats

logger = logging.getLogger("tp1")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Analyse les arguments --pcap, --iface, --out et --count."""
    parser = argparse.ArgumentParser(description="TP1 - Analyse de capture reseau")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", type=Path, help="Fichier PCAP a analyser")
    source.add_argument("--iface", type=str, help="Interface a sniffer")
    parser.add_argument("--out", type=Path, default=Path("report.json"))
    parser.add_argument("--count", type=int, default=100)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Orchestre capture, stats, détection, flag et rapports."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args(argv)

    packets = PacketCapture(pcap=args.pcap, iface=args.iface).load(count=args.count)
    logger.info("%d paquets chargés", len(packets))

    protocols = ProtocolStats().compute(packets)

    attacks = run_all_detectors(packets)
    for attack in attacks:
        logger.info("[%s] %s -> %s", attack.type, attack.attacker, blocking_rule(attack))

    flag = FlagFinder().find(packets, {a.attacker for a in attacks})
    logger.info("Flag : %s", flag)

    JsonReport().write(args.out, protocols, attacks, flag)

    try:
        PdfReport().write(args.out.with_suffix(".pdf"), protocols, attacks)
    except Exception:
        logger.exception("Échec de la génération du PDF (ignoré)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
