"""Lecture des paquets depuis un fichier PCAP ou une interface réseau."""

import logging
from pathlib import Path

from scapy.all import PacketList, get_if_list, rdpcap, sniff

logger = logging.getLogger(__name__)


class PacketCapture:
    """Charge des paquets réseau depuis un PCAP ou une interface."""

    def __init__(self, pcap: Path | None = None, iface: str | None = None) -> None:
        """Enregistre la source ; il en faut au moins une."""
        if pcap is None and iface is None:
            raise ValueError("Il faut un fichier PCAP ou une interface")
        self.pcap = Path(pcap) if pcap is not None else None
        self.iface = iface

    def load(self, count: int = 0, timeout: int = 30) -> PacketList:
        """Retourne les paquets lus depuis le fichier ou l'interface."""
        if self.pcap is not None:
            if not self.pcap.is_file():
                raise FileNotFoundError(self.pcap)
            packets = rdpcap(str(self.pcap))
            logger.info("%d paquets lus depuis %s", len(packets), self.pcap)
            return packets
        logger.info("Capture sur %s (timeout %ds)", self.iface, timeout)
        return sniff(iface=self.iface, count=count, timeout=timeout)


def list_interfaces() -> list[str]:
    """Liste les interfaces réseau disponibles."""
    return get_if_list()
