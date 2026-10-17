"""Détection de scan de ports."""

import logging
from collections import defaultdict

from scapy.all import IP, TCP, PacketList

from tp1.utils.config import PORT_SCAN_THRESHOLD

from .base import Attack, Detector

logger = logging.getLogger(__name__)


class PortScanDetector(Detector):
    """Repère une source qui envoie des SYN vers de nombreux ports."""

    def __init__(self, threshold: int = PORT_SCAN_THRESHOLD) -> None:
        """Fixe le nombre de ports distincts avant alerte."""
        self.threshold = threshold

    def detect(self, packets: PacketList) -> list[Attack]:
        """Retourne les IP sources qui scannent."""
        ports: dict[str, set[int]] = defaultdict(set)

        for pkt in packets:
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
                continue
            tcp = pkt[TCP]
            # SYN seul, pas SYN-ACK ni autre combinaison
            if tcp.flags == "S":
                ports[pkt[IP].src].add(tcp.dport)

        attacks: list[Attack] = []
        for src, dst_ports in sorted(ports.items()):
            if len(dst_ports) >= self.threshold:
                logger.info("Scan de ports depuis %s (%d ports)", src, len(dst_ports))
                attacks.append(Attack(type="port_scan", attacker=src))
        return attacks
