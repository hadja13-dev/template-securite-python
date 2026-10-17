"""Comptage des paquets par protocole."""

import logging
from collections import Counter
from typing import ClassVar

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, PacketList, Raw
from scapy.packet import Packet

logger = logging.getLogger(__name__)


class ProtocolStats:
    """Compte les protocoles présents dans une capture."""

    LAYERS: ClassVar[dict[str, type]] = {
        "Ethernet": Ether,
        "ARP": ARP,
        "IP": IP,
        "ICMP": ICMP,
        "TCP": TCP,
        "UDP": UDP,
        "DNS": DNS,
    }

    def compute(self, packets: PacketList) -> dict[str, int]:
        counts: Counter[str] = Counter()

        for pkt in packets:
            for name, layer in self.LAYERS.items():
                if pkt.haslayer(layer):
                    counts[name] += 1

            if self._is_http(pkt):
                counts["HTTP"] += 1

        logger.info("%d paquets analysés, %d protocoles distincts", len(packets), len(counts))
        return dict(counts)

    @staticmethod
    def _is_http(pkt: Packet) -> bool:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return False

        payload = bytes(pkt[Raw].load)
        return payload.startswith(
            (
                b"GET ",
                b"POST ",
                b"PUT ",
                b"DELETE ",
                b"HEAD ",
                b"OPTIONS ",
                b"PATCH ",
                b"HTTP/",
            )
        )
