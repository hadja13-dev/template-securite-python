"""Recherche du flag dans la capture."""

import logging
import re
from urllib.parse import unquote_plus

from scapy.all import IP, PacketList, Raw

from tp1.utils.config import FLAG_PATTERN

logger = logging.getLogger(__name__)


class FlagFinder:
    """Extrait le flag ESGI{...} des payloads."""

    def __init__(self) -> None:
        """Compile le motif du flag."""
        self.pattern = re.compile(FLAG_PATTERN)

    def find(self, packets: PacketList, attackers: set[str] | None = None) -> str | None:
        """Retourne le flag, en priorité celui envoyé par un attaquant."""
        attackers = attackers or set()
        fallback: str | None = None
        for pkt in packets:
            if not pkt.haslayer(Raw):
                continue
            text = unquote_plus(pkt[Raw].load.decode(errors="ignore"))
            match = self.pattern.search(text)
            if not match:
                continue
            src = pkt[IP].src if pkt.haslayer(IP) else None
            if src in attackers:
                logger.info("Flag trouvé dans le trafic de %s", src)
                return match.group(0)
            fallback = fallback or match.group(0)
        return fallback
