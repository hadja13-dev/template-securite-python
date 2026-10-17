import logging
import re
from urllib.parse import unquote_plus

from scapy.all import IP, TCP, PacketList, Raw

from tp1.utils.config import SQLI_PATTERNS

from .base import Attack, Detector

logger = logging.getLogger(__name__)

HTTP_METHODS: tuple[bytes, ...] = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ")


class SqlInjectionDetector(Detector):
    def __init__(self) -> None:
        self.patterns = [re.compile(p, re.IGNORECASE) for p in SQLI_PATTERNS]

    def is_malicious(self, payload: str) -> bool:
        decoded = unquote_plus(payload)
        return any(p.search(decoded) for p in self.patterns)

    def detect(self, packets: PacketList) -> list[Attack]:
        attackers: set[str] = set()

        for pkt in packets:
            if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
                continue
            raw = pkt[Raw].load
            # seules les requêtes du client, jamais les réponses du serveur
            if not raw.startswith(HTTP_METHODS):
                continue
            if self.is_malicious(raw.decode(errors="ignore")):
                src = pkt[IP].src
                attackers.add(src)
                logger.info("SQLi détectée depuis %s", src)

        return [Attack(type="sql_injection", attacker=ip) for ip in sorted(attackers)]
