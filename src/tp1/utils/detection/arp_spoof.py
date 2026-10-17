import logging
from collections import Counter, defaultdict

from scapy.all import ARP, PacketList

from .base import Attack, Detector

logger = logging.getLogger(__name__)


class ArpSpoofDetector(Detector):
    def detect(self, packets: PacketList) -> list[Attack]:
        ip_to_macs: dict[str, set[str]] = defaultdict(set)
        mac_to_ips: dict[str, set[str]] = defaultdict(set)
        unsolicited: Counter[str] = Counter()
        pending: set[str] = set()

        for pkt in packets:
            if not pkt.haslayer(ARP):
                continue
            arp = pkt[ARP]

            if arp.op == 1:
                # requête : on attend une réponse pour cette IP
                pending.add(arp.pdst)
            elif arp.op == 2:
                mac = arp.hwsrc.lower()
                ip_to_macs[arp.psrc].add(mac)
                mac_to_ips[mac].add(arp.psrc)
                if arp.psrc in pending:
                    # la requête est consommée par la première réponse
                    pending.discard(arp.psrc)
                else:
                    unsolicited[mac] += 1

        attackers: set[str] = set()
        for ip, macs in ip_to_macs.items():
            if len(macs) < 2:
                continue
            # l'usurpateur annonce sa MAC pour plusieurs IP
            suspects = {m for m in macs if len(mac_to_ips[m]) > 1}
            if not suspects:
                # sinon : celle qui envoie le plus de réponses non sollicitées
                suspects = {max(macs, key=lambda m: unsolicited[m])}
            logger.info("Conflit ARP sur %s, suspect(s) : %s", ip, suspects)
            attackers |= suspects

        return [Attack(type="arp_spoofing", attacker=mac) for mac in sorted(attackers)]
