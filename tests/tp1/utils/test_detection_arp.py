"""Tests de la classe ArpSpoofDetector."""

from scapy.all import ARP, Ether, PacketList

from tp1.utils.detection.arp_spoof import ArpSpoofDetector
from tp1.utils.detection.base import Attack


class TestArpSpoofDetector:
    """Tests de détection d'ARP spoofing."""

    def setup_method(self) -> None:
        """Crée un détecteur neuf avant chaque test."""
        self.detector = ArpSpoofDetector()

    def test_detect_empty(self) -> None:
        """Une capture vide ne donne aucune alerte."""
        assert self.detector.detect(PacketList([])) == []

    def test_detect_only_requests(self) -> None:
        """Des requêtes seules ne donnent aucune alerte."""
        pkts = PacketList(
            [
                Ether() / ARP(op=1, pdst="192.168.1.1"),
                Ether() / ARP(op=1, pdst="192.168.1.2"),
            ]
        )
        assert self.detector.detect(pkts) == []

    def test_detect_legitimate_reply(self) -> None:
        """Une requête suivie de sa réponse est normale."""
        pkts = PacketList(
            [
                Ether() / ARP(op=1, pdst="192.168.1.10"),
                Ether() / ARP(op=2, psrc="192.168.1.10", hwsrc="de:ad:be:ef:00:01"),
            ]
        )
        assert self.detector.detect(pkts) == []

    def test_detect_unsolicited_without_conflict(self) -> None:
        """Un ARP gratuit isolé n'est pas une attaque."""
        pkts = PacketList([Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="11:22:33:44:55:66")])
        assert self.detector.detect(pkts) == []

    def test_detect_conflict_spares_legit_mac(self) -> None:
        """Seule la MAC non sollicitée est accusée, pas la légitime."""
        pkts = PacketList(
            [
                Ether() / ARP(op=1, pdst="192.168.1.1"),
                Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:01"),
                Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="11:22:33:44:55:66"),
            ]
        )
        assert self.detector.detect(pkts) == [Attack(type="arp_spoofing", attacker="11:22:33:44:55:66")]

    def test_detect_mitm(self) -> None:
        """La MAC qui revendique plusieurs IP est l'attaquant."""
        pkts = PacketList(
            [
                Ether() / ARP(op=1, pdst="10.0.0.1"),
                Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa"),
                Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="bb:bb:bb:bb:bb:bb"),
                Ether() / ARP(op=2, psrc="10.0.0.2", hwsrc="bb:bb:bb:bb:bb:bb"),
            ]
        )
        assert self.detector.detect(pkts) == [Attack(type="arp_spoofing", attacker="bb:bb:bb:bb:bb:bb")]
