from scapy.all import ARP, Ether, PacketList

from tp1.utils.detection.arp_spoof import ArpSpoofDetector
from tp1.utils.detection.base import Attack


class TestArpSpoofDetector:
    def setup_method(self) -> None:
        self.detector = ArpSpoofDetector()

    def test_detect_empty(self) -> None:
        assert self.detector.detect(PacketList([])) == []

    def test_detect_only_requests(self) -> None:
        pkts = PacketList(
            [
                Ether() / ARP(op=1, pdst="192.168.1.1"),
                Ether() / ARP(op=1, pdst="192.168.1.2"),
            ]
        )
        assert self.detector.detect(pkts) == []

    def test_detect_legitimate_reply(self) -> None:
        pkts = PacketList(
            [
                Ether() / ARP(op=1, pdst="192.168.1.10"),
                Ether() / ARP(op=2, psrc="192.168.1.10", hwsrc="de:ad:be:ef:00:01"),
            ]
        )
        assert self.detector.detect(pkts) == []

    def test_detect_unsolicited_without_conflict(self) -> None:
        pkts = PacketList([Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="11:22:33:44:55:66")])
        assert self.detector.detect(pkts) == []

    def test_detect_conflict_spares_legit_mac(self) -> None:
        pkts = PacketList(
            [
                Ether() / ARP(op=1, pdst="192.168.1.1"),
                Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:01"),
                Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc="11:22:33:44:55:66"),
            ]
        )
        assert self.detector.detect(pkts) == [Attack(type="arp_spoofing", attacker="11:22:33:44:55:66")]

    def test_detect_mitm(self) -> None:
        pkts = PacketList(
            [
                Ether() / ARP(op=1, pdst="10.0.0.1"),
                Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa"),
                Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="bb:bb:bb:bb:bb:bb"),
                Ether() / ARP(op=2, psrc="10.0.0.2", hwsrc="bb:bb:bb:bb:bb:bb"),
            ]
        )
        assert self.detector.detect(pkts) == [Attack(type="arp_spoofing", attacker="bb:bb:bb:bb:bb:bb")]
