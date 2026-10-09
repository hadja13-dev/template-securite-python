"""Tests de la classe PortScanDetector."""

from scapy.all import IP, TCP, Ether, PacketList

from tp1.utils.config import PORT_SCAN_THRESHOLD
from tp1.utils.detection.base import Attack
from tp1.utils.detection.port_scan import PortScanDetector


class TestPortScanDetector:

    def setup_method(self) -> None:
        self.detector = PortScanDetector(threshold=5)

    def test_default_threshold(self) -> None:
        assert PortScanDetector().threshold == PORT_SCAN_THRESHOLD

    def test_detect_empty(self) -> None:
        assert self.detector.detect(PacketList([])) == []

    def test_detect_no_scan(self) -> None:
        pkts = PacketList(
            [
                Ether() / IP(src="10.0.0.5") / TCP(dport=80, flags="S"),
                Ether() / IP(src="10.0.0.5") / TCP(dport=443, flags="S"),
                Ether() / IP(src="10.0.0.5") / TCP(dport=80, flags="S"),
            ]
        )
        assert self.detector.detect(pkts) == []

    def test_detect_scan(self) -> None:
        pkts = PacketList(
            [Ether() / IP(src="10.0.0.99") / TCP(dport=p, flags="S") for p in range(20, 30)]
        )
        assert self.detector.detect(pkts) == [
            Attack(type="port_scan", attacker="10.0.0.99")
        ]

    def test_detect_ignores_synack(self) -> None:
        pkts = PacketList(
            [Ether() / IP(src="10.0.0.1") / TCP(dport=p, flags="SA") for p in range(1, 20)]
        )
        assert self.detector.detect(pkts) == []

    def test_detect_multiple_sources(self) -> None:
        pkts = PacketList(
            [Ether() / IP(src="10.0.0.1") / TCP(dport=p, flags="S") for p in range(10)]
            + [Ether() / IP(src="10.0.0.2") / TCP(dport=80, flags="S")]
        )
        assert self.detector.detect(pkts) == [
            Attack(type="port_scan", attacker="10.0.0.1")
        ]

    def test_detect_threshold_limit(self) -> None:
        src = "10.0.0.77"
        below = PacketList([Ether() / IP(src=src) / TCP(dport=p, flags="S") for p in range(4)])
        at = PacketList([Ether() / IP(src=src) / TCP(dport=p, flags="S") for p in range(5)])
        assert self.detector.detect(below) == []
        assert self.detector.detect(at) == [Attack(type="port_scan", attacker=src)]