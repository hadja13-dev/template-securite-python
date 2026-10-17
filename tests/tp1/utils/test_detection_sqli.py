"""Tests de la classe SqlInjectionDetector."""

from scapy.all import IP, TCP, Ether, PacketList, Raw
from scapy.packet import Packet

from tp1.utils.detection.base import Attack
from tp1.utils.detection.sql_injection import SqlInjectionDetector


def _http_pkt(src: str, payload: str) -> Packet:
    """Construit un paquet TCP/Raw simulant du trafic HTTP."""
    return Ether() / IP(src=src) / TCP(dport=80) / Raw(load=payload.encode())


def test_http_pkt_helper() -> None:
    """Le helper produit un paquet avec IP source et payload."""
    pkt = _http_pkt("10.0.0.1", "GET / HTTP/1.1")
    assert pkt[IP].src == "10.0.0.1"
    assert pkt[Raw].load == b"GET / HTTP/1.1"


class TestSqlInjectionDetector:
    """Tests de détection d'injection SQL."""

    def setup_method(self) -> None:
        """Crée un détecteur neuf avant chaque test."""
        self.detector = SqlInjectionDetector()

    def test_is_malicious_true(self) -> None:
        """Les motifs classiques sont reconnus, même encodés en URL."""
        assert self.detector.is_malicious("id=1' OR 1=1 --") is True
        assert self.detector.is_malicious("id=1 UNION SELECT * FROM users") is True
        assert self.detector.is_malicious("id=1'; DROP TABLE users;--") is True
        assert self.detector.is_malicious("id=1%27%20OR%20%271%27%3D%271") is True

    def test_is_malicious_false(self) -> None:
        """Des requêtes normales ne sont pas signalées."""
        assert self.detector.is_malicious("GET /index.html HTTP/1.1") is False
        assert self.detector.is_malicious("id=42&name=alice") is False

    def test_detect_empty(self) -> None:
        """Une capture vide ne donne aucune alerte."""
        assert self.detector.detect(PacketList([])) == []

    def test_detect_no_raw(self) -> None:
        """Un paquet TCP sans payload est ignoré."""
        pkts = PacketList([Ether() / IP(src="10.0.0.1") / TCP()])
        assert self.detector.detect(pkts) == []

    def test_detect_get(self) -> None:
        """Une requête GET piégée désigne son IP source."""
        pkts = PacketList(
            [
                _http_pkt(
                    "10.0.0.50",
                    "GET /login?user=admin' OR 1=1-- HTTP/1.1\r\nHost: a\r\n\r\n",
                )
            ]
        )
        assert self.detector.detect(pkts) == [Attack(type="sql_injection", attacker="10.0.0.50")]

    def test_detect_post(self) -> None:
        """Une injection dans le corps d'un POST est détectée."""
        pkts = PacketList(
            [
                _http_pkt(
                    "192.168.1.99",
                    "POST / HTTP/1.1\r\n\r\nid=1'; DROP TABLE accounts;--",
                )
            ]
        )
        assert self.detector.detect(pkts) == [Attack(type="sql_injection", attacker="192.168.1.99")]

    def test_detect_ignores_response(self) -> None:
        """Une réponse du serveur qui reprend la requête n'est pas une attaque."""
        pkts = PacketList([_http_pkt("10.0.0.80", "HTTP/1.1 200 OK\r\n\r\nNo result for ' OR 1=1")])
        assert self.detector.detect(pkts) == []

    def test_detect_multiple_attackers(self) -> None:
        """Seules les sources malveillantes sont retenues."""
        pkts = PacketList(
            [
                _http_pkt("10.0.0.10", "GET /?id=1' OR '1'='1 HTTP/1.1\r\n\r\n"),
                _http_pkt("10.0.0.20", "GET /?id=1 UNION SELECT pw FROM u HTTP/1.1\r\n\r\n"),
                _http_pkt("10.0.0.30", "GET /index.html HTTP/1.1\r\n\r\n"),
            ]
        )
        attackers = {a.attacker for a in self.detector.detect(pkts)}
        assert attackers == {"10.0.0.10", "10.0.0.20"}
