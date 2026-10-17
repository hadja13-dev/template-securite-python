"""Tests de la classe ProtocolStats."""

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, PacketList, Raw

from tp1.utils.stats import ProtocolStats


class TestProtocolStats:
    """Tests du comptage des protocoles."""

    def setup_method(self) -> None:
        """Crée une instance neuve avant chaque test."""
        self.stats = ProtocolStats()

    def test_compute_empty(self) -> None:
        """Une capture vide donne un dictionnaire vide."""
        assert self.stats.compute(PacketList([])) == {}

    def test_compute_tcp(self) -> None:
        """Les couches Ethernet, IP et TCP sont toutes comptées."""
        result = self.stats.compute(PacketList([Ether() / IP() / TCP()]))
        assert result == {"Ethernet": 1, "IP": 1, "TCP": 1}

    def test_compute_arp_icmp_dns(self) -> None:
        """ARP, ICMP et DNS sont reconnus."""
        pkts = PacketList(
            [
                Ether() / ARP(),
                Ether() / IP() / ICMP(),
                Ether() / IP() / UDP() / DNS(),
            ]
        )
        result = self.stats.compute(pkts)
        assert result["ARP"] == 1
        assert result["ICMP"] == 1
        assert result["DNS"] == 1
        assert result["Ethernet"] == 3

    def test_compute_counts_http(self) -> None:
        """Une requête GET est comptée comme HTTP."""
        pkt = Ether() / IP() / TCP() / Raw(load=b"GET / HTTP/1.1\r\n\r\n")
        result = self.stats.compute(PacketList([pkt]))
        assert result["HTTP"] == 1
        assert result["TCP"] == 1

    def test_compute_ignores_non_http(self) -> None:
        """Un payload TCP non HTTP n'est pas compté comme HTTP."""
        pkt = Ether() / IP() / TCP() / Raw(load=b"SSH-2.0-OpenSSH_8.2")
        assert "HTTP" not in self.stats.compute(PacketList([pkt]))

    def test_is_http_true(self) -> None:
        """Requête et réponse HTTP sont détectées."""
        get = Ether() / IP() / TCP() / Raw(load=b"POST /login HTTP/1.1\r\n")
        resp = Ether() / IP() / TCP() / Raw(load=b"HTTP/1.1 200 OK\r\n")
        assert ProtocolStats._is_http(get) is True
        assert ProtocolStats._is_http(resp) is True

    def test_is_http_false(self) -> None:
        """Pas de HTTP sans TCP, sans Raw ou avec un autre payload."""
        udp = Ether() / IP() / UDP() / Raw(load=b"GET / HTTP/1.1\r\n")
        no_raw = Ether() / IP() / TCP()
        other = Ether() / IP() / TCP() / Raw(load=b"NOTHTTP")
        assert ProtocolStats._is_http(udp) is False
        assert ProtocolStats._is_http(no_raw) is False
        assert ProtocolStats._is_http(other) is False
