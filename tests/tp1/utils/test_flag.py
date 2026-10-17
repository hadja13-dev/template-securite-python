"""Tests de la classe FlagFinder."""

from scapy.all import IP, TCP, Ether, PacketList, Raw

from tp1.utils.flag import FlagFinder


def _pkt(src: str, payload: bytes) -> Ether:
    """Construit un paquet TCP avec un payload."""
    return Ether() / IP(src=src) / TCP() / Raw(load=payload)


def test_pkt_helper() -> None:
    """Le helper garde l'IP source et le payload."""
    pkt = _pkt("10.0.0.1", b"abc")
    assert pkt[IP].src == "10.0.0.1"
    assert pkt[Raw].load == b"abc"


def test_init_compiles_pattern() -> None:
    """Le motif compilé reconnaît un flag."""
    assert FlagFinder().pattern.search("x ESGI{abc} y") is not None


def test_find_prefers_attacker() -> None:
    """Le flag de l'attaquant l'emporte sur un leurre."""
    pkts = PacketList(
        [
            _pkt("10.0.0.1", b"ESGI{leurre}"),
            _pkt("10.0.0.9", b"GET /?f=ESGI%7Bvrai%7D HTTP/1.1"),
        ]
    )
    assert FlagFinder().find(pkts, {"10.0.0.9"}) == "ESGI{vrai}"


def test_find_fallback() -> None:
    """Sans attaquant connu, le premier flag est retourné."""
    pkts = PacketList([_pkt("10.0.0.1", b"ESGI{premier}")])
    assert FlagFinder().find(pkts) == "ESGI{premier}"


def test_find_none() -> None:
    """Aucun flag dans la capture donne None."""
    pkts = PacketList([_pkt("10.0.0.1", b"GET / HTTP/1.1")])
    assert FlagFinder().find(pkts) is None
