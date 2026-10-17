"""Fixtures partagées : paquets fabriqués en mémoire."""

import pytest
from scapy.all import ARP, IP, TCP, Ether, Raw


@pytest.fixture
def arp_spoof_packets() -> list:
    """Une IP annoncée par deux MAC, dont une réponse non sollicitée."""
    attacker_mac = "11:22:33:44:55:66"
    legit_mac = "aa:bb:cc:dd:ee:01"
    return [
        # Attaquant revendique la passerelle
        Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc=attacker_mac),
        # Attaquant revendique aussi la victime (MITM multi-IP)
        Ether() / ARP(op=2, psrc="192.168.1.100", hwsrc=attacker_mac),
        # Réponse légitime (pour bruit)
        Ether() / ARP(op=1, pdst="192.168.1.1"),
        Ether() / ARP(op=2, psrc="192.168.1.1", hwsrc=legit_mac),
    ]


@pytest.fixture
def port_scan_packets() -> list:
    """20 SYN d'une même source vers 20 ports différents."""
    return [Ether() / IP(src="10.0.0.99") / TCP(dport=p, flags="S") for p in range(20)]


@pytest.fixture
def sqli_packets() -> list:
    """Une requête GET contenant ' OR 1=1 encodé en URL et un flag."""
    payload = (
        "GET /login?user=admin%27%20OR%201%3D1-- HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "X-Flag: FLAG{sqli_detected_42}\r\n"
        "\r\n"
    )
    return [
        Ether() / IP(src="10.0.0.50") / TCP(dport=80) / Raw(load=payload.encode()),
    ]
