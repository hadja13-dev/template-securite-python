"""Point d'entrée des détecteurs."""

from scapy.all import PacketList

from .arp_spoof import ArpSpoofDetector
from .base import Attack, Detector
from .port_scan import PortScanDetector
from .sql_injection import SqlInjectionDetector

__all__ = [
    "ArpSpoofDetector",
    "Attack",
    "Detector",
    "PortScanDetector",
    "SqlInjectionDetector",
    "run_all_detectors",
]


def run_all_detectors(packets: PacketList) -> list[Attack]:
    """Exécute tous les détecteurs et fusionne les résultats sans doublon."""
    detectors: list[Detector] = [
        ArpSpoofDetector(),
        PortScanDetector(),
        SqlInjectionDetector(),
    ]
    seen: set[Attack] = set()
    results: list[Attack] = []
    for det in detectors:
        for attack in det.detect(packets):
            if attack not in seen:
                seen.add(attack)
                results.append(attack)
    return results
