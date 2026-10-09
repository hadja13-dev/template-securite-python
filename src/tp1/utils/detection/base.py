"""Contrat commun des détecteurs."""

from abc import ABC, abstractmethod
from dataclasses import dataclass

from scapy.all import PacketList


@dataclass(frozen=True)
class Attack:
    """Une attaque détectée."""

    type: str
    attacker: str


class Detector(ABC):
    """Classe de base de tous les détecteurs."""

    @abstractmethod
    def detect(self, packets: PacketList) -> list[Attack]:
        """Analyse les paquets et retourne les attaques trouvées."""