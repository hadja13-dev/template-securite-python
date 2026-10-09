from scapy.all import (
    ARP,
    DNS,
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    Raw,
    Scapy_Exception,
    rdpcap,
    sniff,
)

from tp1.utils.config import logger

HTTP_START = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"HTTP/")


class Capture:
    def __init__(self, pcap: str | None = None, interface: str | None = None) -> None:
        self.pcap = pcap
        self.interface = interface
        self.packets = []
        self.summary = ""

    def capture_traffic(self) -> None:
        """
        Capture network traffic from a pcap file or from an interface
        """
        try:
            if self.pcap:
                logger.info(f"Read packets from file {self.pcap}")
                self.packets = rdpcap(self.pcap)
            elif self.interface:
                logger.info(f"Capture traffic from interface {self.interface}")
                self.packets = sniff(iface=self.interface, timeout=10)
            else:
                logger.error("No pcap file or interface given")
        except (OSError, Scapy_Exception) as error:
            logger.error(f"Unable to read traffic: {error}")
            self.packets = []
        logger.info(f"{len(self.packets)} packets captured")

    def get_protocol(self, packet) -> list[str]:
        """
        Return the list of protocols found in one packet
        """
        protocols = []
        for name, layer in [
            ("Ethernet", Ether),
            ("ARP", ARP),
            ("IP", IP),
            ("TCP", TCP),
            ("UDP", UDP),
            ("ICMP", ICMP),
            ("DNS", DNS),
        ]:
            if packet.haslayer(layer):
                protocols.append(name)
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            if payload.startswith(HTTP_START):
                protocols.append("HTTP")
        return protocols

    def get_all_protocols(self) -> dict[str, int]:
        """
        Return all protocols captured with total packets number
        """
        counts = {}
        for packet in self.packets:
            for protocol in self.get_protocol(packet):
                counts[protocol] = counts.get(protocol, 0) + 1
        return counts

    def sort_network_protocols(self) -> dict[str, int]:
        """
        Sort protocols from the most to the least frequent
        """
        counts = self.get_all_protocols()
        return dict(sorted(counts.items(), key=lambda item: item[1], reverse=True))