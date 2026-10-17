"""Tests de la classe PacketCapture."""

from pathlib import Path

import pytest
from scapy.all import IP, TCP, Ether, wrpcap

from tp1.utils.capture import PacketCapture, list_interfaces


def test_init_requires_source() -> None:
    with pytest.raises(ValueError):
        PacketCapture()


def test_load_from_pcap(tmp_path: Path) -> None:
    pkt = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP()
    pcap = tmp_path / "t.pcap"
    wrpcap(str(pcap), [pkt, pkt, pkt])
    assert len(PacketCapture(pcap=pcap).load()) == 3


def test_load_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        PacketCapture(pcap=tmp_path / "absent.pcap").load()


def test_list_interfaces() -> None:
    assert isinstance(list_interfaces(), list)
