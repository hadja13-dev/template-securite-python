"""Tests du point d'entrée CLI."""

import json
from pathlib import Path

import pytest
from scapy.all import ARP, IP, TCP, Ether, Raw, wrpcap

from tp1.main import main, parse_args

MAC_A = "02:00:00:00:00:01"
MAC_B = "02:00:00:00:00:02"


def test_parse_args_defaults() -> None:
    """--out vaut report.json par défaut."""
    args = parse_args(["--pcap", "x.pcap"])
    assert args.pcap == Path("x.pcap")
    assert args.out == Path("report.json")


def test_parse_args_requires_source() -> None:
    """Sans --pcap ni --iface, argparse refuse."""
    with pytest.raises(SystemExit):
        parse_args([])


def test_main_end_to_end(tmp_path: Path) -> None:
    """main détecte les trois attaques et le flag dans un PCAP."""
    eth = Ether(src=MAC_A, dst=MAC_B)
    pkts = [eth / IP(src="10.0.0.5", dst="10.0.0.1") / TCP(flags="S", dport=p) for p in range(20)]
    pkts.append(
        eth
        / IP(src="10.0.0.9", dst="10.0.0.1")
        / TCP(dport=80)
        / Raw(load=b"GET /?id=1' OR 1=1--&f=ESGI{test} HTTP/1.1\r\n\r\n")
    )
    pkts += [
        eth / ARP(op=1, hwsrc=MAC_A, psrc="10.0.0.3", pdst="10.0.0.1"),
        eth / ARP(op=2, hwsrc="aa:aa:aa:aa:aa:aa", psrc="10.0.0.1", pdst="10.0.0.3"),
        eth / ARP(op=2, hwsrc="bb:bb:bb:bb:bb:bb", psrc="10.0.0.1", pdst="10.0.0.3"),
        eth / ARP(op=2, hwsrc="bb:bb:bb:bb:bb:bb", psrc="10.0.0.2", pdst="10.0.0.3"),
    ]
    pcap = tmp_path / "t.pcap"
    wrpcap(str(pcap), pkts)
    out = tmp_path / "r.json"

    assert main(["--pcap", str(pcap), "--out", str(out)]) == 0

    data = json.loads(out.read_text(encoding="utf-8"))
    assert {a["type"] for a in data["attacks"]} == {
        "arp_spoofing",
        "port_scan",
        "sql_injection",
    }
    assert data["flag"] == "ESGI{test}"
    assert out.with_suffix(".pdf").exists()
