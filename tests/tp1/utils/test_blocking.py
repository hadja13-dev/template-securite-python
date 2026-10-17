from tp1.utils.blocking import blocking_rule
from tp1.utils.detection.base import Attack


def test_blocking_rule_mac() -> None:
    rule = blocking_rule(Attack(type="arp_spoofing", attacker="aa:bb:cc:dd:ee:ff"))
    assert rule == "iptables -A INPUT -m mac --mac-source aa:bb:cc:dd:ee:ff -j DROP"


def test_blocking_rule_ipv4() -> None:
    rule = blocking_rule(Attack(type="port_scan", attacker="10.0.0.5"))
    assert rule == "iptables -A INPUT -s 10.0.0.5 -j DROP"


def test_blocking_rule_ipv6() -> None:
    rule = blocking_rule(Attack(type="port_scan", attacker="fe80::1:2:3:4:5:6"))
    assert rule.startswith("ip6tables")
