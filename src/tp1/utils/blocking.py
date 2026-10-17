import re

from .detection.base import Attack

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)


def blocking_rule(attack: Attack) -> str:
    src = attack.attacker
    if MAC_RE.match(src):
        return f"iptables -A INPUT -m mac --mac-source {src} -j DROP"
    if ":" in src:
        return f"ip6tables -A INPUT -s {src} -j DROP"
    return f"iptables -A INPUT -s {src} -j DROP"
