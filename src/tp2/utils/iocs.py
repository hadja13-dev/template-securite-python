import ipaddress
import logging
import re

logger = logging.getLogger(__name__)

MIN_LEN = 4

ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LEN)
# Le lookbehind empêche de démarrer sur la fin d'une chaîne ASCII voisine.
UTF16_RE = re.compile(rb"(?<![\x20-\x7e])(?:[\x20-\x7e]\x00){%d,}" % MIN_LEN)

URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Le lookbehind écarte les noms de sections ELF (.data.rel.ro, .gnu.hash...).
DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
    re.IGNORECASE,
)
MUTEX_RE = re.compile(r"\b(?:Global|Local)\\[^\s\"'<>\\]+")
REGISTRY_RE = re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\[^\s\"'<>|]+", re.IGNORECASE)
WIN_PATH_RE = re.compile(r"(?:\b[A-Za-z]:|%[A-Za-z]+%)\\[^\s\"'<>|*?]+")
UNIX_PATH_RE = re.compile(r"(?<![\w/])/(?:tmp|etc|var|usr|home|bin|dev|opt|root)/[^\s\"'<>]*")
FLAG_RE = re.compile(r"^\s*FLAG\s*=\s*(ESGI\{[A-Za-z0-9_]+\})\s*$")

FAKE_TLDS = {
    "dll",
    "exe",
    "sys",
    "bin",
    "dat",
    "tmp",
    "txt",
    "log",
    "ini",
    "cfg",
    "bat",
    "ps1",
    "vbs",
    "js",
    "py",
    "so",
    "pdb",
    "lnk",
    "zip",
    "png",
    "php",
    "html",
    "htm",
    "asp",
    "aspx",
    "jsp",
    "cgi",
    "json",
    "xml",
}
TRAILING = ".,;:)]}'\""


def extract_strings(data: bytes) -> list[str]:
    strings = [s.decode("ascii") for s in ASCII_RE.findall(data)]
    strings += [s.decode("utf-16le") for s in UTF16_RE.findall(data)]
    return strings


def is_valid_ip(candidate: str) -> bool:
    try:
        ipaddress.IPv4Address(candidate)
    except ValueError:
        return False
    return True


def is_valid_domain(candidate: str) -> bool:
    labels = candidate.split(".")
    if any(len(label) < 2 for label in labels):
        return False
    return labels[-1].lower() not in FAKE_TLDS and not is_valid_ip(candidate)


def find_all(pattern: re.Pattern[str], strings: list[str]) -> set[str]:
    found: set[str] = set()
    for text in strings:
        for match in pattern.findall(text):
            found.add(match.rstrip(TRAILING))
    return found


def extract_iocs(data: bytes) -> dict[str, list[str]]:
    strings = extract_strings(data)

    urls = find_all(URL_RE, strings)
    ips = {ip for ip in find_all(IP_RE, strings) if is_valid_ip(ip)}
    domains = {d.lower() for d in find_all(DOMAIN_RE, strings) if is_valid_domain(d)}
    paths = find_all(WIN_PATH_RE, strings) | find_all(UNIX_PATH_RE, strings)

    iocs = {
        "domains": sorted(domains),
        "ips": sorted(ips),
        "urls": sorted(urls),
        "mutex": sorted(find_all(MUTEX_RE, strings)),
        "registry": sorted(find_all(REGISTRY_RE, strings)),
        "paths": sorted(paths),
    }
    logger.info("IOC extraits : %s", {k: len(v) for k, v in iocs.items()})
    return iocs


def extract_flag(strings: list[str]) -> str:
    for text in strings:
        match = FLAG_RE.match(text)
        if match:
            return match.group(1)
    return ""
