import logging

logger = logging.getLogger(__name__)

SCORE_MIN, SCORE_MAX = 0, 10
LLM_MAX_ADJUST = 1

# Capacité -> technique MITRE ATT&CK
CAPABILITY_TO_MITRE: dict[str, str] = {
    "download": "T1105",  # Ingress Tool Transfer
    "execution": "T1106",  # Native API
    "network": "T1071",  # Application Layer Protocol
    "keylogging": "T1056",  # Input Capture
    "injection": "T1055",  # Process Injection
    "persistence": "T1547",  # Boot or Logon Autostart Execution
    "anti_analysis": "T1622",  # Debugger Evasion
}

# Ordre de priorité : la première capacité trouvée donne la famille.
FAMILY_PRIORITY: list[tuple[str, str]] = [
    ("keylogging", "keylogger"),
    ("download", "dropper"),
    ("network", "backdoor"),
    ("injection", "injector"),
    ("execution", "trojan"),
]


def is_packed(yara_matches: list[str]) -> bool:
    return "High_Entropy_Tail" in yara_matches


def guess_family(capabilities: dict[str, list[str]], yara_matches: list[str]) -> str:
    for capability, family in FAMILY_PRIORITY:
        if capability in capabilities:
            return family
    if is_packed(yara_matches):
        return "packed"
    return "unknown"


def map_mitre(
    capabilities: dict[str, list[str]],
    iocs: dict[str, list[str]],
    yara_matches: list[str],
) -> list[str]:
    """Associe capacités et IOC à des techniques MITRE ATT&CK."""
    techniques = {CAPABILITY_TO_MITRE[c] for c in capabilities if c in CAPABILITY_TO_MITRE}
    if iocs.get("urls") or iocs.get("domains"):
        techniques.add("T1071")
    if any("\\Run" in key for key in iocs.get("registry", [])):
        techniques.add("T1547")
    if is_packed(yara_matches):
        techniques.add("T1027")  # Obfuscated Files or Information
    return sorted(techniques)


def clamp(value: int) -> int:
    return max(SCORE_MIN, min(SCORE_MAX, value))


def compute_score(
    iocs: dict[str, list[str]],
    capabilities: dict[str, list[str]],
    yara_matches: list[str],
) -> int:
    score = sum(1 for key in ("domains", "ips", "urls", "mutex", "registry") if iocs.get(key))
    score += min(len(capabilities), 3)
    if is_packed(yara_matches):
        score += 2
    if "Prompt_Injection_Text" in yara_matches:
        score += 1  # tenter de tromper l'analyse est en soi suspect
    return clamp(score)


def combine_scores(deterministic: int, llm_score: int | None) -> int:
    if llm_score is None:
        return clamp(deterministic)
    delta = max(-LLM_MAX_ADJUST, min(LLM_MAX_ADJUST, llm_score - deterministic))
    final = clamp(deterministic + delta)
    logger.info("Score : déterministe=%d, LLM=%d, final=%d", deterministic, llm_score, final)
    return final
