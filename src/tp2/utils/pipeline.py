import logging
import re
from pathlib import Path

from tp2.utils.binary import find_suspicious_apis, get_overlay, parse_binary
from tp2.utils.iocs import extract_flag, extract_iocs, extract_strings
from tp2.utils.llm import LLMClient, build_summary, fallback_summary, llm_triage
from tp2.utils.metadata import get_file_metadata
from tp2.utils.report import IOC_KEYS, build_report
from tp2.utils.scoring import combine_scores, compute_score, guess_family, map_mitre
from tp2.utils.yara_scan import load_rules, yara_scan

logger = logging.getLogger(__name__)

FLAG_PATTERN = re.compile(r"ESGI\{[^}]*\}")


def redact_flags(text: str) -> str:
    return FLAG_PATTERN.sub("[flag retiré]", text)


class TriagePipeline:
    def __init__(self, rules_dir: Path | None, client: LLMClient) -> None:
        self.rules = load_rules(rules_dir)
        self.client = client

    def analyze(self, path: Path) -> dict:
        logger.info("Analyse de %s", path.name)
        data = path.read_bytes()
        meta = get_file_metadata(data)
        overlay = get_overlay(data)
        strings = extract_strings(overlay)
        iocs = extract_iocs(overlay)
        binary = parse_binary(path)
        capabilities = find_suspicious_apis(strings)
        matches = yara_scan(data, self.rules)

        # Verdict déterministe : ne dépend d'aucun appel réseau.
        family = guess_family(capabilities, matches)
        mitre = map_mitre(capabilities, iocs, matches)
        base_score = compute_score(iocs, capabilities, matches)

        summary, score = self._ask_llm(meta, iocs, capabilities, matches, family, mitre, base_score, strings)

        apis = {api for found in capabilities.values() for api in found}
        imports = sorted(apis | set(binary["imports"]))
        return build_report(
            meta, iocs, imports, matches, family, mitre, summary, score, extract_flag(strings)
        )

    def _ask_llm(
        self,
        meta: dict,
        iocs: dict[str, list[str]],
        capabilities: dict[str, list[str]],
        matches: list[str],
        family: str,
        mitre: list[str],
        base_score: int,
        strings: list[str],
    ) -> tuple[str, int]:
        facts = {
            "file_type": meta["file_type"],
            "size": meta["size"],
            "entropy": meta["entropy"],
            "iocs": {key: iocs.get(key, []) for key in IOC_KEYS},
            "capabilities": capabilities,
            "yara_matches": matches,
            "family_guess": family,
            "mitre_attack": mitre,
            "deterministic_score": base_score,
        }
        safe_strings = [s for s in strings if "ESGI{" not in s]
        verdict = llm_triage(build_summary(facts, safe_strings), self.client)
        if verdict is None:
            return fallback_summary(family, capabilities, base_score), base_score
        return redact_flags(verdict.summary), combine_scores(base_score, verdict.score)
