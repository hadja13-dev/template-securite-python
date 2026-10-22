import logging
from pathlib import Path

import yara

from tp2.utils.custom_rules import CUSTOM_RULES

logger = logging.getLogger(__name__)

RULE_EXTENSIONS = {".yar", ".yara"}


def find_rule_files(rules_dir: Path) -> dict[str, str]:
    if not rules_dir.is_dir():
        logger.warning("Dossier de règles introuvable : %s", rules_dir)
        return {}
    return {
        path.stem: str(path)
        for path in sorted(rules_dir.rglob("*"))
        if path.suffix.lower() in RULE_EXTENSIONS
    }


def load_rules(rules_dir: Path | None = None) -> list[yara.Rules]:
    compiled = [yara.compile(source=CUSTOM_RULES)]
    if rules_dir is None:
        return compiled
    for namespace, path in find_rule_files(rules_dir).items():
        try:
            compiled.append(yara.compile(filepaths={namespace: path}))
        except yara.Error as exc:
            logger.error("Règle invalide ignorée (%s) : %s", path, exc)
    logger.info("%d jeux de règles compilés", len(compiled))
    return compiled


def yara_scan(data: bytes, rules: list[yara.Rules]) -> list[str]:
    matches: set[str] = set()
    for ruleset in rules:
        matches.update(match.rule for match in ruleset.match(data=data, timeout=30))
    return sorted(matches)
