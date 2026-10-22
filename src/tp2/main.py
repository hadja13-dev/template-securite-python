import argparse
from pathlib import Path

from tp2.utils.config import logger
from tp2.utils.llm import LLMClient
from tp2.utils.pipeline import TriagePipeline
from tp2.utils.report import generate_report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Triage automatisé de malware")
    parser.add_argument("--samples", type=Path, required=True, help="dossier des échantillons")
    parser.add_argument("--rules", type=Path, default=None, help="dossier des règles YARA")
    parser.add_argument("--out", type=Path, required=True, help="dossier de sortie (JSON)")
    return parser.parse_args(argv)


def list_samples(samples_dir: Path) -> list[Path]:
    return sorted(path for path in samples_dir.iterdir() if path.is_file() and not path.name.startswith("."))


def run(samples_dir: Path, rules_dir: Path | None, out_dir: Path, client: LLMClient) -> int:
    pipeline = TriagePipeline(rules_dir, client)
    analysed = 0
    for path in list_samples(samples_dir):
        try:
            generate_report(pipeline.analyze(path), out_dir, path)
            analysed += 1
        except Exception:  # noqa: BLE001 - un fichier imprévu ne doit pas bloquer les autres
            logger.exception("Échec de l'analyse de %s", path.name)
    logger.info("%d échantillon(s) analysé(s)", analysed)
    return analysed


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    run(args.samples, args.rules, args.out, LLMClient())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
