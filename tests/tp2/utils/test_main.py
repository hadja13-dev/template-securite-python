"""Tests du point d'entrée en ligne de commande."""

import json
from pathlib import Path

import pytest

from tp2.main import list_samples, main, parse_args, run
from tp2.utils.llm import LLMClient

SAMPLE = b"\x00http://c2.bad.test/gate.php\x00FLAG=ESGI{vrai_1}\x00"


def make_samples(tmp_path: Path) -> Path:
    """Crée un dossier avec un échantillon et un fichier caché à ignorer."""
    samples = tmp_path / "samples"
    samples.mkdir()
    (samples / "a.bin").write_bytes(SAMPLE)
    (samples / ".cache").write_bytes(b"ignore")
    return samples


def test_parse_args() -> None:
    """Les options --samples, --rules et --out sont lues comme des chemins."""
    args = parse_args(["--samples", "s", "--rules", "r", "--out", "o"])
    assert args.samples == Path("s")
    assert args.rules == Path("r")


def test_list_samples_ignore_fichiers_caches(tmp_path: Path) -> None:
    """Les fichiers cachés ne sont pas analysés."""
    assert [p.name for p in list_samples(make_samples(tmp_path))] == ["a.bin"]


def test_run_ecrit_un_json_par_echantillon(tmp_path: Path) -> None:
    """Le fichier <nom>.triage.json attendu par la correction est produit."""
    out = tmp_path / "out"
    assert run(make_samples(tmp_path), None, out, LLMClient("offline")) == 1
    report = json.loads((out / "a.triage.json").read_text(encoding="utf-8"))
    assert report["flag"] == "ESGI{vrai_1}"


def test_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """La commande complète fonctionne hors ligne."""
    monkeypatch.setenv("LLM_BACKEND", "offline")
    out = tmp_path / "out"
    argv = ["--samples", str(make_samples(tmp_path)), "--out", str(out)]
    assert main(argv) == 0
    assert (out / "a.bin.triage.json").exists()
