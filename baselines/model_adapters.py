"""Adapters for the four installed detector projects.

The adapters return the same score/detection contract to the benchmark runner.
Paths and model artifacts are configured through environment variables so the
runner does not copy or modify the detector repositories.
"""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Any

from .common import BaselineResult, PackageCase


RAG_ROOT = Path(os.getenv("ADVPACK_RAG_ROOT", "/home/tkayyy/Malware/RAG"))
RAG_PYTHON = os.getenv("ADVPACK_RAG_PYTHON", "/home/tkayyy/Malware/RAG/venv/bin/python")
EMPHUNTER_ROOT = Path(os.getenv("ADVPACK_EMPHUNTER_ROOT", "/home/tkayyy/Malware/EMPHunter/PyPI/EMPHunter-PyPI"))
EMPHUNTER_PYTHON = os.getenv("ADVPACK_EMPHUNTER_PYTHON", "/home/tkayyy/Malware/EMPHunter/.venv/bin/python")
EMPHUNTER_MODEL = os.getenv(
    "ADVPACK_EMPHUNTER_MODEL",
    str(EMPHUNTER_ROOT / "DataShare/local_models/pypi_static_classifier.joblib"),
)
KTB_COMMAND = os.getenv("ADVPACK_KTB_COMMAND", "")
DYSEC_ROOT = Path(os.getenv("ADVPACK_DYSEC_ROOT", "/home/tkayyy/Malware/DySec"))
DYSEC_PYTHON = os.getenv("ADVPACK_DYSEC_PYTHON", str(DYSEC_ROOT / "venv/bin/python"))
DYSEC_COMMAND = os.getenv("ADVPACK_DYSEC_COMMAND", "")


def _result(name: str, started: float, score: float | None, detected: bool | None, status: str = "ok", error: str = "") -> BaselineResult:
    return BaselineResult(name, score, score, detected, detected, (time.perf_counter() - started) * 1000, status, error)


def _run_command(command: list[str], cwd: Path, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)


def _rag_score(path: str) -> tuple[float, bool]:
    if not RAG_ROOT.is_dir():
        raise FileNotFoundError(f"RAG project not found: {RAG_ROOT}")
    helper = Path(__file__).resolve().parent.parent / "scripts_rag" / "invoke_rag.py"
    completed = _run_command([RAG_PYTHON, str(helper), str(Path(path).resolve())], RAG_ROOT)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
    payload: dict[str, Any] = json.loads(completed.stdout)
    analysis = payload.get("analysis", {})
    return float(analysis.get("score", 0)) / 100.0, analysis.get("verdict") in {"MALICIOUS", "SUSPICIOUS"}


def run_rag(case: PackageCase) -> BaselineResult:
    started = time.perf_counter()
    try:
        original, detected_original = _rag_score(case.original_path)
        adversarial, detected_adversarial = _rag_score(case.adversarial_path)
        return BaselineResult("rag", original, adversarial, detected_original, detected_adversarial, (time.perf_counter() - started) * 1000)
    except Exception as exc:
        return _result("rag", started, None, None, "error", f"{type(exc).__name__}: {exc}")


def _emphunter_score(path: str) -> tuple[float, bool]:
    if not EMPHUNTER_MODEL:
        raise RuntimeError("Set ADVPACK_EMPHUNTER_MODEL to a trained .joblib model")
    with tempfile.TemporaryDirectory(prefix="advpack-emphunter-") as temp_dir:
        output = Path(temp_dir) / "prediction.csv"
        completed = _run_command(
            [EMPHUNTER_PYTHON, "local_pipeline.py", "predict", "--model", EMPHUNTER_MODEL, "--input", str(Path(path).resolve()), "--output", str(output)],
            EMPHUNTER_ROOT,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
        with output.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        if not rows:
            raise RuntimeError("EMPHunter returned no prediction rows")
        row = rows[0]
        score = float(row["malicious_score"])
        return score, row["prediction"].lower() == "malicious"


def run_emphunter(case: PackageCase) -> BaselineResult:
    started = time.perf_counter()
    try:
        original, detected_original = _emphunter_score(case.original_path)
        adversarial, detected_adversarial = _emphunter_score(case.adversarial_path)
        return BaselineResult("emphunter", original, adversarial, detected_original, detected_adversarial, (time.perf_counter() - started) * 1000)
    except Exception as exc:
        return _result("emphunter", started, None, None, "error", f"{type(exc).__name__}: {exc}")


def _external_run(name: str, command: str, case: PackageCase) -> BaselineResult:
    started = time.perf_counter()
    if not command:
        return _result(name, started, None, None, "not_configured", f"Set ADVPACK_{name.upper()}_COMMAND")
    try:
        values = {"original": str(Path(case.original_path).resolve()), "adversarial": str(Path(case.adversarial_path).resolve()), "package_id": case.package_id}
        completed = subprocess.run(command.format(**values), shell=True, text=True, capture_output=True, timeout=1800, check=False)
        if completed.returncode != 0:
            return _result(name, started, None, None, "error", completed.stderr.strip() or completed.stdout.strip())
        payload = json.loads(completed.stdout)
        return BaselineResult(name, float(payload["score_original"]), float(payload["score_adversarial"]), bool(payload["detected_original"]), bool(payload["detected_adversarial"]), (time.perf_counter() - started) * 1000)
    except Exception as exc:
        return _result(name, started, None, None, "error", f"{type(exc).__name__}: {exc}")


def run_killing_two_birds(case: PackageCase) -> BaselineResult:
    started = time.perf_counter()
    try:
        helper = Path(__file__).resolve().parent.parent / "scripts_killing_two_birds" / "invoke_k2b.py"
        repo = Path(os.getenv("ADVPACK_KTB_ROOT", "/home/tkayyy/Malware/KillingTwoBirdswithOneStone"))
        python_path = os.getenv("ADVPACK_KTB_PYTHON", str(repo / ".venv/bin/python"))
        model = os.getenv("ADVPACK_KTB_MODEL", str(repo / "outputs/pypi/model-final"))

        def score(path: str) -> tuple[float, bool]:
            completed = _run_command([python_path, str(helper), str(Path(path).resolve()), "--repo", str(repo), "--python", python_path, "--model", model], repo, timeout=900)
            if completed.returncode != 0:
                raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
            score_text, prediction_text = completed.stdout.strip().splitlines()[-1].split("\t")
            return float(score_text), bool(int(prediction_text))

        original, detected_original = score(case.original_path)
        adversarial, detected_adversarial = score(case.adversarial_path)
        return BaselineResult("killing_two_birds", original, adversarial, detected_original, detected_adversarial, (time.perf_counter() - started) * 1000)
    except Exception as exc:
        return _result("killing_two_birds", started, None, None, "error", f"{type(exc).__name__}: {exc}")


def run_dysec(case: PackageCase) -> BaselineResult:
    if DYSEC_COMMAND:
        return _external_run("dysec", DYSEC_COMMAND, case)
    started = time.perf_counter()
    helper = Path(__file__).resolve().parent.parent / "scripts_dysec" / "invoke_dysec.py"

    def trace(path: str) -> dict[str, Any]:
        completed = _run_command(
            [DYSEC_PYTHON, str(helper), str(Path(path).resolve()), "--repo", str(DYSEC_ROOT), "--package-id", case.package_id],
            DYSEC_ROOT,
            timeout=1800,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
        return json.loads(completed.stdout.strip().splitlines()[-1])

    try:
        original = trace(case.original_path)
        adversarial = trace(case.adversarial_path)
        if original.get("model_status") != "ok" or adversarial.get("model_status") != "ok":
            raise RuntimeError("DySec traces collected, but no deployable inference model is configured")
        return BaselineResult("dysec", float(original["score"]), float(adversarial["score"]), bool(original["detected"]), bool(adversarial["detected"]), (time.perf_counter() - started) * 1000)
    except Exception as exc:
        return _result("dysec", started, None, None, "error", f"{type(exc).__name__}: {exc}")
