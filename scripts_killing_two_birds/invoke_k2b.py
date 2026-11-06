"""Run the installed Killing Two Birds model on one archive."""

from __future__ import annotations

import argparse
import csv
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--repo", type=Path, default=Path("/home/tkayyy/Malware/KillingTwoBirdswithOneStone"))
    parser.add_argument("--python", dest="python_path", default="/home/tkayyy/Malware/KillingTwoBirdswithOneStone/.venv/bin/python")
    parser.add_argument("--model", type=Path, default=Path("/home/tkayyy/Malware/KillingTwoBirdswithOneStone/outputs/pypi/model-final"))
    args = parser.parse_args()

    archive = args.archive.resolve()
    if not archive.is_file():
        raise SystemExit(f"Archive not found: {archive}")
    with tempfile.TemporaryDirectory(prefix="advpack-k2b-") as temp:
        temp_dir = Path(temp)
        dataset_dir = temp_dir / "dataset"
        dataset_dir.mkdir()
        shutil.copy2(archive, dataset_dir / archive.name)
        sequence_path = temp_dir / "sequences.jsonl"
        predictions_path = temp_dir / "predictions.csv"
        extract = [args.python_path, "scripts/run_pypi_dataset.py", "--dataset-dir", str(dataset_dir), "--out", str(sequence_path), "--label", "1"]
        subprocess.run(extract, cwd=args.repo, check=True, capture_output=True, text=True)
        infer = [args.python_path, "scripts/06_infer.py", str(sequence_path), "--model-dir", str(args.model), "--predictions-out", str(predictions_path), "--device", "cpu"]
        subprocess.run(infer, cwd=args.repo, check=True, capture_output=True, text=True)
        with predictions_path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        if not rows:
            raise RuntimeError("Killing Two Birds produced no prediction")
        row = rows[0]
        score = float(row["prob_malicious"])
        print(f"{score}\t{int(row['pred'])}")


if __name__ == "__main__":
    main()
