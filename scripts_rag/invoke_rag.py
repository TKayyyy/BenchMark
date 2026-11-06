"""Emit one RAG local-package result as JSON for the benchmark adapter."""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2] / "RAG"
sys.path.insert(0, str(PROJECT_ROOT))

from detector.engine import DetectionEngine  # noqa: E402


if __name__ == "__main__":
    package_path = Path(sys.argv[1]).resolve()
    engine = DetectionEngine()
    if package_path.is_file():
        result = engine.run_on_archive(str(package_path), package_path.name, "dataset")
    else:
        result = engine.run_on_path(str(package_path), package_path.name, "local", dynamic=False)
    print(json.dumps(result, ensure_ascii=False))
