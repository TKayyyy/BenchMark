"""Concurrent AdvPack benchmark runner with crash-resilient CSV output."""

import argparse
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import threading
import time

from baselines.common import BaselineResult, PackageCase
from baselines.model_adapters import run_dysec, run_emphunter, run_killing_two_birds, run_rag
from scripts_dynamic.sandbox import SandboxConfig

BASELINES = {
    "rag": run_rag,
    "emphunter": run_emphunter,
    "killing_two_birds": run_killing_two_birds,
    "dysec": run_dysec,
}
CSV_FIELDS = [
    "package_id", "baseline", "level", "strategy", "seed", "original_path", "adversarial_path",
    "score_original", "score_adversarial", "detected_original", "detected_adversarial",
    "latency_ms", "status", "error", "completed_at",
]


def read_manifest(path: Path) -> list[PackageCase]:
    with path.open(newline="", encoding="utf-8") as stream:
        if path.suffix.lower() == ".jsonl":
            import json
            return [PackageCase(**json.loads(line)) for line in stream if line.strip()]
        return [
            PackageCase(
                package_id=row["package_id"], original_path=row["original_path"],
                adversarial_path=row["adversarial_path"], level=row.get("level", "unknown"),
                strategy=row.get("strategy", "unknown"), seed=row.get("seed", ""),
            )
            for row in csv.DictReader(stream)
        ]


def write_result(stream: csv.DictWriter, lock: threading.Lock, case: PackageCase, result: BaselineResult) -> None:
    row = {
        **case.__dict__, **result.as_dict(), "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    with lock:
        stream.writerow(row)


def execute(case: PackageCase, baseline_name: str, dry_run: bool, sandbox: SandboxConfig) -> BaselineResult:
    started = time.perf_counter()
    if dry_run:
        return BaselineResult(baseline_name, None, None, None, None, (time.perf_counter() - started) * 1000, "dry_run", "")
    runner = BASELINES[baseline_name]
    return runner(case)


def _completed_jobs(output: Path) -> set[tuple[str, str]]:
    if not output.exists() or output.stat().st_size == 0:
        return set()
    with output.open(newline="", encoding="utf-8") as stream:
        return {(row["package_id"], row["baseline"]) for row in csv.DictReader(stream) if row.get("status") == "ok"}


def run(manifest: Path, output: Path, workers: int, selected: list[str], dry_run: bool, sandbox: SandboxConfig, skip_existing: bool = False, only_ok: bool = False) -> None:
    cases = read_manifest(manifest)
    output.parent.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()
    completed_jobs = _completed_jobs(output) if skip_existing else set()
    with output.open("a+", newline="", encoding="utf-8", buffering=1) as stream:
        stream.seek(0)
        has_header = bool(stream.read(1))
        stream.seek(0, 2)
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS, extrasaction="ignore")
        if not has_header:
            writer.writeheader()
            stream.flush()
        jobs = [(case, baseline) for case in cases for baseline in selected if (case.package_id, baseline) not in completed_jobs]
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="advpack") as pool:
            futures = {pool.submit(execute, case, baseline, dry_run, sandbox): (case, baseline) for case, baseline in jobs}
            for future in as_completed(futures):
                case, baseline = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = BaselineResult(baseline, None, None, None, None, 0.0, "error", f"{type(exc).__name__}: {exc}")
                if not only_ok or result.status == "ok":
                    write_result(writer, lock, case, result)
                    stream.flush()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("results/benchmark_results.csv"))
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--baselines", nargs="+", choices=sorted(BASELINES), default=sorted(BASELINES))
    parser.add_argument("--dry-run", action="store_true", help="Validate dispatch and CSV output without running analyzers")
    parser.add_argument("--skip-existing", action="store_true", help="Resume an output file without repeating completed ok jobs")
    parser.add_argument("--only-ok", action="store_true", help="Write only successful model results to the output CSV")
    parser.add_argument("--sandbox-image", default="advpack-sandbox:latest")
    parser.add_argument("--sandbox-timeout", type=int, default=60)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.workers < 1:
        raise SystemExit("--workers must be >= 1")
    run(args.manifest, args.output, args.workers, args.baselines, args.dry_run, SandboxConfig(args.sandbox_image, args.sandbox_timeout), args.skip_existing, args.only_ok)
