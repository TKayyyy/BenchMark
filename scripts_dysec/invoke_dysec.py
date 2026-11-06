#!/usr/bin/env python3
"""Collect DySec traces for one local archive and emit a JSON result."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time


def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2] / "DySec")
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--package-id", default="archive")
    args = parser.parse_args()

    repo = args.repo.resolve()
    archive = args.archive.resolve()
    if not archive.is_file():
        raise SystemExit(f"archive not found: {archive}")
    if os.geteuid() != 0:
        raise SystemExit("DySec eBPF collection must run as root; use sudo for the pilot command")
    if args.duration < 1:
        raise SystemExit("--duration must be >= 1")

    slug = "dysec-" + "".join(c if c.isalnum() or c in "-_" else "_" for c in args.package_id)
    trace_dirs = {
        "filetop": repo / "Filetop Traces",
        "opensnoop": repo / "Opensnoop Traces",
        "tcp": repo / "TCP Traces",
        "install": repo / "Installation_status",
    }
    for directory in trace_dirs.values():
        directory.mkdir(parents=True, exist_ok=True)
    outputs = repo / "Trace_Outputs" / slug
    shutil.rmtree(outputs, ignore_errors=True)
    venv = repo / "Environments" / f"{slug}_env"
    shutil.rmtree(venv, ignore_errors=True)

    python = sys.executable
    subprocess.run([python, "-m", "venv", str(venv)], cwd=repo, check=True)
    pip = venv / "bin" / "pip"
    install_log = trace_dirs["install"] / f"{slug}_install_log.txt"
    probes: list[subprocess.Popen[str]] = []
    monitor = None
    try:
        monitor = subprocess.Popen(["bash", "scripts/monitor.sh", slug], cwd=repo, text=True)
        probes = [
            subprocess.Popen(["filetop-bpfcc", "5"], cwd=repo, stdout=(trace_dirs["filetop"] / f"{slug}_filetop_trace.txt").open("w")),
            subprocess.Popen(["opensnoop-bpfcc", "-d", str(args.duration)], cwd=repo, stdout=(trace_dirs["opensnoop"] / f"{slug}_opensnoop_trace.txt").open("w")),
            subprocess.Popen(["tcpstates-bpfcc"], cwd=repo, stdout=(trace_dirs["tcp"] / f"{slug}_tcptraces.txt").open("w")),
        ]
        install = subprocess.run(
            [str(pip), "install", "--no-cache-dir", str(archive)],
            cwd=repo, text=True, capture_output=True, check=False,
        )
        install_log.write_text(install.stdout + install.stderr, encoding="utf-8")
        if install.returncode != 0:
            raise RuntimeError(f"local archive installation failed; see {install_log}")
        time.sleep(args.duration)
    finally:
        for process in probes:
            stop_process(process)
        stop_process(monitor)

    aggregate = subprocess.run([python, "scripts/aggregate_traces.py", slug], cwd=repo, text=True, capture_output=True, check=False)
    if aggregate.returncode != 0:
        raise RuntimeError(aggregate.stderr.strip() or aggregate.stdout.strip() or "trace aggregation failed")

    print(json.dumps({
        "status": "traced",
        "package_id": args.package_id,
        "trace_package": slug,
        "features": str(outputs / "trace_statistics_with_advanced_patterns.csv"),
        "install_log": str(install_log),
        "model_status": "unavailable",
    }))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"status": "error", "error": f"{type(exc).__name__}: {exc}"}))
        raise SystemExit(1)