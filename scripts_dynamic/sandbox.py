"""Docker isolation for dynamic analysis.

This module never runs a sample on the host. Each invocation creates a disposable
container, disables networking, mounts the sample read-only, applies resource and
time limits, and removes the container in ``finally``.
"""

from dataclasses import dataclass
from pathlib import Path
import subprocess
import time


@dataclass(frozen=True)
class SandboxConfig:
    image: str = "advpack-sandbox:latest"
    timeout_seconds: int = 60
    memory: str = "512m"
    cpus: str = "1.0"


def run_sample(sample_path: str, config: SandboxConfig) -> tuple[int, str, float]:
    sample = Path(sample_path).resolve()
    if not sample.is_file():
        raise FileNotFoundError(sample)

    container_name = f"advpack-{sample.stem}-{time.time_ns()}"
    command = [
        "docker", "run", "--name", container_name, "--rm",
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true", "--pids-limit", "64",
        "--memory", config.memory, "--cpus", config.cpus,
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "-v", f"{sample}:/sample/input:ro", config.image,
    ]
    started = time.perf_counter()
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=config.timeout_seconds, check=False)
        return completed.returncode, completed.stdout + completed.stderr, (time.perf_counter() - started) * 1000
    except subprocess.TimeoutExpired as exc:
        return 124, f"sandbox timeout: {exc}", (time.perf_counter() - started) * 1000
    finally:
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, text=True, check=False)
