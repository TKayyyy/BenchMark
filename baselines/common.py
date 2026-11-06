"""Shared contracts for benchmark baseline adapters."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PackageCase:
    package_id: str
    original_path: str
    adversarial_path: str
    level: str = "unknown"
    strategy: str = "unknown"
    seed: str = ""


@dataclass(frozen=True)
class BaselineResult:
    baseline: str
    score_original: float | None
    score_adversarial: float | None
    detected_original: bool | None
    detected_adversarial: bool | None
    latency_ms: float
    status: str = "ok"
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()
