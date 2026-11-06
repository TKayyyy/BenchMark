"""Build a benchmark manifest by pairing AdvPack archives with originals."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

ARCHIVES = ("*.tar.gz", "*.tgz", "*.tar", "*.whl", "*.zip")


def archives(root: Path) -> list[Path]:
    paths: list[Path] = []
    for pattern in ARCHIVES:
        paths.extend(root.rglob(pattern))
    return sorted({path.resolve() for path in paths})


def pair_original(archive: Path, original_root: Path) -> Path | None:
    # AdvPack layout: .../<package>/<version>/<archive>.
    if len(archive.parts) < 3:
        return None
    version, package_name = archive.parent.name, archive.parent.parent.name
    candidates = []
    for label_root in (original_root / "benign", original_root / "malicious"):
        candidates.extend((label_root / package_name / version).glob("*"))
    candidates = [path for path in candidates if path.is_file() and path.name.lower().endswith(tuple(ext[1:] for ext in (".tar.gz", ".tgz", ".tar", ".whl", ".zip")))]
    if not candidates:
        return None
    exact = [path for path in candidates if path.name == archive.name]
    return exact[0] if exact else candidates[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", type=Path, required=True, help="AdvPack root containing levels/ or strategies/")
    parser.add_argument("--original-root", type=Path, required=True, help="Directory containing original package archives")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--level", default="all", help="Optional level folder, e.g. l1-syntax-encoding")
    parser.add_argument("--strategy", default="all", help="Optional strategy folder, e.g. s9-time-segmentation")
    args = parser.parse_args()

    dataset_root = args.dataset_root.resolve()
    original_root = args.original_root.resolve()
    roots = [dataset_root / "levels", dataset_root / "strategies"]
    candidates = [path for root in roots for path in archives(root)]
    candidates = sorted(set(candidates))
    if args.level != "all":
        candidates = [path for path in candidates if args.level in path.parts]
    if args.strategy != "all":
        candidates = [path for path in candidates if args.strategy in path.parts]

    rows = []
    missing = []
    for index, adversarial in enumerate(candidates, start=1):
        original = pair_original(adversarial, original_root)
        if original is None:
            missing.append(str(adversarial))
            continue
        parts = adversarial.parts
        level = next((part for part in parts if part.startswith(("l1-", "l2-", "l3-", "l4-"))), "unknown")
        strategy = next((part for part in parts if len(part) > 2 and part[0] == "s" and part[1].isdigit() and "-" in part), "unknown")
        rows.append({
            "package_id": f"{adversarial.parent.parent.name}-{index:05d}",
            "original_path": str(original),
            "adversarial_path": str(adversarial),
            "level": level,
            "strategy": strategy,
            "seed": "",
        })

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["package_id", "original_path", "adversarial_path", "level", "strategy", "seed"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote={len(rows)} missing_original={len(missing)} output={args.output}")
    if missing:
        print("First missing pairs:")
        print("\n".join(missing[:10]))


if __name__ == "__main__":
    main()
