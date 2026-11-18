from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASETS = ROOT / "datasets"
EXPECTED = {"D_tra": 184, "D_mix": 121, "D_log": 122, "D_inc": 123, "D_cve": 18}
FORBIDDEN_NAMES = ("reference-poc", "exploit.t.sol", "replay.json")
FORBIDDEN_SOURCE_PARTS = ("test", "mock", "echidna", "fuzz")
FORBIDDEN_SIGNATURES = (
    "contract Exploit",
    "function testExploit",
    "vm.prank(",
    "createSelectFork(",
)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def main() -> None:
    manifest = json.loads((DATASETS / "manifest.json").read_text(encoding="utf-8"))
    if manifest["datasets"] != EXPECTED or manifest["case_count"] != sum(EXPECTED.values()):
        raise SystemExit("dataset partition counts do not match the published manifest")

    actual: Counter[str] = Counter()
    for bundle_path in DATASETS.glob("*/cases/*/bundle.json"):
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        actual[bundle["dataset"]] += 1
    if dict(actual) != EXPECTED:
        raise SystemExit(f"dataset case counts are invalid: {dict(actual)}")

    links = [path for path in DATASETS.rglob("*") if path.is_symlink()]
    if links:
        raise SystemExit(f"published datasets contain symbolic links: {links[0]}")

    forbidden = [
        path
        for path in DATASETS.rglob("*")
        if path.is_file() and any(marker in path.name.lower() for marker in FORBIDDEN_NAMES)
    ]
    if forbidden:
        raise SystemExit(f"published datasets contain a forbidden artifact: {forbidden[0]}")

    unsafe_sources = []
    for path in DATASETS.rglob("*.sol"):
        relative_parts = [part.lower() for part in path.relative_to(DATASETS).parts]
        if path.name.lower().endswith(".t.sol") or any(
            marker in part for part in relative_parts for marker in FORBIDDEN_SOURCE_PARTS
        ):
            unsafe_sources.append(path)
            continue
        content = path.read_text(encoding="utf-8", errors="ignore")
        if any(signature.lower() in content.lower() for signature in FORBIDDEN_SIGNATURES):
            unsafe_sources.append(path)
    if unsafe_sources:
        raise SystemExit(f"published datasets contain test/PoC-like source: {unsafe_sources[0]}")

    inventory = json.loads((DATASETS / "checksums.json").read_text(encoding="utf-8"))
    listed_paths = {item["path"] for item in inventory}
    if len(listed_paths) != len(inventory):
        raise SystemExit("checksum inventory contains duplicate paths")
    actual_paths = {
        path.relative_to(DATASETS).as_posix()
        for path in DATASETS.rglob("*")
        if path.is_file() and path.name != "checksums.json"
    }
    if listed_paths != actual_paths:
        missing = sorted(listed_paths - actual_paths)
        unlisted = sorted(actual_paths - listed_paths)
        raise SystemExit(
            f"checksum inventory mismatch: missing={missing[:1]}, unlisted={unlisted[:1]}"
        )
    for item in inventory:
        path = DATASETS / item["path"]
        if (
            not path.is_file()
            or path.stat().st_size != item["bytes"]
            or digest(path) != item["sha256"]
        ):
            raise SystemExit(f"checksum verification failed: {item['path']}")

    print(
        "release verification: "
        f"{sum(actual.values())} cases, {len(inventory)} payload files, "
        "0 symlinks, 0 generated/reference PoCs"
    )


if __name__ == "__main__":
    main()
