#!/usr/bin/env python3
"""Repair FORGE workspace dependency mappings without changing imported sources."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/processed"
FORGE = ROOT / "data/raw/FORGE-Artifacts"
MANIFEST = DATA / "environments/manifest.json"
IMPORT_RE = re.compile(r"\bimport\s+(?:[^\"']+\s+from\s+)?[\"']([^\"']+)[\"']")


def tree_hash(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(path.rglob("*")):
        if item.is_file() and not item.is_symlink():
            digest.update(str(item.relative_to(path)).encode())
            digest.update(hashlib.sha256(item.read_bytes()).digest())
    return digest.hexdigest()


def remappings(root: Path) -> list[str]:
    found: dict[str, Path] = {}
    for package in sorted(root.rglob("openzeppelin")):
        contracts = package / "contracts"
        if contracts.is_dir():
            found.setdefault("@openzeppelin/contracts/", contracts)
            found.setdefault("openzeppelin-solidity/contracts/", contracts)
    for package in sorted(root.rglob("forge-std")):
        source = package / "src"
        if source.is_dir():
            found.setdefault("forge-std/", source)
    for package in sorted(root.rglob("@openzeppelin")):
        if package.is_dir() and (package / "contracts").is_dir():
            found.setdefault("@openzeppelin/", package)
    for package in sorted(root.rglob("hardhat")):
        if package.is_dir() and (package / "console.sol").exists():
            found.setdefault("hardhat/", package)
    for base_name in (".deps", "dependencies", "node_modules", "lib"):
        for base in sorted(root.rglob(base_name)):
            if not base.is_dir():
                continue
            for package in sorted(base.iterdir()):
                if package.is_dir() and package.name.startswith("@"):
                    found.setdefault(package.name + "/", package)
                elif package.is_dir() and (package / "contracts").is_dir():
                    found.setdefault(package.name + "/", package)

    # Audit snapshots frequently vendor a package under a project-specific
    # directory while retaining the package's original import prefix.  Resolve
    # those prefixes from the immutable source tree itself.  This deliberately
    # maps only imports whose exact suffix exists in the snapshot; it never
    # downloads or synthesizes a dependency.
    imports: set[str] = set()
    for source in sorted(root.rglob("*.sol")):
        try:
            imports.update(IMPORT_RE.findall(source.read_text(encoding="utf-8", errors="ignore")))
        except OSError:
            continue
    files_by_suffix: dict[tuple[str, ...], list[Path]] = {}
    for source in sorted(root.rglob("*.sol")):
        rel = source.relative_to(root)
        parts = rel.parts
        for start in range(len(parts)):
            files_by_suffix.setdefault(parts[start:], []).append(source)

    def package_prefix(name: str) -> list[str]:
        parts = name.split("/")
        if name.startswith("@") and len(parts) >= 2:
            return ["/".join(parts[:2]) + "/", parts[0] + "/"]
        return [parts[0] + "/"] if parts else []

    for name in sorted(imports):
        if name.startswith((".", "http://", "https://")):
            continue
        parts = tuple(name.split("/"))
        prefixes = package_prefix(name)
        candidates: list[tuple[int, str, Path]] = []
        for prefix in prefixes:
            suffix = tuple(name[len(prefix):].split("/"))
            for match in files_by_suffix.get(suffix, []):
                target = match
                for _ in suffix:
                    target = target.parent
                candidates.append((len(prefix), prefix, target))
        if candidates:
            _, prefix, target = max(candidates, key=lambda item: item[0])
            found.setdefault(prefix, target)
    return [
        f"{prefix}=source/{package.relative_to(root).as_posix()}/"
        for prefix, package in sorted(found.items())
    ]


def main() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    changed = 0
    for row in manifest["records"]:
        if row.get("dataset") not in {"D_mix", "D_log"} or not row.get("workspace"):
            continue
        workspace = Path(row["workspace"])
        root = Path(row["source_root"] or "")
        if not workspace.is_dir() or not root.is_dir():
            continue
        lines = remappings(root)
        target = workspace / "remappings.txt"
        content = "\n".join(lines) + ("\n" if lines else "")
        existing = target.read_text(encoding="utf-8") if target.exists() else None
        if existing != content:
            target.write_text(content, encoding="utf-8")
            changed += 1
        row["remapping_count"] = len(lines)
        row["workspace_sha256"] = tree_hash(workspace)
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"workspaces_repaired": changed}))


if __name__ == "__main__":
    main()
