#!/usr/bin/env python3
"""Construct isolated Foundry workspaces and run reproducible source preflight."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

from solidity_toolchain import resolve

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/processed"
FORGE = ROOT / "data/raw/FORGE-Artifacts"
DEFI = ROOT / "data/raw/DeFiHackLabs"
OUT = DATA / "environments"
WORKSPACES = OUT / "workspaces"
IMPORT_RE = re.compile(r"\bimport\s+(?:[^\"']+\s+from\s+)?[\"']([^\"']+)[\"']")


def run(cmd: list[str], cwd: Path) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=45)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 124, str(exc)
    output = (p.stdout + "\n" + p.stderr).strip()
    return p.returncode, output[-3000:]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_hash(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(path.rglob("*")):
        if item.is_file() and not item.is_symlink():
            digest.update(str(item.relative_to(path)).encode())
            digest.update(sha256_file(item).encode())
    return digest.hexdigest()


def project_remappings(root: Path) -> list[str]:
    """Expose dependency directories shipped inside an immutable FORGE project."""
    mappings: dict[str, Path] = {}
    # A number of audit snapshots vendor libraries below ``contracts`` rather
    # than using a top-level lib/node_modules directory.  Foundry resolves
    # package imports from the workspace root, so expose those package roots as
    # well.  The mapping is derived from the actual import namespace and never
    # substitutes an external dependency.
    for package in root.rglob("openzeppelin"):
        contracts = package / "contracts"
        if contracts.is_dir():
            mappings.setdefault("@openzeppelin/contracts/", contracts)
            mappings.setdefault("openzeppelin-solidity/contracts/", contracts)
    for package in root.rglob("forge-std"):
        source = package / "src"
        if source.is_dir():
            mappings.setdefault("forge-std/", source)
    for package in root.rglob("hardhat"):
        if package.is_dir() and (package / "console.sol").exists():
            mappings.setdefault("hardhat/", package)
    for package in root.rglob("@openzeppelin"):
        if package.is_dir():
            mappings.setdefault("@openzeppelin/", package)
    for base_name in (".deps", "dependencies", "node_modules", "lib"):
        for base in root.rglob(base_name):
            if not base.is_dir():
                continue
            for package in base.iterdir():
                if package.is_dir() and package.name.startswith("@"):
                    mappings.setdefault(package.name + "/", package)
                elif package.is_dir() and (package / "contracts").is_dir():
                    mappings.setdefault(package.name + "/", package)
    imports: set[str] = set()
    for source in sorted(root.rglob("*.sol")):
        try:
            imports.update(IMPORT_RE.findall(source.read_text(encoding="utf-8", errors="ignore")))
        except OSError:
            continue
    files_by_suffix: dict[tuple[str, ...], list[Path]] = {}
    for source in sorted(root.rglob("*.sol")):
        parts = source.relative_to(root).parts
        for start in range(len(parts)):
            files_by_suffix.setdefault(parts[start:], []).append(source)
    for name in sorted(imports):
        if name.startswith((".", "http://", "https://")):
            continue
        parts = name.split("/")
        prefixes = (
            ["/".join(parts[:2]) + "/", parts[0] + "/"]
            if name.startswith("@") and len(parts) >= 2
            else [parts[0] + "/"]
        )
        candidates: list[tuple[int, str, Path]] = []
        for prefix in prefixes:
            suffix = tuple(name[len(prefix) :].split("/"))
            for match in files_by_suffix.get(suffix, []):
                target = match
                for _ in suffix:
                    target = target.parent
                candidates.append((len(prefix), prefix, target))
        if candidates:
            _, prefix, target = max(candidates, key=lambda item: item[0])
            mappings.setdefault(prefix, target)
    lines = []
    for prefix, package in sorted(mappings.items()):
        try:
            relative = package.relative_to(root)
        except ValueError:
            continue
        lines.append(f"{prefix}=source/{relative.as_posix()}/")
    # Keep direct source-relative imports working after the project is copied
    # into the isolated workspace.  The target is the project root itself and
    # is only used for imports that already name a relative repository path.
    return lines


def build_workspace(workspace: Path, target: Path | None = None) -> tuple[int, str, str, dict]:
    solc, closure, missing, pragmas = resolve(workspace, target) if target else (None, [], [], [])
    command = ["forge", "build", "--offline", "--no-cache"]
    if solc and solc.exists():
        command += ["--use", str(solc)]
    if target is not None:
        command.append(str(target.relative_to(workspace)))
    code, output = run(command, workspace)
    resolution = {
        "compiler": str(solc) if solc else None,
        "closure_file_count": len(closure),
        "missing_imports": missing,
        "pragmas": pragmas,
    }
    return code, output, " ".join(command), resolution


def forge_candidate(record_id: str) -> dict | None:
    cid = "forge-" + record_id.split("-forge-", 1)[-1]
    for line in (DATA / "forge/candidates.jsonl").open():
        item = json.loads(line)
        if item["candidate_id"] == cid:
            return item
    return None


def prepare_inc(record: dict) -> dict:
    source = DEFI / record["source_file"]
    workspace = WORKSPACES / record["record_id"]
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True)
    (workspace / "source-root.txt").write_text(str(DEFI.resolve()) + "\n", encoding="utf-8")
    (workspace / "foundry.toml").write_text(
        "[profile.default]\n"
        "src = 'src'\n"
        "out = 'out'\n"
        "libs = ['lib']\n"
        "evm_version = 'shanghai'\n"
        "offline = true\n",
        encoding="utf-8",
    )
    # Copy the pinned source tree into the isolated workspace.  Symlinking the
    # repository made Foundry reject imports as "outside allowed directories"
    # and made the environment digest depend on paths outside the workspace.
    shutil.copytree(DEFI / "src", workspace / "src")
    shutil.copytree(DEFI / "lib", workspace / "lib")
    (workspace / "remappings.txt").write_text("forge-std/=lib/forge-std/src/\n", encoding="utf-8")
    target = workspace / record["source_file"]
    code, output, command, resolution = build_workspace(workspace, target)
    return {
        "record_id": record["record_id"],
        "dataset": record["dataset"],
        "source_root": str(DEFI.resolve()),
        "source_file": record["source_file"],
        "workspace": str(workspace.resolve()),
        "source_exists": source.is_file(),
        "fork_block": record["fixed_fork_block"],
        "status": (
            "COMPILE_OK"
            if code == 0 and source.is_file()
            else "COMPILE_PENDING"
            if source.is_file()
            else "SOURCE_MISSING"
        ),
        "exit_code": code,
        "output": output,
        "compile_command": command,
        "compile_evidence": "case_level_forge_build",
        "source_sha256": sha256_file(source),
        "workspace_sha256": tree_hash(workspace),
        "compiler_resolution": resolution,
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    WORKSPACES.mkdir(parents=True, exist_ok=True)
    records = [
        json.loads(p.read_text()) for p in sorted((DATA / "evaluation/records").glob("*.json"))
    ]
    rows = []
    inc_records = [record for record in records if record["dataset"] == "D_inc"]
    for record in records:
        if record["dataset"] in ("D_mix", "D_log"):
            source = forge_candidate(record["record_id"])
            roots = (
                []
                if source is None
                else [FORGE / "dataset" / value for value in source["project_paths"].values()]
            )
            existing = [p for p in roots if p.is_dir()]
            root = existing[0] if existing else None
            workspace = WORKSPACES / record["record_id"]
            if workspace.exists():
                shutil.rmtree(workspace)
            workspace.mkdir(parents=True)
            if root is None:
                status = "SOURCE_MISSING"
                workspace_path = None
                source_files = []
                code, output, command, resolution = 2, "project root missing", "", {}
            else:
                (workspace / "source").symlink_to(root, target_is_directory=True)
                (workspace / "foundry.toml").write_text(
                    "[profile.default]\n"
                    "src = 'source'\n"
                    "out = 'out'\n"
                    "libs = ['lib']\n"
                    "offline = true\n",
                    encoding="utf-8",
                )
                source_files = sorted((root).rglob("*.sol"))
                remappings = project_remappings(root)
                if remappings:
                    (workspace / "remappings.txt").write_text(
                        "\n".join(remappings) + "\n", encoding="utf-8"
                    )
                target = (
                    workspace / "source" / source_files[0].relative_to(root)
                    if source_files
                    else None
                )
                code, output, command, resolution = build_workspace(workspace, target)
                status = "COMPILE_OK" if source_files and code == 0 else "COMPILE_FAILED"
                workspace_path = str(workspace.resolve())
            rows.append(
                {
                    "record_id": record["record_id"],
                    "dataset": record["dataset"],
                    "source_root": str(root.resolve()) if root else None,
                    "workspace": workspace_path,
                    "source_commit": record["source_commit"],
                    "foundry_config": bool(root),
                    "status": status,
                    "source_file_count": len(source_files) if root else 0,
                    "remapping_count": len(remappings) if root else 0,
                    "reason": "isolated workspace created from immutable FORGE source root",
                    "compile_command": command,
                    "compile_exit_code": code,
                    "compile_output": output,
                    "source_sha256": tree_hash(root) if root else None,
                    "workspace_sha256": tree_hash(workspace),
                    "compiler_resolution": resolution,
                }
            )
        elif record["dataset"] != "D_inc":
            rows.append(
                {
                    "record_id": record["record_id"],
                    "dataset": record["dataset"],
                    "status": "CATALOG_ONLY",
                }
            )
    for record in inc_records:
        rows.append(prepare_inc(record))
    manifest = {
        "schema_version": "1.0",
        "toolchain": {"forge": "1.3.1", "image": "vulnweaver-foundry:1.3.1-solc0.8.24"},
        "source_commits": {
            "forge": json.loads((DATA / "forge/import-manifest.json").read_text())["source_commit"],
            "defihacklabs": "6bbb7b7893d3ccd2ef3d6018d991dc309ccdc281",
        },
        "records": rows,
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    from collections import Counter

    print(
        json.dumps({"total": len(rows), "status": Counter(row["status"] for row in rows)}, indent=2)
    )


if __name__ == "__main__":
    main()
