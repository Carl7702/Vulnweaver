"""Materialize verifier workspaces without exposing sealed or patched inputs."""

from __future__ import annotations

import shutil
from pathlib import Path

from vulnweaver.common.schema import EnvironmentSpec

_EXCLUDED_PARTS = {".git", "cache", "out", "test", "sealed", "reference"}


class WorkspaceMaterializationError(ValueError):
    pass


def _copy_file(source: Path, target: Path) -> None:
    if source.is_symlink():
        raise WorkspaceMaterializationError(f"symlinks are not allowed: {source}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def materialize_foundry_workspace(
    *,
    environment: EnvironmentSpec,
    candidate_dir: Path,
    repository_root: Path,
    destination: Path,
) -> Path:
    """Copy immutable target files and only `.sol` candidate files into a fresh tree."""

    root = repository_root.resolve(strict=True)
    target_root = (root / environment.repository).resolve(strict=True)
    if not target_root.is_relative_to(root) or not target_root.is_dir():
        raise WorkspaceMaterializationError("environment repository escapes repository root")
    candidate_root = candidate_dir.resolve(strict=True)
    if not candidate_root.is_dir():
        raise WorkspaceMaterializationError("candidate path must be a directory")
    destination.mkdir(parents=True, exist_ok=True)

    target_files = 0
    for source in sorted(target_root.rglob("*")):
        if not source.is_file():
            continue
        relative = source.relative_to(target_root)
        if any(part in _EXCLUDED_PARTS for part in relative.parts):
            continue
        _copy_file(source, destination / relative)
        target_files += 1
    if target_files == 0 or not (destination / "foundry.toml").is_file():
        raise WorkspaceMaterializationError("environment has no Foundry target files")

    candidate_files = 0
    for source in sorted(candidate_root.rglob("*")):
        if not source.is_file():
            continue
        relative = source.relative_to(candidate_root)
        if source.suffix != ".sol" or any(part.startswith(".") for part in relative.parts):
            continue
        _copy_file(source, destination / "test" / relative)
        candidate_files += 1
    if candidate_files == 0:
        raise WorkspaceMaterializationError("candidate contains no Solidity files")
    return destination
