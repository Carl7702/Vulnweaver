"""Read-only adapter for the pinned FORGE and FORGE-Curated datasets."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from vulnweaver.common.hashing import file_sha256, stable_hash, tree_sha256
from vulnweaver.common.schema import Severity, StrictModel


class ForgeStatus(StrEnum):
    METADATA_READY = "METADATA_READY"
    REJECTED = "REJECTED"


class ForgeRejectionReason(StrEnum):
    INVALID_JSON = "invalid_json"
    MISSING_PROJECT_INFO = "missing_project_info"
    MISSING_FINDINGS = "missing_findings"
    DUPLICATE_FINDING_ID = "duplicate_finding_id"
    MISSING_COMMIT = "missing_commit"
    MISSING_SOURCE = "missing_source"
    MALFORMED_FINDING = "malformed_finding"


class ForgeFinding(StrictModel):
    finding_id: str
    title: str
    description: str
    severity: Severity
    categories: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    locations: tuple[str, ...] = ()
    affected_files: tuple[str, ...] = ()


class ForgeCandidate(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    candidate_id: str
    project_id: str
    source_file: str
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    report_path: str | None = None
    repository_urls: tuple[str, ...] = ()
    commits: tuple[str, ...] = ()
    chain: tuple[str, ...] = ()
    compiler_versions: tuple[str, ...] = ()
    project_paths: dict[str, str] = Field(default_factory=dict)
    finding: ForgeFinding
    source_available: bool
    status: ForgeStatus
    rejection_reasons: tuple[ForgeRejectionReason, ...] = ()
    candidate_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class ForgeManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    adapter: Literal["forge"] = "forge"
    source: str
    source_commit: str
    source_tree_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    report_count: int = Field(ge=0)
    finding_count: int = Field(ge=0)
    metadata_ready_count: int = Field(ge=0)
    rejected_count: int = Field(ge=0)
    source_available_count: int = Field(ge=0)
    rejection_counts: dict[str, int]
    candidates_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def _texts(value: Any) -> tuple[str, ...]:
    values = value if isinstance(value, list) else [value]
    return tuple(
        text
        for item in values
        if (text := str(item).strip()) and text.lower() not in {"n/a", "none", "null"}
    )


def _severity(value: Any) -> Severity:
    values = _texts(value)
    try:
        return Severity(values[0].lower()) if values else Severity.UNKNOWN
    except ValueError:
        return Severity.UNKNOWN


def _categories(value: Any) -> dict[str, tuple[str, ...]]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key): _texts(items)
        for key, items in value.items()
        if _texts(items)
    }


def _source_available(source_root: Path, paths: dict[str, str], files: tuple[str, ...]) -> bool:
    root = source_root.resolve()
    candidates = [*paths.values(), *files]
    for relative in candidates:
        path = (root / relative).resolve()
        if path.is_relative_to(root) and path.exists():
            return True
        for project_path in paths.values():
            path = (root / project_path / relative).resolve()
            if path.is_relative_to(root) and path.exists():
                return True
    return False


def _git_commit(source: Path) -> str:
    head = source / ".git"
    if not head.exists():
        return "unversioned"
    import subprocess

    result = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def scan_forge(
    source: Path,
    *,
    results_dir: Path | None = None,
    source_root: Path | None = None,
) -> tuple[list[ForgeCandidate], ForgeManifest]:
    """Convert each FORGE finding into a provenance-preserving metadata candidate."""

    results = results_dir or source / "dataset" / "results"
    contracts = source_root or source / "dataset"
    candidates: list[ForgeCandidate] = []
    report_count = 0
    for path in sorted(results.rglob("*.json")):
        relative = path.relative_to(source).as_posix()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        report_count += 1
        project = payload.get("project_info")
        project = project if isinstance(project, dict) else {}
        findings = payload.get("findings")
        findings = findings if isinstance(findings, list) else []
        paths_value = project.get("project_path")
        project_paths = (
            {str(key): str(value) for key, value in paths_value.items()}
            if isinstance(paths_value, dict)
            else {}
        )
        finding_ids = [
            str(item.get("id", index))
            for index, item in enumerate(findings)
            if isinstance(item, dict)
        ]
        duplicate_ids = {item for item, count in Counter(finding_ids).items() if count > 1}
        project_id = stable_hash({"source_file": relative})[:16]
        for index, raw in enumerate(findings):
            if not isinstance(raw, dict):
                continue
            finding_id = str(raw.get("id", index))
            title = str(raw.get("title", "")).strip()
            description = str(raw.get("description", "")).strip()
            affected_files = _texts(raw.get("files"))
            available = _source_available(contracts, project_paths, affected_files)
            reasons: list[ForgeRejectionReason] = []
            if not project:
                reasons.append(ForgeRejectionReason.MISSING_PROJECT_INFO)
            if finding_id in duplicate_ids:
                reasons.append(ForgeRejectionReason.DUPLICATE_FINDING_ID)
            if not _texts(project.get("commit_id")):
                reasons.append(ForgeRejectionReason.MISSING_COMMIT)
            if not available:
                reasons.append(ForgeRejectionReason.MISSING_SOURCE)
            if not title or not description:
                reasons.append(ForgeRejectionReason.MALFORMED_FINDING)
            occurrence = f"-n{index}" if finding_id in duplicate_ids else ""
            candidate = ForgeCandidate(
                candidate_id=f"forge-{project_id}-f{finding_id}{occurrence}",
                project_id=project_id,
                source_file=relative,
                source_sha256=file_sha256(path),
                report_path=str(payload.get("path")) if payload.get("path") else None,
                repository_urls=_texts(project.get("url")),
                commits=_texts(project.get("commit_id")),
                chain=_texts(project.get("chain")),
                compiler_versions=_texts(project.get("compiler_version")),
                project_paths=project_paths,
                finding=ForgeFinding(
                    finding_id=finding_id,
                    title=title or "<missing title>",
                    description=description or "<missing description>",
                    severity=_severity(raw.get("severity")),
                    categories=_categories(raw.get("category")),
                    locations=_texts(raw.get("location")),
                    affected_files=affected_files,
                ),
                source_available=available,
                status=ForgeStatus.REJECTED if reasons else ForgeStatus.METADATA_READY,
                rejection_reasons=tuple(dict.fromkeys(reasons)),
            )
            digest = stable_hash(candidate.model_dump(mode="json", exclude={"candidate_sha256"}))
            candidates.append(candidate.model_copy(update={"candidate_sha256": digest}))

    rejection_counts = Counter(
        reason.value for candidate in candidates for reason in candidate.rejection_reasons
    )
    ready = sum(candidate.status is ForgeStatus.METADATA_READY for candidate in candidates)
    manifest = ForgeManifest(
        source=str(source.resolve()),
        source_commit=_git_commit(source),
        source_tree_sha256=tree_sha256(source),
        report_count=report_count,
        finding_count=len(candidates),
        metadata_ready_count=ready,
        rejected_count=len(candidates) - ready,
        source_available_count=sum(candidate.source_available for candidate in candidates),
        rejection_counts=dict(sorted(rejection_counts.items())),
        candidates_sha256=stable_hash(
            [candidate.candidate_sha256 for candidate in candidates]
        ),
    )
    return candidates, manifest


def write_forge_import(
    output: Path,
    candidates: Iterable[ForgeCandidate],
    manifest: ForgeManifest,
) -> None:
    output.mkdir(parents=True, exist_ok=True)
    with (output / "candidates.jsonl").open("w", encoding="utf-8") as handle:
        for candidate in candidates:
            handle.write(candidate.model_dump_json() + "\n")
    (output / "import-manifest.json").write_text(
        manifest.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
