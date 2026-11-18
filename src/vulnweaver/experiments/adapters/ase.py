"""Read-only ASE26 project_info/findings adapter.

The adapter intentionally does not import or execute PoCForge code. One project JSON can
produce many finding candidates; project counts and vulnerability-case counts are kept
separate throughout the import manifest.
"""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from collections import Counter
from collections.abc import Iterable, Iterator
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import Field

from vulnweaver.common.hashing import file_sha256, stable_hash
from vulnweaver.common.schema import Severity, StrictModel

_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_COMMIT = re.compile(r"^[0-9a-fA-F]{7,64}$")


class RejectionReason(StrEnum):
    INVALID_JSON = "invalid_json"
    MISSING_PROJECT_INFO = "missing_project_info"
    MISSING_FINDINGS = "missing_findings"
    DUPLICATE_FINDING_ID = "duplicate_finding_id"
    MISSING_COMMIT = "missing_commit"
    INVALID_COMMIT = "invalid_commit"
    INVALID_ADDRESS = "invalid_address"
    MISSING_COMPILER = "missing_compiler"
    MISSING_SOURCE = "missing_source"
    MALFORMED_FINDING = "malformed_finding"


class CandidateStatus(StrEnum):
    CANDIDATE = "CANDIDATE"
    REJECTED = "REJECTED"


class ASEFinding(StrictModel):
    finding_id: str
    title: str
    description: str
    severity: Severity
    location: str | None = None
    categories: dict[str, tuple[str, ...]] = Field(default_factory=dict)


class ASECandidate(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    candidate_id: str
    dataset: Literal["D_mix", "D_log"]
    project_id: str
    source_file: str
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_document: str | None = None
    repository_url: str | None = None
    commit: str | None = None
    address: str | None = None
    chain: str | None = None
    compiler_versions: tuple[str, ...] = ()
    project_paths: dict[str, str] = Field(default_factory=dict)
    finding: ASEFinding
    status: CandidateStatus
    rejection_reasons: tuple[RejectionReason, ...] = ()
    conversion_log: tuple[str, ...]
    candidate_sha256: str | None = None


class ImportManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    adapter: Literal["ase26"] = "ase26"
    source: str
    source_sha256: str | None = None
    project_counts: dict[str, int]
    finding_counts: dict[str, int]
    candidate_count: int
    structurally_valid_candidate_count: int
    rejected_candidate_count: int
    rejection_counts: dict[str, int]
    candidates_sha256: str


class _SourceRecord(StrictModel):
    dataset: Literal["D_mix", "D_log"]
    name: str
    content: bytes


def _dataset_for_path(path: PurePosixPath) -> Literal["D_mix", "D_log"] | None:
    parts = set(path.parts)
    if "D_mix" in parts:
        return "D_mix"
    if "D_log" in parts:
        return "D_log"
    return None


def _iter_zip(path: Path) -> Iterator[_SourceRecord]:
    with zipfile.ZipFile(path) as archive:
        for info in sorted(archive.infolist(), key=lambda item: item.filename):
            member = PurePosixPath(info.filename)
            dataset = _dataset_for_path(member)
            if info.is_dir() or member.suffix.lower() != ".json" or dataset is None:
                continue
            if "__MACOSX" in member.parts or member.name.startswith("._"):
                continue
            # Dataset files are flat project JSON. Exclude RAG and generated result trees.
            if "rag_knowledge_base" in member.parts or "results" in member.parts:
                continue
            yield _SourceRecord(dataset=dataset, name=member.as_posix(), content=archive.read(info))


def _iter_directory(path: Path) -> Iterator[_SourceRecord]:
    for item in sorted(path.rglob("*.json")):
        relative = PurePosixPath(item.relative_to(path).as_posix())
        dataset = _dataset_for_path(relative)
        if dataset is None or "rag_knowledge_base" in relative.parts or "results" in relative.parts:
            continue
        yield _SourceRecord(dataset=dataset, name=relative.as_posix(), content=item.read_bytes())


def iter_source_records(source: Path) -> Iterator[_SourceRecord]:
    if source.is_file() and zipfile.is_zipfile(source):
        yield from _iter_zip(source)
        return
    if source.is_dir():
        yield from _iter_directory(source)
        return
    raise ValueError("ASE source must be a directory or ZIP archive")


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return None if text.lower() in {"", "n/a", "none", "null"} else text


def _severity(value: Any) -> Severity:
    try:
        return Severity(str(value).strip().lower())
    except ValueError:
        return Severity.UNKNOWN


def _categories(value: Any) -> dict[str, tuple[str, ...]]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, tuple[str, ...]] = {}
    for key, items in value.items():
        if isinstance(items, list):
            result[str(key)] = tuple(str(item) for item in items)
    return result


def _source_exists(project_paths: dict[str, str], source_root: Path | None) -> bool:
    if source_root is None:
        return False
    resolved_root = source_root.resolve()
    for relative in project_paths.values():
        candidate = (resolved_root / relative).resolve()
        if candidate.is_relative_to(resolved_root) and candidate.exists():
            return True
    return False


def _candidate(
    *,
    record: _SourceRecord,
    payload: dict[str, Any],
    finding: dict[str, Any],
    finding_id: str,
    finding_index: int,
    duplicate_id: bool,
    require_source: bool,
    source_root: Path | None,
) -> ASECandidate:
    project = payload.get("project_info")
    project = project if isinstance(project, dict) else {}
    commit = _optional_text(project.get("commit_id"))
    address = _optional_text(project.get("address"))
    compiler_value = project.get("compiler_version")
    compilers = (
        tuple(str(item) for item in compiler_value if str(item).strip())
        if isinstance(compiler_value, list)
        else ()
    )
    paths_value = project.get("project_path")
    paths = (
        {str(key): str(value) for key, value in paths_value.items()}
        if isinstance(paths_value, dict)
        else {}
    )

    reasons: list[RejectionReason] = []
    if not project:
        reasons.append(RejectionReason.MISSING_PROJECT_INFO)
    if duplicate_id:
        reasons.append(RejectionReason.DUPLICATE_FINDING_ID)
    if commit is None:
        reasons.append(RejectionReason.MISSING_COMMIT)
    elif not _COMMIT.fullmatch(commit):
        reasons.append(RejectionReason.INVALID_COMMIT)
    if address is None or not _ADDRESS.fullmatch(address):
        reasons.append(RejectionReason.INVALID_ADDRESS)
    if not compilers:
        reasons.append(RejectionReason.MISSING_COMPILER)
    if require_source and not _source_exists(paths, source_root):
        reasons.append(RejectionReason.MISSING_SOURCE)

    title = _optional_text(finding.get("title"))
    description = _optional_text(finding.get("description"))
    if title is None or description is None:
        reasons.append(RejectionReason.MALFORMED_FINDING)
    source_digest = hashlib.sha256(record.content).hexdigest()
    project_id = stable_hash({"dataset": record.dataset, "source_file": record.name})[:16]
    occurrence = f"-n{finding_index}" if duplicate_id else ""
    candidate_id = f"ase26-{record.dataset.lower()}-{project_id}-f{finding_id}{occurrence}"
    candidate = ASECandidate(
        candidate_id=candidate_id,
        dataset=record.dataset,
        project_id=project_id,
        source_file=record.name,
        source_sha256=source_digest,
        source_document=_optional_text(payload.get("path")),
        repository_url=_optional_text(project.get("url")),
        commit=commit,
        address=address,
        chain=_optional_text(project.get("chain")),
        compiler_versions=compilers,
        project_paths=paths,
        finding=ASEFinding(
            finding_id=finding_id,
            title=title or "<missing title>",
            description=description or "<missing description>",
            severity=_severity(finding.get("severity")),
            location=_optional_text(finding.get("location")),
            categories=_categories(finding.get("category")),
        ),
        status=CandidateStatus.REJECTED if reasons else CandidateStatus.CANDIDATE,
        rejection_reasons=tuple(dict.fromkeys(reasons)),
        conversion_log=(
            "one project finding converted to one independent candidate",
            "reference PoC, if present externally, was not read",
        ),
    )
    digest = stable_hash(candidate.model_dump(mode="json", exclude={"candidate_sha256"}))
    return candidate.model_copy(update={"candidate_sha256": digest})


def convert_record(
    record: _SourceRecord,
    *,
    require_source: bool = False,
    source_root: Path | None = None,
) -> list[ASECandidate]:
    try:
        payload = json.loads(record.content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(payload, dict):
        return []
    findings = payload.get("findings")
    if not isinstance(findings, list):
        return []
    ids = [
        str(item.get("id", index))
        for index, item in enumerate(findings)
        if isinstance(item, dict)
    ]
    duplicate_ids = {item for item, count in Counter(ids).items() if count > 1}
    converted: list[ASECandidate] = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        finding_id = str(finding.get("id", index))
        converted.append(
            _candidate(
                record=record,
                payload=payload,
                finding=finding,
                finding_id=finding_id,
                finding_index=index,
                duplicate_id=finding_id in duplicate_ids,
                require_source=require_source,
                source_root=source_root,
            )
        )
    return converted


def scan_ase(
    source: Path,
    *,
    require_source: bool = False,
    source_root: Path | None = None,
) -> tuple[list[ASECandidate], ImportManifest]:
    records = list(iter_source_records(source))
    candidates = [
        candidate
        for record in records
        for candidate in convert_record(
            record,
            require_source=require_source,
            source_root=source_root,
        )
    ]
    project_counts = Counter(record.dataset for record in records)
    finding_counts = Counter(candidate.dataset for candidate in candidates)
    rejection_counts = Counter(
        reason.value for candidate in candidates for reason in candidate.rejection_reasons
    )
    rejected = sum(candidate.status is CandidateStatus.REJECTED for candidate in candidates)
    source_hash = file_sha256(source) if source.is_file() else None
    manifest = ImportManifest(
        source=str(source.resolve()),
        source_sha256=source_hash,
        project_counts=dict(sorted(project_counts.items())),
        finding_counts=dict(sorted(finding_counts.items())),
        candidate_count=len(candidates),
        structurally_valid_candidate_count=len(candidates) - rejected,
        rejected_candidate_count=rejected,
        rejection_counts=dict(sorted(rejection_counts.items())),
        candidates_sha256=stable_hash(
            sorted(candidate.candidate_sha256 for candidate in candidates)
        ),
    )
    return candidates, manifest


def write_import(
    output: Path,
    candidates: Iterable[ASECandidate],
    manifest: ImportManifest,
) -> None:
    output.mkdir(parents=True, exist_ok=True)
    candidate_dir = output / "candidates"
    candidate_dir.mkdir(exist_ok=True)
    for candidate in candidates:
        path = candidate_dir / f"{candidate.candidate_id}.json"
        path.write_text(candidate.model_dump_json(indent=2) + "\n", encoding="utf-8")
    (output / "import-manifest.json").write_text(
        manifest.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )

