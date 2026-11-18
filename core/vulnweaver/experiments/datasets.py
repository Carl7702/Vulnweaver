"""Evaluation-pool construction and data-card generation.

This module keeps paper-scale targets separate from the records that are actually
available.  It records metadata and admission gates; it never copies source code or
pretends that a missing environment is reproducible.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Mapping
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, ValidationError

from vulnweaver.common.hashing import file_sha256, stable_hash, tree_sha256
from vulnweaver.common.schema import DatasetSplit, StrictModel
from vulnweaver.experiments.adapters.ase import ASECandidate, CandidateStatus
from vulnweaver.experiments.adapters.defihacklabs import (
    DefiHackLabsCandidate,
    DefiHackLabsStatus,
)


class EvaluationDataset(StrEnum):
    D_MIX = "D_mix"
    D_LOG = "D_log"
    D_INC = "D_inc"
    D_CVE = "D_cve"


PAPER_TARGET_COUNTS: dict[EvaluationDataset, int] = {
    EvaluationDataset.D_MIX: 121,
    EvaluationDataset.D_LOG: 122,
    EvaluationDataset.D_INC: 123,
    EvaluationDataset.D_CVE: 18,
}


class EvaluationStatus(StrEnum):
    CANDIDATE = "CANDIDATE"
    METADATA_READY = "METADATA_READY"
    READY = "READY"
    REJECTED = "REJECTED"


class EvaluationRejectionReason(StrEnum):
    SOURCE_REJECTED = "source_rejected"
    METADATA_UNAVAILABLE = "metadata_unavailable"
    PROJECT_LEAKAGE = "project_leakage"
    ATTACK_FAMILY_LEAKAGE = "attack_family_leakage"
    EVALUATION_POOL_LIMIT = "evaluation_pool_limit"
    CATALOG_NOT_PROVIDED = "catalog_not_provided"
    MALFORMED_CVE = "malformed_cve"
    MISSING_VULNERABLE_ENVIRONMENT = "missing_vulnerable_environment"
    MISSING_NEUTRALIZED_ENVIRONMENT = "missing_neutralized_environment"
    MISSING_PATCHED_ENVIRONMENT = "missing_patched_environment"
    MISSING_MANUAL_REVIEW = "missing_manual_review"
    MISSING_PATCH_REPLAY = "missing_patch_replay"


class EvaluationRecord(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    record_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    dataset: EvaluationDataset
    source_file: str = Field(min_length=1)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_commit: str | None = None
    project_id: str = Field(min_length=1)
    attack_family: str = Field(min_length=1)
    incident_month: str | None = Field(default=None, pattern=r"^20\d{2}-(0[1-9]|1[0-2])$")
    fixed_fork_block: int | None = Field(default=None, ge=0)
    attack_tx_hash: str | None = Field(default=None, pattern=r"^0x[a-fA-F0-9]{64}$")
    vulnerable_environment: bool = False
    neutralized_environment: bool = False
    patched_environment: bool = False
    manual_reviewed: bool = False
    official_patch_replayed: bool = False
    status: EvaluationStatus
    split: DatasetSplit = DatasetSplit.TEST
    rejection_reasons: tuple[EvaluationRejectionReason, ...] = ()
    provenance: tuple[str, ...] = ()
    record_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class EvaluationDatasetSummary(StrictModel):
    dataset: EvaluationDataset
    target_count: int = Field(ge=0)
    discovered_count: int = Field(ge=0)
    candidate_count: int = Field(ge=0)
    metadata_ready_count: int = Field(ge=0)
    ready_count: int = Field(ge=0)
    rejected_count: int = Field(ge=0)
    rejection_counts: dict[str, int]
    project_count: int = Field(ge=0)
    attack_family_count: int = Field(ge=0)


class EvaluationManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    adapter: Literal["evaluation"] = "evaluation"
    source_inputs: dict[str, str]
    target_counts: dict[str, int]
    dataset_summaries: dict[str, EvaluationDatasetSummary]
    leakage: dict[str, object]
    records_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    discrepancy_count: int = Field(ge=0)


def _finalize(record: EvaluationRecord) -> EvaluationRecord:
    digest = stable_hash(record.model_dump(mode="json", exclude={"record_sha256"}))
    return record.model_copy(update={"record_sha256": digest})


def _family_from_ase(candidate: ASECandidate) -> str:
    labels = [
        f"{key}:{value}"
        for key, values in sorted(candidate.finding.categories.items())
        for value in values
    ]
    return "+".join(labels) if labels else "unknown"


def build_ase_evaluation_records(
    candidates: Iterable[ASECandidate],
) -> list[EvaluationRecord]:
    """Convert one ASE finding into one evaluation record without inventing Ev."""

    records: list[EvaluationRecord] = []
    for candidate in candidates:
        reasons: tuple[EvaluationRejectionReason, ...] = ()
        status = EvaluationStatus.CANDIDATE
        if candidate.status is not CandidateStatus.CANDIDATE:
            reasons = (EvaluationRejectionReason.SOURCE_REJECTED,)
            status = EvaluationStatus.REJECTED
        record = EvaluationRecord(
            record_id=candidate.candidate_id,
            dataset=EvaluationDataset(candidate.dataset),
            source_file=candidate.source_file,
            source_sha256=candidate.source_sha256,
            source_commit=candidate.commit,
            project_id=candidate.project_id,
            attack_family=_family_from_ase(candidate),
            status=status,
            rejection_reasons=reasons,
            provenance=(
                "converted from one ASE26 finding",
                "environment admission remains a separate gate",
            ),
        )
        records.append(_finalize(record))
    return records


def build_inc_evaluation_records(
    candidates: Iterable[DefiHackLabsCandidate],
    training_candidates: Iterable[DefiHackLabsCandidate],
    *,
    cutoff_month: str,
    target_count: int = 123,
) -> list[EvaluationRecord]:
    """Build held-out DeFiHackLabs metadata records with strict leakage checks."""

    train = [
        item for item in training_candidates if item.status is DefiHackLabsStatus.METADATA_READY
    ]
    train_projects = {item.project_id for item in train}
    train_families = {item.attack_family for item in train}
    records: list[EvaluationRecord] = []
    for candidate in sorted(candidates, key=lambda item: item.case_id):
        reasons: list[EvaluationRejectionReason] = []
        if candidate.status is not DefiHackLabsStatus.METADATA_READY:
            reasons.append(EvaluationRejectionReason.METADATA_UNAVAILABLE)
        if candidate.incident_month <= cutoff_month:
            continue
        if candidate.project_id in train_projects:
            reasons.append(EvaluationRejectionReason.PROJECT_LEAKAGE)
        if candidate.attack_family in train_families:
            reasons.append(EvaluationRejectionReason.ATTACK_FAMILY_LEAKAGE)
        status = EvaluationStatus.METADATA_READY if not reasons else EvaluationStatus.REJECTED
        record = EvaluationRecord(
            record_id=f"inc-{candidate.case_id}",
            dataset=EvaluationDataset.D_INC,
            source_file=candidate.source_file,
            source_sha256=candidate.source_sha256,
            source_commit=candidate.source_commit,
            project_id=candidate.project_id,
            attack_family=candidate.attack_family,
            incident_month=candidate.incident_month,
            fixed_fork_block=candidate.fork.block if candidate.fork else None,
            attack_tx_hash=candidate.attack_tx_hash,
            vulnerable_environment=candidate.fork is not None,
            status=status,
            rejection_reasons=tuple(dict.fromkeys(reasons)),
            provenance=(
                "held-out DeFiHackLabs candidate",
                "source PoC remains sealed",
                "compile, root-cause, and patched replay are pending admission",
            ),
        )
        records.append(_finalize(record))
    eligible = [item for item in records if item.status is EvaluationStatus.METADATA_READY]
    selected = {item.record_id for item in eligible[:target_count]}
    for index, record in enumerate(records):
        if record.status is not EvaluationStatus.METADATA_READY or record.record_id in selected:
            continue
        records[index] = _finalize(
            record.model_copy(
                update={
                    "status": EvaluationStatus.REJECTED,
                    "rejection_reasons": (EvaluationRejectionReason.EVALUATION_POOL_LIMIT,),
                }
            )
        )
    return records


def _raw_cve_record(raw: Mapping[str, Any], index: int) -> EvaluationRecord:
    source_file = str(raw.get("source_file", f"catalog-record-{index}"))
    source_sha256 = str(raw.get("source_sha256", ""))
    if len(source_sha256) != 64 or any(char not in "0123456789abcdef" for char in source_sha256):
        source_sha256 = stable_hash(raw)
    reasons: list[EvaluationRejectionReason] = []
    required = ("cve_id", "project_id", "attack_family")
    reasons.extend(
        EvaluationRejectionReason.MALFORMED_CVE
        for key in required
        if not str(raw.get(key, "")).strip()
    )
    if not raw.get("vulnerable_environment", False):
        reasons.append(EvaluationRejectionReason.MISSING_VULNERABLE_ENVIRONMENT)
    if not raw.get("neutralized_environment", False):
        reasons.append(EvaluationRejectionReason.MISSING_NEUTRALIZED_ENVIRONMENT)
    if not raw.get("patched_environment", False):
        reasons.append(EvaluationRejectionReason.MISSING_PATCHED_ENVIRONMENT)
    if not raw.get("manual_reviewed", False):
        reasons.append(EvaluationRejectionReason.MISSING_MANUAL_REVIEW)
    if not raw.get("official_patch_replayed", False):
        reasons.append(EvaluationRejectionReason.MISSING_PATCH_REPLAY)
    status = EvaluationStatus.READY if not reasons else EvaluationStatus.REJECTED
    return _finalize(
        EvaluationRecord(
            record_id=f"cve-{str(raw.get('cve_id', f'unknown-{index}')).lower()}",
            dataset=EvaluationDataset.D_CVE,
            source_file=source_file,
            source_sha256=source_sha256,
            source_commit=(
                str(raw.get("vulnerable_commit")) if raw.get("vulnerable_commit") else None
            ),
            project_id=str(raw.get("project_id", f"unknown-project-{index}")),
            attack_family=str(raw.get("attack_family", "unknown")),
            vulnerable_environment=bool(raw.get("vulnerable_environment", False)),
            neutralized_environment=bool(raw.get("neutralized_environment", False)),
            patched_environment=bool(raw.get("patched_environment", False)),
            manual_reviewed=bool(raw.get("manual_reviewed", False)),
            official_patch_replayed=bool(raw.get("official_patch_replayed", False)),
            status=status,
            rejection_reasons=tuple(dict.fromkeys(reasons)),
            provenance=(
                "constructed from a version-pinned CVE catalog",
                "manual review and official patch replay are recorded as explicit gates",
            ),
        )
    )


def load_cve_catalog(path: Path) -> list[EvaluationRecord]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    raw_records = payload.get("records", []) if isinstance(payload, dict) else payload
    if not isinstance(raw_records, list):
        raise ValueError("CVE catalog must be a JSON list or an object with a records list")
    records: list[EvaluationRecord] = []
    for index, raw in enumerate(raw_records):
        if not isinstance(raw, dict):
            raw = {"cve_id": f"unknown-{index}", "raw": raw}
        try:
            records.append(_raw_cve_record(raw, index))
        except ValidationError as error:
            raise ValueError(f"invalid CVE catalog record {index}: {error}") from error
    return records


def empty_evaluation_dataset(
    dataset: EvaluationDataset, reason: EvaluationRejectionReason
) -> list[EvaluationRecord]:
    return [
        _finalize(
            EvaluationRecord(
                record_id=f"{dataset.value.lower()}-input-missing",
                dataset=dataset,
                source_file=f"{dataset.value}:input",
                source_sha256=stable_hash({"dataset": dataset.value, "reason": reason.value}),
                project_id="unavailable",
                attack_family="unavailable",
                status=EvaluationStatus.REJECTED,
                rejection_reasons=(reason,),
                provenance=("no source was supplied for this dataset",),
            )
        )
    ]


def build_evaluation_manifest(
    records: Iterable[EvaluationRecord],
    *,
    source_inputs: Mapping[str, str],
    target_counts: Mapping[EvaluationDataset | str, int],
) -> EvaluationManifest:
    materialized = list(records)
    summaries: dict[str, EvaluationDatasetSummary] = {}
    for dataset in EvaluationDataset:
        subset = [item for item in materialized if item.dataset is dataset]
        counts = Counter(reason.value for item in subset for reason in item.rejection_reasons)
        summaries[dataset.value] = EvaluationDatasetSummary(
            dataset=dataset,
            target_count=int(target_counts.get(dataset, target_counts.get(dataset.value, 0))),
            discovered_count=len(subset),
            candidate_count=sum(item.status is EvaluationStatus.CANDIDATE for item in subset),
            metadata_ready_count=sum(
                item.status is EvaluationStatus.METADATA_READY for item in subset
            ),
            ready_count=sum(item.status is EvaluationStatus.READY for item in subset),
            rejected_count=sum(item.status is EvaluationStatus.REJECTED for item in subset),
            rejection_counts=dict(sorted(counts.items())),
            project_count=len(
                {item.project_id for item in subset if item.status is not EvaluationStatus.REJECTED}
            ),
            attack_family_count=len(
                {
                    item.attack_family
                    for item in subset
                    if item.status is not EvaluationStatus.REJECTED
                }
            ),
        )
    datasets = {
        dataset.value: [item for item in materialized if item.dataset is dataset]
        for dataset in EvaluationDataset
    }
    leakage: dict[str, object] = {
        "d_inc_projects": sorted(
            {
                item.project_id
                for item in datasets[EvaluationDataset.D_INC.value]
                if item.status is EvaluationStatus.METADATA_READY
            }
        ),
        "d_inc_attack_families": sorted(
            {
                item.attack_family
                for item in datasets[EvaluationDataset.D_INC.value]
                if item.status is EvaluationStatus.METADATA_READY
            }
        ),
    }
    discrepancies = sum(
        summary.target_count
        != summary.candidate_count + summary.metadata_ready_count + summary.ready_count
        for summary in summaries.values()
        if summary.target_count > 0
    )
    return EvaluationManifest(
        source_inputs=dict(source_inputs),
        target_counts={str(key): int(value) for key, value in target_counts.items()},
        dataset_summaries=summaries,
        leakage=leakage,
        records_sha256=stable_hash(
            [item.record_sha256 for item in materialized if item.record_sha256 is not None]
        ),
        discrepancy_count=discrepancies,
    )


def write_evaluation_import(
    output: Path,
    records: Iterable[EvaluationRecord],
    manifest: EvaluationManifest,
) -> None:
    output.mkdir(parents=True, exist_ok=True)
    record_dir = output / "records"
    record_dir.mkdir(exist_ok=True)
    materialized = list(records)
    for record in materialized:
        (record_dir / f"{record.record_id}.json").write_text(
            record.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
    expected_files = {record.record_id + ".json" for record in materialized}
    for stale in record_dir.glob("*.json"):
        if stale.name not in expected_files:
            stale.unlink()
    (output / "import-manifest.json").write_text(
        manifest.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "# Evaluation datasets data card",
        "",
        "The builder records actual availability and keeps the paper target separate.",
        "Source code is never copied into this output.",
        "",
        "## Dataset counts",
        "",
        "| Dataset | Target | Discovered | Candidate | Metadata-ready | Ready | Rejected |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for dataset in EvaluationDataset:
        summary = manifest.dataset_summaries[dataset.value]
        lines.append(
            f"| {dataset.value} | {summary.target_count} | {summary.discovered_count} | "
            f"{summary.candidate_count} | {summary.metadata_ready_count} | "
            f"{summary.ready_count} | {summary.rejected_count} |"
        )
    lines.extend(
        [
            "",
            "## Leakage and gates",
            "",
            "D_inc records are admitted only when their project and inferred attack family "
            "are absent from the supplied training pool. CVE records require vulnerable, "
            "root-cause-neutralized, and patched environment metadata, manual review, and "
            "official patch replay.",
            "",
            f"Manifest discrepancy count: `{manifest.discrepancy_count}`.",
            "",
            "## Rebuild inputs",
            "",
        ]
    )
    lines.extend(f"- `{key}`: `{value}`" for key, value in sorted(manifest.source_inputs.items()))
    (output / "data-card.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    discrepancy_lines = ["# Evaluation discrepancy report", ""]
    for dataset in EvaluationDataset:
        summary = manifest.dataset_summaries[dataset.value]
        actual = summary.candidate_count + summary.metadata_ready_count + summary.ready_count
        discrepancy_lines.append(
            f"- `{dataset.value}`: target `{summary.target_count}`, actual `{actual}`, "
            f"difference `{summary.target_count - actual}`."
        )
    discrepancy_lines.append("")
    discrepancy_lines.append(
        "Rejected records retain machine-readable reasons in their JSON files."
    )
    (output / "discrepancy-report.md").write_text(
        "\n".join(discrepancy_lines) + "\n", encoding="utf-8"
    )


def evaluation_input_hashes(paths: Mapping[str, Path]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for name, path in paths.items():
        if path.is_file():
            hashes[name] = file_sha256(path)
        elif path.is_dir():
            hashes[name] = tree_sha256(path)
        else:
            raise FileNotFoundError(f"evaluation input does not exist: {path}")
    return hashes
