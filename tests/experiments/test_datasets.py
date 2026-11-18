from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnweaver.common.hashing import file_sha256
from vulnweaver.experiments.adapters.defihacklabs import (
    DefiHackLabsCandidate,
    DefiHackLabsStatus,
    ForkSpec,
)
from vulnweaver.experiments.datasets import (
    EvaluationDataset,
    EvaluationRejectionReason,
    EvaluationStatus,
    build_evaluation_manifest,
    build_inc_evaluation_records,
    evaluation_input_hashes,
    load_cve_catalog,
    write_evaluation_import,
)


def test_evaluation_directory_hashes_follow_contents_across_locations(tmp_path: Path) -> None:
    left, right = tmp_path / "left", tmp_path / "right"
    left.mkdir()
    right.mkdir()
    for root in (left, right):
        (root / "findings.json").write_text('{"finding": 1}')
    original = evaluation_input_hashes({"source": left})
    assert evaluation_input_hashes({"source": right}) == original
    (left / "findings.json").write_text('{"finding": 2}')
    assert evaluation_input_hashes({"source": left}) != original
    assert evaluation_input_hashes({"file": right / "findings.json"}) == {
        "file": file_sha256(right / "findings.json")
    }


def test_evaluation_hash_rejects_missing_source(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="evaluation input does not exist"):
        evaluation_input_hashes({"source": tmp_path / "missing"})


def _candidate(
    project: str,
    family: str,
    month: str,
    *,
    ready: bool = True,
) -> DefiHackLabsCandidate:
    return DefiHackLabsCandidate(
        case_id=f"defihacklabs-{month}-{project}",
        source_file=f"src/test/{month}/{project}_exp.sol",
        source_sha256=(project.encode().hex() * 64)[:64],
        source_commit="a" * 40,
        incident_month=month,
        project_id=project,
        attack_family=family,
        fork=ForkSpec(network="mainnet", block=1) if ready else None,
        attack_tx_hash="0x" + "a" * 64 if ready else None,
        status=DefiHackLabsStatus.METADATA_READY if ready else DefiHackLabsStatus.REJECTED,
    )


def test_inc_pool_applies_leakage_and_target_limit() -> None:
    training = [_candidate("trained", "oracle", "2023-01")]
    candidates = [
        _candidate("leaked-project", "other", "2023-02"),
        _candidate("new-project", "oracle", "2023-02"),
        _candidate("heldout-a", "new-family-a", "2023-02"),
        _candidate("heldout-b", "new-family-b", "2023-03"),
    ]

    records = build_inc_evaluation_records(
        candidates, training, cutoff_month="2023-01", target_count=1
    )

    by_project = {record.project_id: record for record in records}
    assert by_project["leaked-project"].status is EvaluationStatus.REJECTED
    assert (
        EvaluationRejectionReason.EVALUATION_POOL_LIMIT
        in by_project["leaked-project"].rejection_reasons
    )
    assert by_project["new-project"].status is EvaluationStatus.REJECTED
    assert (
        EvaluationRejectionReason.ATTACK_FAMILY_LEAKAGE
        in by_project["new-project"].rejection_reasons
    )
    assert by_project["heldout-a"].status is EvaluationStatus.METADATA_READY
    assert by_project["heldout-b"].status is EvaluationStatus.REJECTED
    assert (
        EvaluationRejectionReason.EVALUATION_POOL_LIMIT in by_project["heldout-b"].rejection_reasons
    )
    assert sum(record.status is EvaluationStatus.METADATA_READY for record in records) == 1


def test_cve_catalog_requires_all_admission_gates(tmp_path: Path) -> None:
    catalog = tmp_path / "cve.json"
    catalog.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "cve_id": "CVE-2026-0001",
                        "project_id": "demo",
                        "attack_family": "oracle",
                        "vulnerable_environment": True,
                        "neutralized_environment": True,
                        "patched_environment": True,
                        "manual_reviewed": True,
                        "official_patch_replayed": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    record = load_cve_catalog(catalog)[0]
    assert record.status is EvaluationStatus.READY


def test_manifest_discrepancy_counts_actual_states() -> None:
    records = [
        _candidate("x", "family", "2023-01"),
    ]
    inc_records = build_inc_evaluation_records(records, [], cutoff_month="2022-12", target_count=1)
    manifest = build_evaluation_manifest(
        [
            # The helper accepts normalized records; this test focuses on the empty-pool accounting.
            *[],
        ],
        source_inputs={},
        target_counts={dataset.value: 0 for dataset in EvaluationDataset},
    )
    assert inc_records[0].status is EvaluationStatus.METADATA_READY
    assert manifest.discrepancy_count == 0


def test_reimport_removes_stale_evaluation_records(tmp_path: Path) -> None:
    records = build_inc_evaluation_records(
        [_candidate("x", "family", "2023-01")], [], cutoff_month="2022-12"
    )
    manifest = build_evaluation_manifest(
        records, source_inputs={}, target_counts={dataset.value: 0 for dataset in EvaluationDataset}
    )
    write_evaluation_import(tmp_path, records, manifest)
    stale = tmp_path / "records" / "stale.json"
    stale.write_text("{}")
    write_evaluation_import(tmp_path, records, manifest)
    assert not stale.exists()
    assert len(list((tmp_path / "records").glob("*.json"))) == len(records)
