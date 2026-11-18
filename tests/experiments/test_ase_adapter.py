from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulnweaver.experiments.adapters.ase import (
    CandidateStatus,
    RejectionReason,
    scan_ase,
    write_import,
)


def _project(
    *, commit: str = "abcdef123456", finding_ids: tuple[int, ...] = (0,)
) -> dict[str, Any]:
    return {
        "path": "report.pdf",
        "project_info": {
            "url": "https://example.invalid/repo",
            "commit_id": commit,
            "address": "0x1111111111111111111111111111111111111111",
            "chain": "ethereum",
            "compiler_version": ["v0.8.24"],
            "project_path": {"Contract": "contracts/Contract.sol"},
        },
        "findings": [
            {
                "id": finding_id,
                "title": f"Finding {finding_id}",
                "description": "A test finding.",
                "severity": "high",
                "location": "Contract.sol#L1",
            }
            for finding_id in finding_ids
        ],
    }


def test_scan_counts_projects_and_findings_separately(tmp_path: Path) -> None:
    mix = tmp_path / "data" / "D_mix" / "D_mix"
    log = tmp_path / "data" / "D_log"
    mix.mkdir(parents=True)
    log.mkdir(parents=True)
    (mix / "one.json").write_text(json.dumps(_project(finding_ids=(0, 1))), encoding="utf-8")
    (log / "two.json").write_text(json.dumps(_project(commit="n/a")), encoding="utf-8")

    candidates, manifest = scan_ase(tmp_path)

    assert manifest.project_counts == {"D_log": 1, "D_mix": 1}
    assert manifest.finding_counts == {"D_log": 1, "D_mix": 2}
    assert manifest.candidate_count == 3
    assert manifest.rejection_counts == {"missing_commit": 1}
    assert sum(item.status is CandidateStatus.CANDIDATE for item in candidates) == 2


def test_duplicate_finding_ids_are_rejected_without_overwrite(tmp_path: Path) -> None:
    dataset = tmp_path / "D_mix"
    dataset.mkdir()
    (dataset / "duplicate.json").write_text(
        json.dumps(_project(finding_ids=(4, 4))),
        encoding="utf-8",
    )

    candidates, manifest = scan_ase(tmp_path)
    output = tmp_path / "output"
    write_import(output, candidates, manifest)

    assert len(candidates) == 2
    assert len({item.candidate_id for item in candidates}) == 2
    assert all(
        RejectionReason.DUPLICATE_FINDING_ID in item.rejection_reasons for item in candidates
    )
    assert len(list((output / "candidates").glob("*.json"))) == 2


def test_require_source_reports_missing_source(tmp_path: Path) -> None:
    dataset = tmp_path / "D_log"
    dataset.mkdir()
    (dataset / "missing.json").write_text(json.dumps(_project()), encoding="utf-8")

    candidates, _ = scan_ase(tmp_path, require_source=True, source_root=tmp_path / "sources")

    assert candidates[0].status is CandidateStatus.REJECTED
    assert RejectionReason.MISSING_SOURCE in candidates[0].rejection_reasons


def test_scan_is_deterministic(tmp_path: Path) -> None:
    dataset = tmp_path / "D_mix"
    dataset.mkdir()
    (dataset / "stable.json").write_text(json.dumps(_project()), encoding="utf-8")

    first_candidates, first_manifest = scan_ase(tmp_path)
    second_candidates, second_manifest = scan_ase(tmp_path)

    assert first_manifest.candidates_sha256 == second_manifest.candidates_sha256
    assert first_candidates[0].candidate_sha256 == second_candidates[0].candidate_sha256
