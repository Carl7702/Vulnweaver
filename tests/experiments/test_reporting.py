from __future__ import annotations

from pathlib import Path

import pytest

from vulnweaver.common.schema import VerificationStatus
from vulnweaver.experiments.datasets import (
    PAPER_TARGET_COUNTS,
    EvaluationDataset,
    EvaluationRecord,
    EvaluationStatus,
    build_evaluation_manifest,
)
from vulnweaver.experiments.reporting import (
    bootstrap_intervals,
    build_report,
    load_report,
    paired_permutation_test,
    write_report,
)
from vulnweaver.experiments.runner import (
    ExperimentCaseResult,
    ExperimentMethod,
    ExperimentUsage,
    RewardMode,
    discover_experiment_cases,
    run_experiment,
)


def test_report_bootstrap_permutation_and_failure_summary(tmp_path: Path) -> None:
    cases = discover_experiment_cases(Path("examples"))
    run = run_experiment(
        cases,
        tmp_path / "run",
        methods=(
            ExperimentMethod.DIRECT_PROMPTING,
            ExperimentMethod.PROGRESS_GUIDED_REWARD,
        ),
    )
    report = build_report(run, bootstrap_samples=100, seed=7)
    assert report.bootstrap_samples == 100
    assert len(report.uncertainty) == 2
    assert all(len(item.intervals) == 4 for item in report.uncertainty)
    assert len(report.paired_tests) == 3
    assert {test.metric for test in report.paired_tests} == {"epr", "vpr", "car"}
    assert report.resampling_unit == "project"
    assert report.seed == 7
    assert 0.0 <= report.paired_tests[0].p_value <= 1.0
    assert report.failures[0].counts == {"none": 3}
    write_report(tmp_path / "report", report)
    loaded = load_report(tmp_path / "report" / "report.json")
    assert loaded.run_id == run.run_id
    assert "Failure analysis" in (tmp_path / "report" / "report.md").read_text(encoding="utf-8")
    assert "offline_replay" in (tmp_path / "report" / "paper-table.csv").read_text()


def _result(case_id: str, success: bool, method: ExperimentMethod) -> ExperimentCaseResult:
    return ExperimentCaseResult(
        method=method,
        case_id=case_id,
        reward_mode=RewardMode.TERMINAL_ONLY,
        status=VerificationStatus.CAUSALLY_VALIDATED if success else VerificationStatus.UNRESOLVED,
        execution_proof=success,
        vulnerability_proof=success,
        causal_validation=success,
        latency_seconds=1.0,
        usage=ExperimentUsage(),
    )


def test_bootstrap_preserves_findings_in_one_project_as_one_block() -> None:
    results = [
        _result(str(index), index < 2, ExperimentMethod.DIRECT_PROMPTING) for index in range(3)
    ]
    projects = {item.case_id: "one-project" for item in results}
    intervals = bootstrap_intervals(results, samples=200, seed=42, project_ids=projects)
    assert all(
        item.lower == item.median == item.upper == 2 / 3
        for item in intervals
        if item.metric != "latency"
    )
    assert (
        bootstrap_intervals(list(reversed(results)), samples=200, seed=42, project_ids=projects)
        == intervals
    )


def test_bootstrap_weights_unequal_project_sizes_by_sampled_case_count() -> None:
    results = [
        _result(str(index), index < 3, ExperimentMethod.DIRECT_PROMPTING) for index in range(4)
    ]
    projects = {str(index): "large" if index < 3 else "small" for index in range(4)}
    intervals = bootstrap_intervals(results, samples=1_000, seed=42, project_ids=projects)
    car = next(item for item in intervals if item.metric == "car")
    assert (car.lower, car.median, car.upper) == (0.0, 0.75, 1.0)


def test_permutation_flips_whole_projects_and_rejects_incomplete_pairs() -> None:
    baseline = [_result(str(index), False, ExperimentMethod.DIRECT_PROMPTING) for index in range(3)]
    challenger = [
        _result(str(index), True, ExperimentMethod.PROGRESS_GUIDED_REWARD) for index in range(3)
    ]
    projects = {item.case_id: "one-project" for item in baseline}
    result = paired_permutation_test(
        baseline,
        challenger,
        baseline_method=ExperimentMethod.DIRECT_PROMPTING,
        challenger_method=ExperimentMethod.PROGRESS_GUIDED_REWARD,
        project_ids=projects,
        permutations=100,
    )
    assert result.paired_cases == 3
    assert result.paired_projects == 1
    assert result.observed_delta == 1.0
    assert result.p_value == 1.0
    with pytest.raises(ValueError, match="identical case pools"):
        paired_permutation_test(
            baseline,
            challenger[:1],
            baseline_method=ExperimentMethod.DIRECT_PROMPTING,
            challenger_method=ExperimentMethod.PROGRESS_GUIDED_REWARD,
            project_ids=projects,
        )
    with pytest.raises(ValueError, match="must be unique"):
        paired_permutation_test(
            baseline + baseline[:1],
            challenger,
            baseline_method=ExperimentMethod.DIRECT_PROMPTING,
            challenger_method=ExperimentMethod.PROGRESS_GUIDED_REWARD,
            project_ids=projects,
        )


def test_report_requires_complete_method_case_matrix(tmp_path: Path) -> None:
    run = run_experiment(
        discover_experiment_cases(Path("examples")),
        tmp_path / "run",
        methods=(ExperimentMethod.DIRECT_PROMPTING,),
    )
    broken = run.model_copy(update={"results": run.results[:-1]})
    with pytest.raises(ValueError, match="one result per method and case"):
        build_report(broken, bootstrap_samples=10)
    old_cases = tuple(case.model_copy(update={"project_id": None}) for case in run.cases)
    with pytest.raises(ValueError, match="project_id missing"):
        build_report(run.model_copy(update={"cases": old_cases}), bootstrap_samples=10)


def test_report_keeps_metadata_availability_separate_from_ready(tmp_path: Path) -> None:
    record = EvaluationRecord(
        record_id="finding",
        dataset=EvaluationDataset.D_MIX,
        source_file="metadata.json",
        source_sha256="a" * 64,
        project_id="project",
        attack_family="accounting",
        status=EvaluationStatus.CANDIDATE,
    )
    manifest = build_evaluation_manifest(
        [record],
        source_inputs={},
        target_counts={dataset.value: count for dataset, count in PAPER_TARGET_COUNTS.items()},
    )
    manifest_path = tmp_path / "import-manifest.json"
    manifest_path.write_text(manifest.model_dump_json())
    run = run_experiment(
        discover_experiment_cases(Path("examples")),
        tmp_path / "run",
        methods=(ExperimentMethod.DIRECT_PROMPTING,),
    )
    report = build_report(run, bootstrap_samples=10, evaluation_manifest=manifest_path)
    summary = report.evaluation_dataset_summaries["D_mix"]
    assert report.evaluation_actual_counts["D_mix"] == summary.candidate_count == 1
    assert summary.ready_count == 0
    assert report.evaluation_manifest_sha256
    write_report(tmp_path / "report", report)
    markdown = (tmp_path / "report" / "report.md").read_text()
    assert "| D_mix | 121 | 1 | 0 | 0 | 0 |" in markdown
