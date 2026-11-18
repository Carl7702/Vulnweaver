"""Paper-facing summaries for experiment runs and evaluation-pool discrepancies."""

from __future__ import annotations

import csv
import random
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal

from pydantic import Field

from vulnweaver.common.hashing import file_sha256, stable_hash
from vulnweaver.common.schema import StrictModel
from vulnweaver.experiments.datasets import EvaluationDatasetSummary, EvaluationManifest
from vulnweaver.experiments.runner import (
    ExperimentCaseResult,
    ExperimentMethod,
    ExperimentRun,
    MethodMetrics,
)

PROOF_METRICS: tuple[Literal["epr", "vpr", "car"], ...] = ("epr", "vpr", "car")
REPORT_METRICS: tuple[Literal["epr", "vpr", "car", "latency"], ...] = (*PROOF_METRICS, "latency")


class BootstrapInterval(StrictModel):
    metric: Literal["epr", "vpr", "car", "latency"]
    lower: float
    median: float
    upper: float
    samples: int = Field(ge=1)


class MethodUncertainty(StrictModel):
    method: ExperimentMethod
    project_count: int = Field(ge=1)
    intervals: tuple[BootstrapInterval, ...]


class PairedPermutation(StrictModel):
    baseline: ExperimentMethod
    challenger: ExperimentMethod
    metric: Literal["epr", "vpr", "car"]
    paired_cases: int = Field(ge=0)
    paired_projects: int = Field(ge=1)
    observed_delta: float
    p_value: float = Field(ge=0.0, le=1.0)
    permutations: int = Field(ge=1)


class FailureSummary(StrictModel):
    method: ExperimentMethod
    counts: dict[str, int]


class ExperimentReport(StrictModel):
    schema_version: str = "1.1"
    evaluation_mode: Literal["offline_replay"] = "offline_replay"
    resource_accounting: Literal["profiled"] = "profiled"
    resampling_unit: Literal["project"] = "project"
    seed: int
    run_id: str
    run_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_pool_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bootstrap_samples: int = Field(ge=1)
    metrics: tuple[MethodMetrics, ...]
    uncertainty: tuple[MethodUncertainty, ...]
    paired_tests: tuple[PairedPermutation, ...]
    failures: tuple[FailureSummary, ...]
    evaluation_manifest: str | None = None
    evaluation_manifest_sha256: str | None = None
    evaluation_discrepancy_count: int | None = Field(default=None, ge=0)
    evaluation_actual_counts: dict[str, int] = Field(default_factory=dict)
    evaluation_dataset_summaries: dict[str, EvaluationDatasetSummary] = Field(default_factory=dict)


def _quantile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def _metric_value(result: ExperimentCaseResult, metric: str) -> float:
    if metric == "epr":
        return float(result.execution_proof)
    if metric == "vpr":
        return float(result.vulnerability_proof)
    if metric == "car":
        return float(result.causal_validation)
    if metric == "latency":
        return result.latency_seconds
    raise ValueError(f"unsupported report metric: {metric}")


def bootstrap_intervals(
    results: Sequence[ExperimentCaseResult],
    *,
    samples: int,
    seed: int,
    project_ids: Mapping[str, str],
) -> tuple[BootstrapInterval, ...]:
    if not results:
        raise ValueError("cannot bootstrap an empty result set")
    if samples < 1:
        raise ValueError("bootstrap sample count must be positive")
    if len({item.case_id for item in results}) != len(results):
        raise ValueError("bootstrap case ids must be unique")
    clusters: dict[str, list[ExperimentCaseResult]] = defaultdict(list)
    for item in sorted(results, key=lambda item: item.case_id):
        project = project_ids.get(item.case_id)
        if not project:
            raise ValueError(f"project_id required for clustered bootstrap: {item.case_id}")
        clusters[project].append(item)
    blocks = [clusters[project] for project in sorted(clusters)]
    rng = random.Random(seed)
    estimates: dict[str, list[float]] = {metric: [] for metric in ("epr", "vpr", "car", "latency")}
    totals = {
        metric: [sum(_metric_value(item, metric) for item in block) for block in blocks]
        for metric in estimates
    }
    for _ in range(samples):
        selected = [rng.randrange(len(blocks)) for _ in blocks]
        count = sum(len(blocks[index]) for index in selected)
        for metric in estimates:
            estimates[metric].append(sum(totals[metric][index] for index in selected) / count)
    intervals: list[BootstrapInterval] = []
    for metric in REPORT_METRICS:
        intervals.append(
            BootstrapInterval(
                metric=metric,
                lower=_quantile(estimates[metric], 0.025),
                median=_quantile(estimates[metric], 0.5),
                upper=_quantile(estimates[metric], 0.975),
                samples=samples,
            )
        )
    return tuple(intervals)


def paired_permutation_test(
    baseline: Sequence[ExperimentCaseResult],
    challenger: Sequence[ExperimentCaseResult],
    *,
    baseline_method: ExperimentMethod,
    challenger_method: ExperimentMethod,
    project_ids: Mapping[str, str],
    metric: Literal["epr", "vpr", "car"] = "car",
    permutations: int = 10_000,
    seed: int = 42,
) -> PairedPermutation:
    if permutations < 1:
        raise ValueError("permutation sample count must be positive")
    left = {item.case_id: item for item in baseline}
    right = {item.case_id: item for item in challenger}
    if len(left) != len(baseline) or len(right) != len(challenger):
        raise ValueError("paired permutation case ids must be unique")
    if left.keys() != right.keys():
        raise ValueError("paired permutation requires identical case pools")
    if any(item.method is not baseline_method for item in baseline) or any(
        item.method is not challenger_method for item in challenger
    ):
        raise ValueError("paired permutation method does not match results")
    case_ids = sorted(left)
    if not case_ids:
        raise ValueError("paired permutation test has no common case ids")
    cluster_differences: dict[str, float] = defaultdict(float)
    for case_id in case_ids:
        project = project_ids.get(case_id)
        if not project:
            raise ValueError(f"project_id required for clustered permutation: {case_id}")
        cluster_differences[project] += _metric_value(right[case_id], metric) - _metric_value(
            left[case_id], metric
        )
    differences = [cluster_differences[project] for project in sorted(cluster_differences)]
    observed = sum(differences) / len(case_ids)
    rng = random.Random(seed)
    exceed = 0
    for _ in range(permutations):
        signed = [difference if rng.getrandbits(1) else -difference for difference in differences]
        permuted = sum(signed) / len(case_ids)
        if abs(permuted) >= abs(observed):
            exceed += 1
    return PairedPermutation(
        baseline=baseline_method,
        challenger=challenger_method,
        metric=metric,
        paired_cases=len(case_ids),
        paired_projects=len(cluster_differences),
        observed_delta=observed,
        p_value=(exceed + 1) / (permutations + 1),
        permutations=permutations,
    )


def _load_evaluation_manifest(path: Path | None) -> EvaluationManifest | None:
    if path is None:
        return None
    return EvaluationManifest.model_validate_json(path.read_text(encoding="utf-8"))


def build_report(
    run: ExperimentRun,
    *,
    bootstrap_samples: int = 10_000,
    seed: int = 42,
    comparisons: Sequence[tuple[ExperimentMethod, ExperimentMethod]] = (),
    evaluation_manifest: Path | None = None,
) -> ExperimentReport:
    if len({item.case_id for item in run.cases}) != len(run.cases):
        raise ValueError("report case ids must be unique")
    project_ids: dict[str, str] = {}
    for case in run.cases:
        if not case.project_id:
            raise ValueError("project_id missing from experiment; rerun vw evaluate")
        project_ids[case.case_id] = case.project_id
    if not run.methods or len(set(run.methods)) != len(run.methods):
        raise ValueError("report requires unique non-empty methods")
    if {item.method for item in run.results} != set(run.methods):
        raise ValueError("report result methods do not match experiment methods")
    for method in run.methods:
        ids = [item.case_id for item in run.results if item.method is method]
        if len(ids) != len(set(ids)) or set(ids) != set(project_ids):
            raise ValueError("report requires one result per method and case")
    uncertainty = tuple(
        MethodUncertainty(
            method=method,
            project_count=len(set(project_ids.values())),
            intervals=bootstrap_intervals(
                [item for item in run.results if item.method is method],
                samples=bootstrap_samples,
                seed=seed,
                project_ids=project_ids,
            ),
        )
        for method in run.methods
    )
    by_method = {
        method: [item for item in run.results if item.method is method] for method in run.methods
    }
    selected_comparisons = tuple(comparisons)
    if not selected_comparisons and len(run.methods) >= 2:
        selected_comparisons = tuple((run.methods[0], method) for method in run.methods[1:])
    if any(
        baseline not in by_method or challenger not in by_method
        for baseline, challenger in selected_comparisons
    ):
        raise ValueError("report comparison method absent from experiment")
    paired = tuple(
        paired_permutation_test(
            by_method[baseline],
            by_method[challenger],
            baseline_method=baseline,
            challenger_method=challenger,
            project_ids=project_ids,
            metric=metric,
            permutations=bootstrap_samples,
            seed=seed + index,
        )
        for index, (baseline, challenger) in enumerate(selected_comparisons)
        for metric in PROOF_METRICS
    )
    failures = tuple(
        FailureSummary(
            method=method,
            counts=dict(
                sorted(Counter(item.failure_type.value for item in by_method[method]).items())
            ),
        )
        for method in run.methods
    )
    manifest = _load_evaluation_manifest(evaluation_manifest)
    actual_counts: dict[str, int] = {}
    discrepancy_count: int | None = None
    if manifest is not None:
        discrepancy_count = manifest.discrepancy_count
        actual_counts = {
            dataset: summary.candidate_count + summary.metadata_ready_count + summary.ready_count
            for dataset, summary in manifest.dataset_summaries.items()
        }
    return ExperimentReport(
        evaluation_mode=run.evaluation_mode,
        resource_accounting=run.resource_accounting,
        seed=seed,
        run_id=run.run_id,
        run_sha256=stable_hash(run.model_dump(mode="json")),
        case_pool_sha256=run.case_pool_sha256,
        bootstrap_samples=bootstrap_samples,
        metrics=run.metrics,
        uncertainty=uncertainty,
        paired_tests=paired,
        failures=failures,
        evaluation_manifest=str(evaluation_manifest.resolve())
        if evaluation_manifest is not None
        else None,
        evaluation_manifest_sha256=file_sha256(evaluation_manifest)
        if evaluation_manifest is not None
        else None,
        evaluation_discrepancy_count=discrepancy_count,
        evaluation_actual_counts=actual_counts,
        evaluation_dataset_summaries=manifest.dataset_summaries if manifest else {},
    )


def write_report(output: Path, report: ExperimentReport) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Experiment report",
        "",
        f"Run: `{report.run_id}`",
        f"Case pool: `{report.case_pool_sha256}`",
        f"Bootstrap/permutation samples: `{report.bootstrap_samples}`; seed: `{report.seed}`; "
        f"resampling unit: `{report.resampling_unit}`.",
        f"Mode: `{report.evaluation_mode}`; resource accounting: `{report.resource_accounting}`.",
        "",
        "Protocol smoke results use shared replay evidence and placeholder candidates. "
        "Resource counts follow prescribed profiles; latency measures local replay processing. "
        "The table supports protocol validation; model and reward comparisons require live runs.",
        "",
        "## Point estimates",
        "",
        "| Method | Cases | EPR | VPR | CAR | Mean latency (s) |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for metric in report.metrics:
        lines.append(
            f"| {metric.method.value} | {metric.cases} | {metric.epr:.4f} | {metric.vpr:.4f} | "
            f"{metric.car:.4f} | {metric.mean_latency_seconds:.6f} |"
        )
    lines.extend(
        [
            "",
            "## Project-clustered uncertainty",
            "",
            "| Method | Metric | 2.5% | Median | 97.5% |",
            "|---|---|---:|---:|---:|",
        ]
    )
    for method in report.uncertainty:
        for interval in method.intervals:
            lines.append(
                f"| {method.method.value} | {interval.metric} | {interval.lower:.4f} | "
                f"{interval.median:.4f} | {interval.upper:.4f} |"
            )
    lines.extend(
        [
            "",
            "## Paired tests",
            "",
            "Project-level paired sign flips preserve all findings from each project together. "
            "P-values are two-sided, unadjusted Monte Carlo estimates with add-one correction.",
            "",
            "| Baseline | Challenger | Metric | Cases | Projects | Δ | p-value |",
            "|---|---|---|---:|---:|---:|---:|",
        ]
    )
    for test in report.paired_tests:
        lines.append(
            f"| {test.baseline.value} | {test.challenger.value} | {test.metric} | "
            f"{test.paired_cases} | {test.paired_projects} | "
            f"{test.observed_delta:.4f} | {test.p_value:.4f} |"
        )
    lines.extend(["", "## Failure analysis", "", "| Method | Failure counts |", "|---|---|"])
    for failure in report.failures:
        counts = ", ".join(f"{key}={value}" for key, value in failure.counts.items())
        lines.append(f"| {failure.method.value} | {counts or 'none'} |")
    if report.evaluation_manifest is not None:
        lines.extend(
            [
                "",
                "## Evaluation discrepancy",
                "",
                f"Manifest: `{report.evaluation_manifest}`",
                f"Discrepancy count: `{report.evaluation_discrepancy_count}`",
                "",
                "Candidate and metadata-ready counts describe availability before executable "
                "admission. The discrepancy count compares these available records "
                "to paper targets.",
                "",
                "| Dataset | Target | Candidate | Metadata-ready | Ready | Rejected |",
                "|---|---:|---:|---:|---:|---:|---:|",
            ]
        )
        lines.extend(
            f"| {dataset} | {summary.target_count} | {summary.candidate_count} | "
            f"{summary.metadata_ready_count} | {summary.ready_count} | {summary.rejected_count} |"
            for dataset, summary in sorted(report.evaluation_dataset_summaries.items())
        )
    (output / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    with (output / "paper-table.csv").open("w", newline="", encoding="utf-8") as stream:
        fields = [
            "method",
            "evaluation_mode",
            "resource_accounting",
            "cases",
            "projects",
            "epr",
            "epr_lower",
            "epr_upper",
            "vpr",
            "vpr_lower",
            "vpr_upper",
            "car",
            "car_lower",
            "car_upper",
            "mean_latency_seconds",
            "model_calls",
            "input_tokens",
            "output_tokens",
            "evm_executions",
        ]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        uncertainty = {item.method: item for item in report.uncertainty}
        for metric in report.metrics:
            row = {
                key: value for key, value in metric.model_dump(mode="json").items() if key in fields
            }
            row.update(
                evaluation_mode=report.evaluation_mode,
                resource_accounting=report.resource_accounting,
                projects=uncertainty[metric.method].project_count,
            )
            for interval in uncertainty[metric.method].intervals:
                if interval.metric != "latency":
                    row[f"{interval.metric}_lower"] = interval.lower
                    row[f"{interval.metric}_upper"] = interval.upper
            writer.writerow(row)


def load_report(path: Path) -> ExperimentReport:
    return ExperimentReport.model_validate_json(path.read_text(encoding="utf-8"))
