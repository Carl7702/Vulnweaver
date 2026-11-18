"""Offline, budgeted baseline and ablation evaluation.

The experiment runner deliberately separates method accounting from the
independent verifier.  Every method receives the same immutable case pool and
the same replay evidence; only its construction profile and reward label vary.
This makes the protocol table reproducible on a machine without a model server or an
RPC endpoint.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from vulnweaver.common.config import config_snapshot
from vulnweaver.common.hashing import file_sha256, stable_hash
from vulnweaver.common.manifest import create_manifest, write_manifest
from vulnweaver.common.protocols import ModelBackend
from vulnweaver.common.schema import (
    Budget,
    ResourceUsage,
    StrictModel,
    ValidationReport,
    VerificationStatus,
)
from vulnweaver.policy_learning.models import FakeModelBackend, ModelMessage
from vulnweaver.task_construction.cases import case_hash, load_case
from vulnweaver.validation.obligations import TemplateObligationEvaluator
from vulnweaver.validation.replay import ReplayExecutionBackend, load_replay_bundle
from vulnweaver.validation.verifier import IndependentVerifier


class ExperimentMethod(StrEnum):
    DIRECT_PROMPTING = "direct_prompting"
    POCFORGE_SINGLE_AGENT = "pocforge_single_agent"
    FIXED_WORKFLOW = "fixed_workflow"
    HEURISTIC_SCHEDULING = "heuristic_scheduling"
    HIERARCHICAL_COORDINATION = "hierarchical_coordination"
    TERMINAL_ONLY_REWARD = "terminal_only_reward"
    IMMEDIATE_PROGRESS_REWARD = "immediate_progress_reward"
    PROGRESS_GUIDED_REWARD = "progress_guided_reward"


class RewardMode(StrEnum):
    TERMINAL_ONLY = "terminal_only"
    IMMEDIATE_PROGRESS = "immediate_progress"
    PROGRESS_GUIDED = "progress_guided"


class ExperimentFailure(StrEnum):
    NONE = "none"
    ENVIRONMENT = "environment"
    UNRESOLVED = "unresolved"
    MODEL_OUTPUT = "model_output"
    BUDGET = "budget"
    INTERNAL = "internal"


class ExperimentBudget(StrictModel):
    """The shared per-case budget from the protocol section of the plan."""

    model_calls: int = Field(default=20, ge=0)
    input_tokens: int = Field(default=65_536, ge=0)
    output_tokens: int = Field(default=24_576, ge=0)
    candidate_pocs: int = Field(default=4, ge=0)
    evm_executions: int = Field(default=12, ge=0)
    scheduling_decisions: int = Field(default=24, ge=0)
    wall_clock_seconds: int = Field(default=900, ge=0)

    @classmethod
    def paper_default(cls) -> ExperimentBudget:
        return cls()

    @classmethod
    def from_case_budget(cls, budget: Budget) -> ExperimentBudget:
        return cls(**budget.model_dump())


class ExperimentUsage(StrictModel):
    model_calls: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    candidate_pocs: int = Field(default=0, ge=0)
    evm_executions: int = Field(default=0, ge=0)
    scheduling_decisions: int = Field(default=0, ge=0)
    wall_clock_seconds: float = Field(default=0.0, ge=0.0)

    def within(self, budget: ExperimentBudget) -> bool:
        return all(
            getattr(self, field) <= getattr(budget, field)
            for field in (
                "model_calls",
                "input_tokens",
                "output_tokens",
                "candidate_pocs",
                "evm_executions",
                "scheduling_decisions",
                "wall_clock_seconds",
            )
        )

    def to_resource_usage(self) -> ResourceUsage:
        return ResourceUsage(
            model_calls=self.model_calls,
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
            evm_executions=self.evm_executions,
            wall_clock_seconds=self.wall_clock_seconds,
        )


class ExperimentCase(StrictModel):
    case_id: str
    project_id: str | None = Field(default=None, min_length=1)
    dataset: str = "golden"
    case_path: str
    replay_path: str
    case_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    replay_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class MethodProfile(StrictModel):
    method: ExperimentMethod
    reward_mode: RewardMode
    model_calls: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    candidate_pocs: int = Field(ge=0)
    scheduling_decisions: int = Field(ge=0)


class ExperimentCaseResult(StrictModel):
    method: ExperimentMethod
    case_id: str
    reward_mode: RewardMode
    status: VerificationStatus
    execution_proof: bool
    vulnerability_proof: bool
    causal_validation: bool
    latency_seconds: float = Field(ge=0.0)
    usage: ExperimentUsage
    failure_type: ExperimentFailure = ExperimentFailure.NONE
    error: str | None = None


class MethodMetrics(StrictModel):
    method: ExperimentMethod
    reward_mode: RewardMode
    cases: int = Field(ge=0)
    epr: float = Field(ge=0.0, le=1.0)
    vpr: float = Field(ge=0.0, le=1.0)
    car: float = Field(ge=0.0, le=1.0)
    mean_latency_seconds: float = Field(ge=0.0)
    model_calls: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    candidate_pocs: int = Field(ge=0)
    scheduling_decisions: int = Field(ge=0)
    evm_executions: int = Field(ge=0)
    failure_types: dict[str, int]


class ExperimentRun(StrictModel):
    schema_version: str = "1.1"
    evaluation_mode: Literal["offline_replay"] = "offline_replay"
    resource_accounting: Literal["profiled"] = "profiled"
    model_backend: str = "FakeModelBackend"
    run_id: str
    started_at: datetime
    finished_at: datetime
    seed: int
    budget: ExperimentBudget
    case_pool_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    cases: tuple[ExperimentCase, ...]
    methods: tuple[ExperimentMethod, ...]
    results: tuple[ExperimentCaseResult, ...]
    metrics: tuple[MethodMetrics, ...]
    manifest_path: str


@dataclass(frozen=True)
class _Profile:
    reward_mode: RewardMode
    model_calls: int
    input_tokens: int
    output_tokens: int
    candidate_pocs: int
    scheduling_decisions: int


# Accounting is intentionally explicit and identical for every case in a run.
_PROFILES: dict[ExperimentMethod, _Profile] = {
    ExperimentMethod.DIRECT_PROMPTING: _Profile(RewardMode.TERMINAL_ONLY, 1, 1_000, 500, 1, 1),
    ExperimentMethod.POCFORGE_SINGLE_AGENT: _Profile(RewardMode.TERMINAL_ONLY, 2, 1_500, 700, 1, 2),
    ExperimentMethod.FIXED_WORKFLOW: _Profile(RewardMode.TERMINAL_ONLY, 6, 3_000, 1_200, 1, 6),
    ExperimentMethod.HEURISTIC_SCHEDULING: _Profile(
        RewardMode.IMMEDIATE_PROGRESS, 4, 2_400, 1_000, 1, 6
    ),
    ExperimentMethod.HIERARCHICAL_COORDINATION: _Profile(
        RewardMode.PROGRESS_GUIDED, 6, 3_200, 1_400, 1, 12
    ),
    ExperimentMethod.TERMINAL_ONLY_REWARD: _Profile(
        RewardMode.TERMINAL_ONLY, 4, 2_400, 1_000, 1, 6
    ),
    ExperimentMethod.IMMEDIATE_PROGRESS_REWARD: _Profile(
        RewardMode.IMMEDIATE_PROGRESS, 4, 2_400, 1_000, 1, 6
    ),
    ExperimentMethod.PROGRESS_GUIDED_REWARD: _Profile(
        RewardMode.PROGRESS_GUIDED, 4, 2_400, 1_000, 1, 6
    ),
}

DEFAULT_METHODS: tuple[ExperimentMethod, ...] = tuple(ExperimentMethod)


def discover_experiment_cases(root: Path) -> tuple[ExperimentCase, ...]:
    """Discover only case/replay pairs; incomplete records are not silently used."""

    found: list[ExperimentCase] = []
    for case_path in sorted(root.rglob("case.json")):
        replay_path = case_path.with_name("replay.json")
        if not replay_path.is_file():
            continue
        case = load_case(case_path, verify_inputs=True)
        bundle = load_replay_bundle(replay_path)
        if bundle.case_sha256 != case_hash(case):
            raise ValueError(f"replay/case hash mismatch for {case_path}")
        found.append(
            ExperimentCase(
                case_id=case.case_id,
                project_id=case.project_id,
                case_path=str(case_path.resolve()),
                replay_path=str(replay_path.resolve()),
                case_sha256=case_hash(case),
                replay_sha256=file_sha256(replay_path),
            )
        )
    if not found:
        raise ValueError(f"no complete case/replay pairs found below {root}")
    if len({item.case_id for item in found}) != len(found):
        raise ValueError("experiment case ids must be unique")
    return tuple(found)


def _case_pool_hash(cases: Sequence[ExperimentCase]) -> str:
    return stable_hash(
        [
            {
                "case_id": item.case_id,
                "project_id": item.project_id,
                "dataset": item.dataset,
                "case_sha256": item.case_sha256,
                "replay_sha256": item.replay_sha256,
            }
            for item in cases
        ]
    )


def _profile_usage(profile: _Profile, *, latency: float) -> ExperimentUsage:
    # The verifier performs one Ev and one Er execution for the replay protocol.
    return ExperimentUsage(
        model_calls=profile.model_calls,
        input_tokens=profile.input_tokens,
        output_tokens=profile.output_tokens,
        candidate_pocs=profile.candidate_pocs,
        evm_executions=2,
        scheduling_decisions=profile.scheduling_decisions,
        wall_clock_seconds=latency,
    )


def _failure_for_report(report: ValidationReport) -> ExperimentFailure:
    if report.status is VerificationStatus.CAUSALLY_VALIDATED:
        return ExperimentFailure.NONE
    if report.status is VerificationStatus.ENVERROR:
        return ExperimentFailure.ENVIRONMENT
    return ExperimentFailure.UNRESOLVED


def _proof_flags(report: ValidationReport) -> tuple[bool, bool, bool]:
    execution = report.status in {
        VerificationStatus.EXECUTION_EVIDENCED,
        VerificationStatus.CAUSALLY_VALIDATED,
    }
    vulnerability = bool(report.vulnerable_results) and all(
        item.status.value == "satisfied" for item in report.vulnerable_results
    )
    causal = report.status is VerificationStatus.CAUSALLY_VALIDATED
    return execution, vulnerability, causal


def _invoke_offline_model(
    backend: ModelBackend,
    method: ExperimentMethod,
    case: ExperimentCase,
    calls: int,
) -> str:
    """Consume exactly the profiled calls without exposing sealed evidence."""

    response = ""
    for index in range(calls):
        response = backend.complete(
            [
                ModelMessage(
                    role="system",
                    content=(
                        "Return an offline construction plan; do not request source or RPC data."
                    ),
                ),
                ModelMessage(
                    role="user",
                    content=f"method={method.value}; case_id={case.case_id}; step={index}",
                ),
            ]
        ).content
    return response


def _write_protocol_marker(
    directory: Path,
    method: ExperimentMethod,
    case: ExperimentCase,
    model_response: str,
    *,
    pocforge_source: Path | None,
) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    # Offline replay does not execute candidate code. This marker binds the
    # profiled method and model response without resembling a usable PoC.
    provenance = "available" if pocforge_source is not None else "not_supplied"
    payload = (
        "// VulnWeaver offline protocol marker; not executable candidate code.\n"
        f"// method={method.value}\n"
        f"// case_id={case.case_id}\n"
        f"// baseline_source={provenance}\n"
        f"// plan_digest={stable_hash(model_response)}\n"
        "contract OfflineProtocolMarker {}\n"
    )
    (directory / "ProtocolMarker.sol").write_text(payload, encoding="utf-8")


def _run_one(
    method: ExperimentMethod,
    case_ref: ExperimentCase,
    output: Path,
    budget: ExperimentBudget,
    backend: ModelBackend,
    *,
    pocforge_source: Path | None,
) -> ExperimentCaseResult:
    profile = _PROFILES[method]
    case = load_case(Path(case_ref.case_path), verify_inputs=True)
    usage_without_latency = _profile_usage(profile, latency=0.0)
    if not usage_without_latency.within(budget):
        return ExperimentCaseResult(
            method=method,
            case_id=case.case_id,
            reward_mode=profile.reward_mode,
            status=VerificationStatus.UNRESOLVED,
            execution_proof=False,
            vulnerability_proof=False,
            causal_validation=False,
            latency_seconds=0.0,
            usage=usage_without_latency,
            failure_type=ExperimentFailure.BUDGET,
            error="method profile exceeds shared per-case budget",
        )
    started = time.monotonic()
    candidate_dir = output / "candidates" / method.value / case.case_id
    try:
        response = _invoke_offline_model(backend, method, case_ref, profile.model_calls)
        _write_protocol_marker(
            candidate_dir,
            method,
            case_ref,
            response,
            pocforge_source=pocforge_source,
        )
        bundle = load_replay_bundle(Path(case_ref.replay_path))
        records = {record.environment_id: record for record in bundle.records}
        verifier = IndependentVerifier(
            lambda: ReplayExecutionBackend(records),
            TemplateObligationEvaluator(),
        )
        report = verifier.verify(candidate_dir, case)
        latency = time.monotonic() - started
        usage = _profile_usage(profile, latency=latency)
        if not usage.within(budget):
            return ExperimentCaseResult(
                method=method,
                case_id=case.case_id,
                reward_mode=profile.reward_mode,
                status=VerificationStatus.UNRESOLVED,
                execution_proof=False,
                vulnerability_proof=False,
                causal_validation=False,
                latency_seconds=latency,
                usage=usage,
                failure_type=ExperimentFailure.BUDGET,
                error="measured wall-clock usage exceeded shared per-case budget",
            )
        execution, vulnerability, causal = _proof_flags(report)
        return ExperimentCaseResult(
            method=method,
            case_id=case.case_id,
            reward_mode=profile.reward_mode,
            status=report.status,
            execution_proof=execution,
            vulnerability_proof=vulnerability,
            causal_validation=causal,
            latency_seconds=latency,
            usage=usage,
            failure_type=_failure_for_report(report),
            error="; ".join(report.errors) if report.errors else None,
        )
    except (OSError, KeyError, RuntimeError, ValueError) as error:
        latency = time.monotonic() - started
        return ExperimentCaseResult(
            method=method,
            case_id=case.case_id,
            reward_mode=profile.reward_mode,
            status=VerificationStatus.UNRESOLVED,
            execution_proof=False,
            vulnerability_proof=False,
            causal_validation=False,
            latency_seconds=latency,
            usage=_profile_usage(profile, latency=latency),
            failure_type=(
                ExperimentFailure.MODEL_OUTPUT
                if "model" in str(error).lower()
                else ExperimentFailure.INTERNAL
            ),
            error=str(error),
        )


def aggregate_metrics(
    results: Iterable[ExperimentCaseResult],
) -> tuple[MethodMetrics, ...]:
    grouped: dict[ExperimentMethod, list[ExperimentCaseResult]] = {}
    for result in results:
        grouped.setdefault(result.method, []).append(result)
    metrics: list[MethodMetrics] = []
    for method in ExperimentMethod:
        items = grouped.get(method, [])
        if not items:
            continue
        count = len(items)
        usage = [item.usage for item in items]
        failures = Counter(item.failure_type.value for item in items)
        metrics.append(
            MethodMetrics(
                method=method,
                reward_mode=items[0].reward_mode,
                cases=count,
                # EPR: execution evidence in Ev; VPR: all four Ev obligations;
                # CAR: Ev/Er causal validation.
                epr=sum(item.execution_proof for item in items) / count,
                vpr=sum(item.vulnerability_proof for item in items) / count,
                car=sum(item.causal_validation for item in items) / count,
                mean_latency_seconds=sum(item.latency_seconds for item in items) / count,
                model_calls=sum(item.model_calls for item in usage),
                input_tokens=sum(item.input_tokens for item in usage),
                output_tokens=sum(item.output_tokens for item in usage),
                candidate_pocs=sum(item.candidate_pocs for item in usage),
                scheduling_decisions=sum(item.scheduling_decisions for item in usage),
                evm_executions=sum(item.evm_executions for item in usage),
                failure_types=dict(sorted(failures.items())),
            )
        )
    return tuple(metrics)


def run_experiment(
    cases: Sequence[ExperimentCase],
    output: Path,
    *,
    methods: Sequence[ExperimentMethod] = DEFAULT_METHODS,
    budget: ExperimentBudget | None = None,
    seed: int = 42,
    model_backend: ModelBackend | None = None,
    pocforge_source: Path | None = None,
) -> ExperimentRun:
    """Run all requested methods over one shared, immutable replay case pool."""

    if not cases:
        raise ValueError("experiment case pool must not be empty")
    if len({item.case_id for item in cases}) != len(cases):
        raise ValueError("experiment case ids must be unique")
    for case_ref in cases:
        case = load_case(Path(case_ref.case_path), verify_inputs=True)
        if (
            case.case_id != case_ref.case_id
            or case.project_id != case_ref.project_id
            or case_hash(case) != case_ref.case_sha256
            or file_sha256(Path(case_ref.replay_path)) != case_ref.replay_sha256
        ):
            raise ValueError(f"experiment input changed since discovery: {case_ref.case_id}")
    selected = tuple(dict.fromkeys(methods))
    if not selected:
        raise ValueError("at least one experiment method is required")
    unknown = [method for method in selected if method not in _PROFILES]
    if unknown:
        raise ValueError(f"unsupported experiment methods: {unknown}")
    actual_budget = budget or ExperimentBudget.paper_default()
    output.mkdir(parents=True, exist_ok=True)
    started = datetime.now(UTC)
    backend = model_backend or FakeModelBackend(["offline-plan"] * 10_000)
    results: list[ExperimentCaseResult] = []
    for method in selected:
        for case_ref in cases:
            results.append(
                _run_one(
                    method,
                    case_ref,
                    output,
                    actual_budget,
                    backend,
                    pocforge_source=pocforge_source,
                )
            )
    finished = datetime.now(UTC)
    metrics = aggregate_metrics(results)
    config = {
        "evaluation_mode": "offline_replay",
        "resource_accounting": "profiled",
        "model_backend": type(backend).__name__,
        "code_sha256": stable_hash(
            {
                path.relative_to(Path(__file__).parent).as_posix(): file_sha256(path)
                for path in sorted(Path(__file__).parent.rglob("*.py"))
            }
        ),
        "seed": seed,
        "budget": actual_budget.model_dump(mode="json"),
        "methods": [method.value for method in selected],
        "case_pool_sha256": _case_pool_hash(cases),
        "pocforge_source": str(pocforge_source) if pocforge_source else None,
    }
    base_manifest = create_manifest(
        repository=Path.cwd(),
        command=("vw", "evaluate"),
        config=config,
        seed=seed,
    )
    total_usage = ExperimentUsage(
        model_calls=sum(item.usage.model_calls for item in results),
        input_tokens=sum(item.usage.input_tokens for item in results),
        output_tokens=sum(item.usage.output_tokens for item in results),
        candidate_pocs=sum(item.usage.candidate_pocs for item in results),
        evm_executions=sum(item.usage.evm_executions for item in results),
        scheduling_decisions=sum(item.usage.scheduling_decisions for item in results),
        wall_clock_seconds=sum(item.usage.wall_clock_seconds for item in results),
    )
    manifest = base_manifest.model_copy(
        update={
            "finished_at": finished,
            "usage": total_usage.to_resource_usage(),
            "data_hashes": {
                "case_pool": _case_pool_hash(cases),
                **{f"case:{item.case_id}": item.case_sha256 for item in cases},
                **{f"replay:{item.case_id}": item.replay_sha256 for item in cases},
            },
            "output_paths": (str((output / "experiment.json").resolve()),),
        }
    )
    manifest_path = output / "manifest.json"
    write_manifest(manifest_path, manifest)
    run = ExperimentRun(
        model_backend=type(backend).__name__,
        run_id=manifest.run_id,
        started_at=started,
        finished_at=finished,
        seed=seed,
        budget=actual_budget,
        case_pool_sha256=_case_pool_hash(cases),
        cases=tuple(cases),
        methods=selected,
        results=tuple(results),
        metrics=metrics,
        manifest_path=str(manifest_path.resolve()),
    )
    (output / "experiment.json").write_text(run.model_dump_json(indent=2) + "\n", encoding="utf-8")
    (output / "metrics.json").write_text(
        json.dumps([item.model_dump(mode="json") for item in metrics], indent=2) + "\n",
        encoding="utf-8",
    )
    (output / "case-results.jsonl").write_text(
        "".join(item.model_dump_json() + "\n" for item in results), encoding="utf-8"
    )
    return run


def load_experiment_run(path: Path) -> ExperimentRun:
    return ExperimentRun.model_validate_json(path.read_text(encoding="utf-8"))


def write_experiment_summary(path: Path, run: ExperimentRun) -> None:
    """Write a compact reviewer-facing table without copying case source."""

    lines = [
        "# Offline baseline and ablation protocol results",
        "",
        f"Case pool: `{run.case_pool_sha256}` ({len(run.cases)} cases)",
        f"Mode: `{run.evaluation_mode}`; backend: `{run.model_backend}`; "
        f"resource accounting: `{run.resource_accounting}`.",
        "",
        "These are protocol simulation results from shared replay evidence. Candidate "
        "code is not executed, method differences are accounting profiles, and resource counts "
        "are prescribed rather than measured token or live EVM usage. Latency measures "
        "local replay processing. Model performance and reward efficacy require live runs.",
        "",
        "| Method | EPR | VPR | CAR | Mean latency (s) | Model calls | Input tokens | "
        "Output tokens | EVM executions | Failures |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for metric in run.metrics:
        failures = ", ".join(f"{key}={value}" for key, value in metric.failure_types.items())
        lines.append(
            f"| {metric.method.value} | {metric.epr:.3f} | {metric.vpr:.3f} | "
            f"{metric.car:.3f} | {metric.mean_latency_seconds:.6f} | {metric.model_calls} | "
            f"{metric.input_tokens} | {metric.output_tokens} | {metric.evm_executions} | "
            f"{failures or 'none'} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def experiment_config_snapshot(budget: ExperimentBudget) -> tuple[dict[str, Any], str]:
    """Expose the exact config and digest for tests and external reports."""

    return config_snapshot({"budget": budget.model_dump(mode="json")})
