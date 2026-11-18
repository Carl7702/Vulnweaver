"""Versioned, strict schemas shared by datasets, construction, and validation."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    """Reject unknown fields so schema drift is visible instead of silent."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class FrozenSpec(StrictModel):
    """Immutable input specification."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class DatasetSplit(StrEnum):
    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"
    UNASSIGNED = "unassigned"


class EnvironmentKind(StrEnum):
    VULNERABLE = "vulnerable"
    ROOT_CAUSE_NEUTRALIZED = "root_cause_neutralized"
    OFFICIAL_PATCHED = "official_patched"


class ObligationKind(StrEnum):
    SETUP = "setup"
    TRIGGER = "trigger"
    VIOLATION = "violation"
    IMPACT = "impact"


class ObligationStatus(StrEnum):
    PENDING = "pending"
    SATISFIED = "satisfied"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"


class TaskStatus(StrEnum):
    BLOCKED = "blocked"
    READY = "ready"
    ACTIVE = "active"
    COMPLETE = "complete"
    FAILED = "failed"


class AgentRole(StrEnum):
    STATE_PREPARATION = "state_preparation"
    AUTHORIZATION = "authorization"
    ASSET_FLOW = "asset_flow"
    DEPENDENCY = "dependency"
    POC_BUILDER = "poc_builder"
    EXECUTION_DIAGNOSIS = "execution_diagnosis"


class OperationStatus(StrEnum):
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class ErrorKind(StrEnum):
    NONE = "none"
    ENVIRONMENT = "environment"
    COMPILE = "compile"
    REVERT = "revert"
    TIMEOUT = "timeout"
    RPC = "rpc"
    POLICY = "policy"
    MODEL_OUTPUT = "model_output"
    BUDGET = "budget"
    INTERNAL = "internal"


class VerificationStatus(StrEnum):
    ENVERROR = "ENVERROR"
    UNRESOLVED = "UNRESOLVED"
    EXECUTION_EVIDENCED = "EXECUTION_EVIDENCED"
    CAUSALLY_VALIDATED = "CAUSALLY_VALIDATED"


class DependencyKind(StrEnum):
    STORAGE_READ_AFTER_WRITE = "storage_read_after_write"
    CALL_RESULT = "call_result"
    ASSET_FLOW = "asset_flow"


class FindingSpec(FrozenSpec):
    finding_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    vulnerability_type: str = Field(min_length=1)
    severity: Severity = Severity.UNKNOWN
    report: str = Field(min_length=1)
    root_cause: str = Field(min_length=1)
    affected_functions: tuple[str, ...] = ()


class EnvironmentSpec(FrozenSpec):
    environment_id: str = Field(min_length=1)
    kind: EnvironmentKind
    repository: str = Field(min_length=1)
    commit: str = Field(min_length=7)
    chain: str = Field(min_length=1)
    chain_id: int = Field(gt=0)
    fork_block: int = Field(ge=0)
    foundry_version: str = Field(min_length=1)
    solc_version: str = Field(min_length=1)
    rpc_alias: str | None = None
    patch_files: tuple[str, ...] = ()
    settings: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_rpc_alias(self) -> EnvironmentSpec:
        alias = self.rpc_alias
        if alias and ("://" in alias or "@" in alias):
            raise ValueError("rpc_alias must be an environment-variable alias, not a URL")
        return self


class PredicateSpec(FrozenSpec):
    """A controlled predicate template plus validated, data-only parameters."""

    template: str = Field(min_length=1)
    parameters: dict[str, Any] = Field(default_factory=dict)


class ObligationSpec(FrozenSpec):
    obligation_id: str = Field(min_length=1)
    kind: ObligationKind
    description: str = Field(min_length=1)
    predicate: PredicateSpec


class TaskSpec(FrozenSpec):
    task_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    required_role: AgentRole
    prerequisites: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()


class Budget(FrozenSpec):
    model_calls: int = Field(default=20, ge=0)
    input_tokens: int = Field(default=65_536, ge=0)
    output_tokens: int = Field(default=24_576, ge=0)
    candidate_pocs: int = Field(default=4, ge=0)
    evm_executions: int = Field(default=12, ge=0)
    scheduling_decisions: int = Field(default=24, ge=0)
    wall_clock_seconds: int = Field(default=900, ge=0)


class InputArtifact(FrozenSpec):
    path: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source: str = Field(min_length=1)


class SealedReference(FrozenSpec):
    path: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    sealed: Literal[True] = True


class CaseSpec(FrozenSpec):
    schema_version: Literal["1.0"] = "1.0"
    case_id: str = Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    source: str = Field(min_length=1)
    split: DatasetSplit = DatasetSplit.UNASSIGNED
    project_id: str = Field(min_length=1)
    attack_family: str | None = None
    finding: FindingSpec
    vulnerable_environment: EnvironmentSpec = Field(alias="Ev")
    neutralized_environment: EnvironmentSpec | None = Field(default=None, alias="Er")
    patched_environment: EnvironmentSpec | None = Field(default=None, alias="Ep")
    obligations: tuple[ObligationSpec, ...]
    tasks: tuple[TaskSpec, ...]
    allowed_operations: dict[AgentRole, tuple[str, ...]]
    budget: Budget = Field(default_factory=Budget)
    inputs: tuple[InputArtifact, ...] = ()
    reference_poc: SealedReference | None = None
    conversion_log: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_case_graph(self) -> CaseSpec:
        if self.vulnerable_environment.kind is not EnvironmentKind.VULNERABLE:
            raise ValueError("Ev must have kind=vulnerable")
        if self.neutralized_environment is not None and (
            self.neutralized_environment.kind is not EnvironmentKind.ROOT_CAUSE_NEUTRALIZED
        ):
            raise ValueError("Er must have kind=root_cause_neutralized")
        if self.patched_environment is not None and (
            self.patched_environment.kind is not EnvironmentKind.OFFICIAL_PATCHED
        ):
            raise ValueError("Ep must have kind=official_patched")

        obligation_kinds = {item.kind for item in self.obligations}
        required = set(ObligationKind)
        if obligation_kinds != required:
            raise ValueError("exactly the four setup/trigger/violation/impact kinds are required")

        task_ids = [task.task_id for task in self.tasks]
        if len(task_ids) != len(set(task_ids)):
            raise ValueError("task ids must be unique")
        known_tasks = set(task_ids)
        for task in self.tasks:
            missing = set(task.prerequisites) - known_tasks
            if missing:
                raise ValueError(f"task {task.task_id!r} has unknown prerequisites: {missing}")
            if task.task_id in task.prerequisites:
                raise ValueError(f"task {task.task_id!r} cannot depend on itself")
        return self


class Observation(StrictModel):
    source: str
    kind: str
    data: dict[str, Any] = Field(default_factory=dict)


class HistoryEntry(StrictModel):
    sequence: int = Field(ge=0)
    assignment_id: str | None = None
    operation_id: str | None = None
    summary: str


class ConstructionState(StrictModel):
    case_id: str
    candidate_files: dict[str, str] = Field(default_factory=dict)
    observations: list[Observation] = Field(default_factory=list)
    history: list[HistoryEntry] = Field(default_factory=list)
    obligation_progress: dict[ObligationKind, ObligationStatus] = Field(
        default_factory=lambda: {kind: ObligationStatus.PENDING for kind in ObligationKind}
    )
    task_status: dict[str, TaskStatus] = Field(default_factory=dict)
    remaining_budget: Budget = Field(default_factory=Budget)


class Assignment(FrozenSpec):
    assignment_id: str
    task_id: str
    agent_role: AgentRole
    sequence: int = Field(ge=0)


class AgentOperation(FrozenSpec):
    operation_id: str
    assignment_id: str
    role: AgentRole
    capability: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class OperationResult(StrictModel):
    operation_id: str
    status: OperationStatus
    error_kind: ErrorKind = ErrorKind.NONE
    message: str = ""
    artifacts: dict[str, str] = Field(default_factory=dict)
    observations: list[Observation] = Field(default_factory=list)
    duration_seconds: float = Field(default=0.0, ge=0.0)


class TraceEvent(FrozenSpec):
    event_id: str
    operation_id: str
    sequence: int = Field(ge=0)
    call_depth: int = Field(ge=0)
    caller: str | None = None
    target: str | None = None
    selector: str | None = None
    value: int = Field(default=0, ge=0)
    succeeded: bool = True
    event_type: str
    data: dict[str, Any] = Field(default_factory=dict)


class DependencyEdge(FrozenSpec):
    source_operation_id: str
    target_event_id: str
    kind: DependencyKind
    evidence: dict[str, Any] = Field(default_factory=dict)
    weight: float = Field(default=1.0, gt=0.0)


class VerifiedEvent(FrozenSpec):
    event_id: str
    obligation: ObligationKind
    trace_event_ids: tuple[str, ...]
    first_observed_at: int = Field(ge=0)
    evidence: dict[str, Any] = Field(default_factory=dict)


class Trajectory(StrictModel):
    case_id: str
    assignments: list[Assignment] = Field(default_factory=list)
    operations: list[AgentOperation] = Field(default_factory=list)
    results: list[OperationResult] = Field(default_factory=list)
    verified_events: list[VerifiedEvent] = Field(default_factory=list)
    dependencies: list[DependencyEdge] = Field(default_factory=list)
    assignment_returns: dict[str, float] = Field(default_factory=dict)
    total_reward: float = 0.0


class ObligationResult(FrozenSpec):
    obligation_id: str
    kind: ObligationKind
    status: ObligationStatus
    evidence: dict[str, Any] = Field(default_factory=dict)
    message: str = ""


class ValidationReport(FrozenSpec):
    schema_version: Literal["1.0"] = "1.0"
    case_id: str
    status: VerificationStatus
    vulnerable_results: tuple[ObligationResult, ...] = ()
    neutralized_results: tuple[ObligationResult, ...] = ()
    patched_results: tuple[ObligationResult, ...] = ()
    prefix_equivalent: bool | None = None
    environment_digests: dict[str, str] = Field(default_factory=dict)
    evidence_paths: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()


class ResourceUsage(FrozenSpec):
    model_calls: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    evm_executions: int = Field(default=0, ge=0)
    wall_clock_seconds: float = Field(default=0.0, ge=0.0)


class RunManifest(FrozenSpec):
    schema_version: Literal["1.0"] = "1.0"
    run_id: str
    case_id: str | None = None
    command: tuple[str, ...]
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    seed: int = 42
    config: dict[str, Any] = Field(default_factory=dict)
    config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    code_commit: str | None = None
    code_dirty: bool | None = None
    data_hashes: dict[str, str] = Field(default_factory=dict)
    tool_versions: dict[str, str] = Field(default_factory=dict)
    usage: ResourceUsage = Field(default_factory=ResourceUsage)
    output_paths: tuple[str, ...] = ()

