"""Offline execution-evidence replay for deterministic verifier tests and audits."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from pydantic import Field

from vulnweaver.common.schema import (
    CaseSpec,
    EnvironmentSpec,
    ErrorKind,
    OperationResult,
    OperationStatus,
    StrictModel,
    TraceEvent,
)


class ExecutionReplayRecord(StrictModel):
    environment_id: str
    digest: str
    trace: tuple[TraceEvent, ...] = ()
    state_diff: dict[str, Any] = Field(default_factory=dict)
    build_status: OperationStatus = OperationStatus.SUCCEEDED
    run_status: OperationStatus = OperationStatus.SUCCEEDED
    error_kind: ErrorKind = ErrorKind.NONE
    message: str = ""


class ExecutionReplayBundle(StrictModel):
    schema_version: str = "1.0"
    case_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    records: tuple[ExecutionReplayRecord, ...]


def load_replay_bundle(path: Path) -> ExecutionReplayBundle:
    bundle = ExecutionReplayBundle.model_validate_json(path.read_text(encoding="utf-8"))
    environment_ids = [record.environment_id for record in bundle.records]
    if len(environment_ids) != len(set(environment_ids)):
        raise ValueError("execution replay contains duplicate environment ids")
    return bundle


class ReplayExecutionBackend:
    """Return captured evidence without invoking Foundry or a model."""

    def __init__(self, records: Mapping[str, ExecutionReplayRecord]) -> None:
        self._records = dict(records)
        self._current: ExecutionReplayRecord | None = None

    def reset(self, case: CaseSpec, environment: EnvironmentSpec) -> str:
        try:
            self._current = self._records[environment.environment_id]
        except KeyError as error:
            raise KeyError(f"no execution replay for {environment.environment_id}") from error
        return self._current.digest

    def _record(self) -> ExecutionReplayRecord:
        if self._current is None:
            raise RuntimeError("reset must be called before execution replay")
        return self._current

    def build(self, candidate_dir: Path) -> OperationResult:
        record = self._record()
        return OperationResult(
            operation_id="replay-build",
            status=record.build_status,
            error_kind=record.error_kind,
            message=record.message,
        )

    def run(self, candidate_dir: Path, *, test_name: str | None = None) -> OperationResult:
        record = self._record()
        return OperationResult(
            operation_id="replay-run",
            status=record.run_status,
            error_kind=record.error_kind,
            message=record.message,
        )

    def trace(self) -> Sequence[TraceEvent]:
        return self._record().trace

    def state_diff(self) -> Mapping[str, Any]:
        return self._record().state_diff

    def digest(self, case: CaseSpec, environment: EnvironmentSpec) -> str:
        try:
            return self._records[environment.environment_id].digest
        except KeyError as error:
            raise KeyError(f"no execution replay for {environment.environment_id}") from error
