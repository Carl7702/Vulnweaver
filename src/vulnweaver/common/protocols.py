"""Stable plugin interfaces for construction, execution, policy, and validation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel

from vulnweaver.common.schema import (
    AgentOperation,
    Assignment,
    CaseSpec,
    ConstructionState,
    EnvironmentSpec,
    ObligationResult,
    OperationResult,
    TraceEvent,
    ValidationReport,
)
from vulnweaver.policy_learning.models import ModelMessage, ModelResponse


@runtime_checkable
class ModelBackend(Protocol):
    def complete(
        self,
        messages: Sequence[ModelMessage],
        *,
        response_schema: type[BaseModel] | None = None,
    ) -> ModelResponse: ...


@runtime_checkable
class ExecutionBackend(Protocol):
    def reset(self, case: CaseSpec, environment: EnvironmentSpec) -> str: ...

    def build(self, candidate_dir: Path) -> OperationResult: ...

    def run(self, candidate_dir: Path, *, test_name: str | None = None) -> OperationResult: ...

    def trace(self) -> Sequence[TraceEvent]: ...

    def state_diff(self) -> Mapping[str, Any]: ...

    def digest(self, case: CaseSpec, environment: EnvironmentSpec) -> str: ...


@runtime_checkable
class ObligationEvaluator(Protocol):
    def evaluate(
        self,
        case: CaseSpec,
        trace: Sequence[TraceEvent],
        state_diff: Mapping[str, Any],
    ) -> Sequence[ObligationResult]: ...


@runtime_checkable
class CoordinatorPolicy(Protocol):
    def select_assignment(
        self,
        case: CaseSpec,
        state: ConstructionState,
        action_mask: Sequence[bool],
    ) -> Assignment | None: ...


@runtime_checkable
class SpecialistPolicy(Protocol):
    def select_operation(
        self,
        assignment: Assignment,
        state: ConstructionState,
        action_mask: Sequence[bool],
    ) -> AgentOperation | None: ...


@runtime_checkable
class Verifier(Protocol):
    def verify(self, candidate_dir: Path, case: CaseSpec) -> ValidationReport: ...

