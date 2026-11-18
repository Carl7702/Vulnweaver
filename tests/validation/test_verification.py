from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from test_obligations import evidence, evidenced_case

from vulnweaver.common.schema import (
    CaseSpec,
    EnvironmentKind,
    EnvironmentSpec,
    ErrorKind,
    OperationResult,
    OperationStatus,
    SealedReference,
    TraceEvent,
    VerificationStatus,
)
from vulnweaver.task_construction.isolation import construction_view
from vulnweaver.validation.obligations import TemplateObligationEvaluator
from vulnweaver.validation.verifier import IndependentVerifier


def _environment(kind: EnvironmentKind, suffix: str) -> EnvironmentSpec:
    return EnvironmentSpec(
        environment_id=f"golden-{suffix}",
        kind=kind,
        repository="examples/authorization/environments/ev",
        commit="abcdef123456",
        chain="local",
        chain_id=31337,
        fork_block=0,
        foundry_version="1.3.1",
        solc_version="0.8.24",
    )


class ReplayExecutionBackend:
    def __init__(
        self,
        replays: Mapping[EnvironmentKind, tuple[Sequence[TraceEvent], Mapping[str, Any]]],
        *,
        unstable_reset: bool = False,
        environment_error: EnvironmentKind | None = None,
    ) -> None:
        self.replays = replays
        self.unstable_reset = unstable_reset
        self.environment_error = environment_error
        self.environment: EnvironmentSpec | None = None
        self.reset_count = 0

    def reset(self, case: CaseSpec, environment: EnvironmentSpec) -> str:
        self.environment = environment
        self.reset_count += 1
        suffix = f"-{self.reset_count}" if self.unstable_reset else ""
        return f"digest-{environment.environment_id}{suffix}"

    def build(self, candidate_dir: Path) -> OperationResult:
        if self.environment is not None and self.environment.kind is self.environment_error:
            return OperationResult(
                operation_id="build",
                status=OperationStatus.FAILED,
                error_kind=ErrorKind.ENVIRONMENT,
                message="environment unavailable",
            )
        return OperationResult(operation_id="build", status=OperationStatus.SUCCEEDED)

    def run(self, candidate_dir: Path, *, test_name: str | None = None) -> OperationResult:
        return OperationResult(operation_id="run", status=OperationStatus.SUCCEEDED)

    def trace(self) -> Sequence[TraceEvent]:
        assert self.environment is not None
        return self.replays[self.environment.kind][0]

    def state_diff(self) -> Mapping[str, Any]:
        assert self.environment is not None
        return self.replays[self.environment.kind][1]

    def digest(self, case: CaseSpec, environment: EnvironmentSpec) -> str:
        return f"digest-{environment.environment_id}"


def _neutralized_evidence() -> tuple[list[TraceEvent], dict[str, Any]]:
    trace, state_diff = evidence()
    state_diff["after"] = {"owner": "owner", "balances": {"attacker": 0}}
    return trace[:1], state_diff


def _case_with_er(sample_case: CaseSpec) -> CaseSpec:
    case = evidenced_case(sample_case)
    return case.model_copy(
        update={
            "neutralized_environment": _environment(
                EnvironmentKind.ROOT_CAUSE_NEUTRALIZED, "er"
            )
        }
    )


def _verifier(
    replays: Mapping[EnvironmentKind, tuple[Sequence[TraceEvent], Mapping[str, Any]]],
    **backend_options: Any,
) -> IndependentVerifier:
    return IndependentVerifier(
        lambda: ReplayExecutionBackend(replays, **backend_options),
        TemplateObligationEvaluator(),
    )


def test_causal_validation_requires_impact_to_disappear(
    tmp_path: Path,
    sample_case: CaseSpec,
) -> None:
    case = _case_with_er(sample_case)
    vulnerable = evidence()
    neutralized = _neutralized_evidence()
    verifier = _verifier(
        {
            EnvironmentKind.VULNERABLE: vulnerable,
            EnvironmentKind.ROOT_CAUSE_NEUTRALIZED: neutralized,
        }
    )

    report = verifier.verify(tmp_path, case)

    assert report.status is VerificationStatus.CAUSALLY_VALIDATED
    assert report.prefix_equivalent is True


def test_persistent_impact_is_rejected(tmp_path: Path, sample_case: CaseSpec) -> None:
    case = _case_with_er(sample_case)
    vulnerable = evidence()
    er_trace, er_diff = evidence()
    er_diff["after"]["owner"] = "owner"
    er_diff["after"]["balances"]["attacker"] = 100
    verifier = _verifier(
        {
            EnvironmentKind.VULNERABLE: vulnerable,
            EnvironmentKind.ROOT_CAUSE_NEUTRALIZED: (er_trace, er_diff),
        }
    )

    report = verifier.verify(tmp_path, case)

    assert report.status is VerificationStatus.UNRESOLVED
    assert "persists" in report.errors[0]


def test_trigger_only_is_unresolved(tmp_path: Path, sample_case: CaseSpec) -> None:
    case = evidenced_case(sample_case)
    trace, state_diff = _neutralized_evidence()
    verifier = _verifier({EnvironmentKind.VULNERABLE: (trace, state_diff)})

    report = verifier.verify(tmp_path, case)

    assert report.status is VerificationStatus.UNRESOLVED


def test_missing_er_cannot_claim_causal_validation(
    tmp_path: Path,
    sample_case: CaseSpec,
) -> None:
    case = evidenced_case(sample_case)
    verifier = _verifier({EnvironmentKind.VULNERABLE: evidence()})

    report = verifier.verify(tmp_path, case)

    assert report.status is VerificationStatus.EXECUTION_EVIDENCED


def test_unavailable_er_preserves_execution_evidence(
    tmp_path: Path,
    sample_case: CaseSpec,
) -> None:
    case = _case_with_er(sample_case)
    verifier = _verifier(
        {
            EnvironmentKind.VULNERABLE: evidence(),
            EnvironmentKind.ROOT_CAUSE_NEUTRALIZED: _neutralized_evidence(),
        },
        environment_error=EnvironmentKind.ROOT_CAUSE_NEUTRALIZED,
    )

    report = verifier.verify(tmp_path, case)

    assert report.status is VerificationStatus.EXECUTION_EVIDENCED


def test_nondeterministic_reset_is_enverror(tmp_path: Path, sample_case: CaseSpec) -> None:
    case = evidenced_case(sample_case)
    verifier = _verifier(
        {EnvironmentKind.VULNERABLE: evidence()},
        unstable_reset=True,
    )

    report = verifier.verify(tmp_path, case)

    assert report.status is VerificationStatus.ENVERROR
    assert "digest changed" in report.errors[0]


def test_construction_view_removes_verifier_only_inputs(sample_case: CaseSpec) -> None:
    case = _case_with_er(sample_case).model_copy(
        update={
            "patched_environment": _environment(EnvironmentKind.OFFICIAL_PATCHED, "ep"),
            "reference_poc": SealedReference(path="sealed/poc.sol", sha256="0" * 64),
        }
    )

    visible = construction_view(case)

    assert visible.neutralized_environment is None
    assert visible.patched_environment is None
    assert visible.reference_poc is None
