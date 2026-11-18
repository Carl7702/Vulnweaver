"""Independent replay and causal validation state machine."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vulnweaver.common.protocols import ExecutionBackend, ObligationEvaluator
from vulnweaver.common.schema import (
    CaseSpec,
    EnvironmentSpec,
    ErrorKind,
    ObligationKind,
    ObligationResult,
    ObligationStatus,
    OperationStatus,
    TraceEvent,
    ValidationReport,
    VerificationStatus,
)


@dataclass(frozen=True)
class _Replay:
    environment: EnvironmentSpec
    digest: str
    trace: tuple[TraceEvent, ...]
    state_diff: Mapping[str, Any]
    obligations: tuple[ObligationResult, ...]
    error_kind: ErrorKind = ErrorKind.NONE
    error: str | None = None


def _event_signature(event: TraceEvent) -> tuple[Any, ...]:
    return (
        event.call_depth,
        event.caller,
        event.target,
        event.selector,
        event.value,
        event.succeeded,
        event.data.get("storage"),
    )


def prefix_equivalent(
    vulnerable_trace: Sequence[TraceEvent],
    neutralized_trace: Sequence[TraceEvent],
    *,
    stop_event_ids: Sequence[str],
) -> bool:
    """Compare execution before the affected transition, ignoring gas and memory."""

    stop = set(stop_event_ids)
    stop_index = next(
        (index for index, event in enumerate(vulnerable_trace) if event.event_id in stop),
        min(len(vulnerable_trace), len(neutralized_trace)),
    )
    if len(neutralized_trace) < stop_index:
        return False
    return all(
        _event_signature(vulnerable_trace[index])
        == _event_signature(neutralized_trace[index])
        for index in range(stop_index)
    )


class IndependentVerifier:
    """Use fresh execution backends and keep validation output from construction."""

    def __init__(
        self,
        backend_factory: Callable[[], ExecutionBackend],
        evaluator: ObligationEvaluator,
    ) -> None:
        self._backend_factory = backend_factory
        self._evaluator = evaluator

    def _replay(
        self,
        candidate_dir: Path,
        case: CaseSpec,
        environment: EnvironmentSpec,
    ) -> _Replay:
        backend = self._backend_factory()
        first_digest = backend.reset(case, environment)
        build = backend.build(candidate_dir)
        if build.status is not OperationStatus.SUCCEEDED:
            return _Replay(
                environment=environment,
                digest=first_digest,
                trace=(),
                state_diff={},
                obligations=(),
                error_kind=build.error_kind,
                error=f"build failed: {build.message}",
            )
        run = backend.run(candidate_dir)
        if run.status is not OperationStatus.SUCCEEDED:
            return _Replay(
                environment=environment,
                digest=first_digest,
                trace=tuple(backend.trace()),
                state_diff=backend.state_diff(),
                obligations=(),
                error_kind=run.error_kind,
                error=f"execution failed: {run.message}",
            )
        trace = tuple(backend.trace())
        state_diff = backend.state_diff()
        obligations = tuple(self._evaluator.evaluate(case, trace, state_diff))
        second_digest = backend.reset(case, environment)
        if first_digest != second_digest:
            return _Replay(
                environment=environment,
                digest=second_digest,
                trace=trace,
                state_diff=state_diff,
                obligations=obligations,
                error_kind=ErrorKind.ENVIRONMENT,
                error="environment digest changed after reset",
            )
        return _Replay(
            environment=environment,
            digest=first_digest,
            trace=trace,
            state_diff=state_diff,
            obligations=obligations,
        )

    def verify(self, candidate_dir: Path, case: CaseSpec) -> ValidationReport:
        vulnerable = self._replay(candidate_dir, case, case.vulnerable_environment)
        digests = {"Ev": vulnerable.digest}
        if vulnerable.error is not None:
            status = (
                VerificationStatus.ENVERROR
                if vulnerable.error_kind in {ErrorKind.ENVIRONMENT, ErrorKind.RPC}
                else VerificationStatus.UNRESOLVED
            )
            return ValidationReport(
                case_id=case.case_id,
                status=status,
                environment_digests=digests,
                errors=(vulnerable.error,),
            )

        satisfied = {
            item.kind
            for item in vulnerable.obligations
            if item.status is ObligationStatus.SATISFIED
        }
        if satisfied != set(ObligationKind):
            return ValidationReport(
                case_id=case.case_id,
                status=VerificationStatus.UNRESOLVED,
                vulnerable_results=vulnerable.obligations,
                environment_digests=digests,
                errors=("vulnerable replay did not satisfy all four obligations",),
            )

        neutralized_environment = case.neutralized_environment
        if neutralized_environment is None:
            return ValidationReport(
                case_id=case.case_id,
                status=VerificationStatus.EXECUTION_EVIDENCED,
                vulnerable_results=vulnerable.obligations,
                environment_digests=digests,
            )

        neutralized = self._replay(candidate_dir, case, neutralized_environment)
        digests["Er"] = neutralized.digest
        if neutralized.error is not None:
            return ValidationReport(
                case_id=case.case_id,
                status=VerificationStatus.EXECUTION_EVIDENCED,
                vulnerable_results=vulnerable.obligations,
                neutralized_results=neutralized.obligations,
                environment_digests=digests,
                errors=(neutralized.error,),
            )

        violation = next(
            item for item in vulnerable.obligations if item.kind is ObligationKind.VIOLATION
        )
        event_ids = tuple(
            str(item) for item in violation.evidence.get("trace_event_ids", ())
        )
        equivalent = bool(event_ids) and prefix_equivalent(
            vulnerable.trace, neutralized.trace, stop_event_ids=event_ids
        )
        neutralized_impact = next(
            item for item in neutralized.obligations if item.kind is ObligationKind.IMPACT
        )
        impact_disappeared = neutralized_impact.status is not ObligationStatus.SATISFIED
        status = (
            VerificationStatus.CAUSALLY_VALIDATED
            if equivalent and impact_disappeared
            else VerificationStatus.UNRESOLVED
        )
        errors: tuple[str, ...] = ()
        if not equivalent:
            errors += ("Ev/Er prefixes differ before the affected transition",)
        if not impact_disappeared:
            errors += ("reported impact persists after root-cause neutralization",)
        patched_results: tuple[ObligationResult, ...] = ()
        if case.patched_environment is not None:
            patched = self._replay(candidate_dir, case, case.patched_environment)
            digests["Ep"] = patched.digest
            patched_results = patched.obligations
            if patched.error is not None:
                errors += (f"official patch replay failed: {patched.error}",)
        return ValidationReport(
            case_id=case.case_id,
            status=status,
            vulnerable_results=vulnerable.obligations,
            neutralized_results=neutralized.obligations,
            patched_results=patched_results,
            prefix_equivalent=equivalent,
            environment_digests=digests,
            errors=errors,
        )
