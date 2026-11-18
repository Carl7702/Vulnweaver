from __future__ import annotations

from typing import Any

from vulnweaver.common.schema import (
    CaseSpec,
    ObligationKind,
    ObligationSpec,
    ObligationStatus,
    PredicateSpec,
    TraceEvent,
)
from vulnweaver.validation.obligations import TemplateObligationEvaluator


def evidenced_case(sample_case: CaseSpec) -> CaseSpec:
    obligations = (
        ObligationSpec(
            obligation_id="setup",
            kind=ObligationKind.SETUP,
            description="Attacker is distinct from owner",
            predicate=PredicateSpec(
                template="compare",
                parameters={
                    "left_path": "context.attacker",
                    "right_path": "context.owner",
                    "operator": "ne",
                },
            ),
        ),
        ObligationSpec(
            obligation_id="trigger",
            kind=ObligationKind.TRIGGER,
            description="Affected call executes",
            predicate=PredicateSpec(
                template="trace_call",
                parameters={
                    "match": {
                        "target": "vault",
                        "selector": "0x12345678",
                        "succeeded": True,
                    }
                },
            ),
        ),
        ObligationSpec(
            obligation_id="violation",
            kind=ObligationKind.VIOLATION,
            description="Owner changes to attacker",
            predicate=PredicateSpec(
                template="changed",
                parameters={
                    "before_path": "before.owner",
                    "after_path": "after.owner",
                    "from": "owner",
                    "to": "attacker",
                    "trace_event_ids": ["write-owner"],
                },
            ),
        ),
        ObligationSpec(
            obligation_id="impact",
            kind=ObligationKind.IMPACT,
            description="Attacker gains assets",
            predicate=PredicateSpec(
                template="delta",
                parameters={
                    "before_path": "before.balances.attacker",
                    "after_path": "after.balances.attacker",
                    "operator": "ge",
                    "threshold": 100,
                    "requires_trace_event_ids": ["write-owner"],
                },
            ),
        ),
    )
    return sample_case.model_copy(update={"obligations": obligations})


def evidence() -> tuple[list[TraceEvent], dict[str, Any]]:
    trace = [
        TraceEvent(
            event_id="call",
            operation_id="op",
            sequence=0,
            call_depth=1,
            caller="attacker",
            target="vault",
            selector="0x12345678",
            event_type="call",
        ),
        TraceEvent(
            event_id="write-owner",
            operation_id="op",
            sequence=1,
            call_depth=1,
            caller="attacker",
            target="vault",
            selector="0x12345678",
            event_type="storage_write",
            data={"storage": {"slot": "owner", "before": "owner", "after": "attacker"}},
        ),
    ]
    state_diff = {
        "context": {"attacker": "attacker", "owner": "owner"},
        "before": {"owner": "owner", "balances": {"attacker": 0}},
        "after": {"owner": "attacker", "balances": {"attacker": 100}},
    }
    return trace, state_diff


def test_all_four_obligations_require_machine_evidence(sample_case: CaseSpec) -> None:
    case = evidenced_case(sample_case)
    trace, state_diff = evidence()

    results = TemplateObligationEvaluator().evaluate(case, trace, state_diff)

    assert {item.kind for item in results} == set(ObligationKind)
    assert all(item.status is ObligationStatus.SATISFIED for item in results)


def test_trigger_only_is_not_a_valid_poc(sample_case: CaseSpec) -> None:
    case = evidenced_case(sample_case)
    trace, state_diff = evidence()
    state_diff["after"] = {"owner": "owner", "balances": {"attacker": 0}}

    results = TemplateObligationEvaluator().evaluate(case, trace[:1], state_diff)
    statuses = {item.kind: item.status for item in results}

    assert statuses[ObligationKind.TRIGGER] is ObligationStatus.SATISFIED
    assert statuses[ObligationKind.VIOLATION] is ObligationStatus.FAILED
    assert statuses[ObligationKind.IMPACT] is ObligationStatus.FAILED


def test_unknown_template_fails_closed(sample_case: CaseSpec) -> None:
    case = evidenced_case(sample_case)
    obligations = list(case.obligations)
    obligations[0] = obligations[0].model_copy(
        update={"predicate": PredicateSpec(template="python.eval", parameters={})}
    )
    case = case.model_copy(update={"obligations": tuple(obligations)})

    result = TemplateObligationEvaluator().evaluate(case, [], {})[0]

    assert result.status is ObligationStatus.FAILED
    assert "not registered" in result.message


def test_unrelated_impact_without_trace_dependency_is_rejected(
    sample_case: CaseSpec,
) -> None:
    case = evidenced_case(sample_case)
    trace, state_diff = evidence()

    results = TemplateObligationEvaluator().evaluate(case, trace[:1], state_diff)
    impact = next(item for item in results if item.kind is ObligationKind.IMPACT)

    assert impact.status is ObligationStatus.FAILED
