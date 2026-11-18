from __future__ import annotations

from vulnweaver.common.schema import (
    AgentOperation,
    AgentRole,
    DependencyEdge,
    DependencyKind,
    ObligationKind,
    TraceEvent,
    VerifiedEvent,
)
from vulnweaver.policy_learning.dependency_tracing import DependencyTracker
from vulnweaver.policy_learning.rewards import (
    ProgressPotential,
    ProgressState,
    RewardAllocator,
    RewardConfig,
    reward_conservation,
)


def _event(
    event_id: str,
    operation_id: str,
    sequence: int,
    event_type: str,
    *,
    storage: dict[str, str] | None = None,
    data: dict[str, object] | None = None,
) -> TraceEvent:
    payload = dict(data or {})
    if storage is not None:
        payload["storage"] = storage
    return TraceEvent(
        event_id=event_id,
        operation_id=operation_id,
        sequence=sequence,
        call_depth=1,
        caller="attacker",
        target="vault",
        event_type=event_type,
        data=payload,
    )


def test_dependency_tracker_finds_storage_call_and_asset_edges() -> None:
    trace = (
        _event("write", "op-state", 0, "storage_write", storage={"key": "0x1", "after": "0xbeef"}),
        _event(
            "read",
            "op-dependency",
            1,
            "storage_read",
            storage={"key": "0x1", "value": "0xbeef"},
        ),
        _event("call", "op-call", 2, "call"),
        _event(
            "result",
            "op-result",
            3,
            "call",
            data={"result_of_event_id": "call"},
        ),
        _event(
            "mint",
            "op-mint",
            4,
            "asset_transfer",
            data={"asset": {"token": "USDC", "from": "treasury", "to": "attacker"}},
        ),
        _event(
            "spend",
            "op-spend",
            5,
            "asset_transfer",
            data={"asset": {"token": "USDC", "from": "treasury", "to": "attacker"}},
        ),
    )
    edges = DependencyTracker().trace(trace)
    kinds = {(edge.kind, edge.source_operation_id, edge.target_event_id) for edge in edges}
    assert (DependencyKind.STORAGE_READ_AFTER_WRITE, "op-state", "read") in kinds
    assert (DependencyKind.CALL_RESULT, "op-call", "result") in kinds
    assert (DependencyKind.ASSET_FLOW, "op-mint", "spend") in kinds


def test_reward_conservation_and_delayed_event_attribution() -> None:
    allocator = RewardAllocator()
    setup = VerifiedEvent(
        event_id="setup-event",
        obligation=ObligationKind.SETUP,
        trace_event_ids=("setup-trace",),
        first_observed_at=0,
    )
    violation = VerifiedEvent(
        event_id="violation-event",
        obligation=ObligationKind.VIOLATION,
        trace_event_ids=("late-trace",),
        first_observed_at=3,
    )
    first = allocator.step((setup, violation), trace_event_ids=("setup-trace",), cost=1.0)
    assert first.delta_potential == 1.0
    assert first.event_rewards == {"setup-event": 1.0}
    assert first.operation_reward == 0.95

    delayed = allocator.step(
        (setup, violation), trace_event_ids=("late-trace",), operation=AgentOperation(
            operation_id="op-late",
            assignment_id="assignment-late",
            role=AgentRole.EXECUTION_DIAGNOSIS,
            capability="slice_trace",
        )
    )
    assert delayed.delta_potential == 4.0
    assert delayed.event_rewards == {"violation-event": 4.0}
    assert reward_conservation((first, delayed)) == (5.0, 5.0)


def test_repeated_trace_and_unexecuted_claim_do_not_add_positive_reward() -> None:
    allocator = RewardAllocator(RewardConfig(lambda_repeat=0.1))
    event = VerifiedEvent(
        event_id="impact-event",
        obligation=ObligationKind.IMPACT,
        trace_event_ids=("impact-trace",),
        first_observed_at=1,
    )
    first = allocator.step((event,), trace_event_ids=("impact-trace",))
    repeated = allocator.step((event,), trace_event_ids=("impact-trace",), repeated_attempt=True)
    unexecuted = allocator.step(
        (VerifiedEvent(
            event_id="fake-event",
            obligation=ObligationKind.TRIGGER,
            trace_event_ids=("missing-trace",),
            first_observed_at=2,
        ),),
        trace_event_ids=(),
    )
    assert first.delta_potential == 8.0
    assert repeated.delta_potential == 0.0
    assert repeated.operation_reward == -0.1
    assert unexecuted.operation_reward == 0.0


def test_assignment_returns_discount_delayed_specialist_rewards() -> None:
    allocator = RewardAllocator(RewardConfig(gamma_s=0.99))
    events = tuple(
        VerifiedEvent(
            event_id=f"event-{index}",
            obligation=kind,
            trace_event_ids=(f"trace-{index}",),
            first_observed_at=index,
        )
        for index, kind in enumerate((ObligationKind.SETUP, ObligationKind.IMPACT))
    )
    steps = (
        allocator.step(
            (events[0],),
            trace_event_ids=("trace-0",),
            operation=AgentOperation(
                operation_id="op-0",
                assignment_id="assignment-0",
                role=AgentRole.STATE_PREPARATION,
                capability="prepare_local_state",
            ),
        ),
        allocator.step(
            (events[1],),
            trace_event_ids=("trace-1",),
            operation=AgentOperation(
                operation_id="op-1",
                assignment_id="assignment-1",
                role=AgentRole.EXECUTION_DIAGNOSIS,
                capability="slice_trace",
            ),
        ),
    )
    returns = allocator.aggregate_assignment_returns(steps)
    assert returns["assignment-0"] == 1.0
    assert returns["assignment-1"] == 8.0 * 0.99


def test_progress_state_uses_normalized_setup_and_prefix_fractions() -> None:
    potential = ProgressPotential()
    state = ProgressState(
        setup_satisfied=2,
        setup_total=4,
        executable_prefix=3,
        transaction_total=4,
        violation_observed=True,
        impact_observed=False,
    )
    assert potential.state_value(state) == 0.5 + 2.0 * 0.75 + 4.0


def test_dependency_weighted_delayed_reward_and_assignment_propagation() -> None:
    allocator = RewardAllocator(
        RewardConfig(
            storage_dependency_weight=2.0,
            call_dependency_weight=1.0,
            lambda_cost=0.1,
            lambda_repeat=0.25,
            gamma_s=0.5,
        )
    )
    operations = (
        AgentOperation(
            operation_id="op-state",
            assignment_id="assignment-a",
            role=AgentRole.STATE_PREPARATION,
            capability="prepare",
        ),
        AgentOperation(
            operation_id="op-call",
            assignment_id="assignment-a",
            role=AgentRole.DEPENDENCY,
            capability="bind",
        ),
    )
    event = VerifiedEvent(
        event_id="impact",
        obligation=ObligationKind.IMPACT,
        trace_event_ids=("impact-trace",),
        first_observed_at=2,
    )
    dependencies = (
        DependencyEdge(
            source_operation_id="op-state",
            target_event_id="impact-trace",
            kind=DependencyKind.STORAGE_READ_AFTER_WRITE,
        ),
        # A repeated edge of the same type is evidence, not a second reward vote.
        DependencyEdge(
            source_operation_id="op-state",
            target_event_id="impact-trace",
            kind=DependencyKind.STORAGE_READ_AFTER_WRITE,
            evidence={"duplicate-path": True},
        ),
        DependencyEdge(
            source_operation_id="op-call",
            target_event_id="impact-trace",
            kind=DependencyKind.CALL_RESULT,
        ),
    )
    result = allocator.redistribute_dependency_rewards(
        event_rewards={"impact": 9.0},
        verified_events=(event,),
        dependencies=dependencies,
        operations=operations,
        costs={"op-state": 1.0},
        repeated_operation_ids=("op-call",),
    )
    assert result.event_attributions["impact"] == {"op-state": 6.0, "op-call": 3.0}
    assert result.operation_rewards == {"op-state": 5.9, "op-call": 2.75}
    assert result.distributed_positive_reward == 9.0
    assert result.undistributed_positive_reward == 0.0
    assert result.total_penalties == 0.35
    assert result.assignment_returns["assignment-a"] == 5.9 + 0.5 * 2.75
