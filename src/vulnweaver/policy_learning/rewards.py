"""Progress-potential rewards with execution-only event attribution."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from vulnweaver.common.schema import (
    AgentOperation,
    DependencyEdge,
    DependencyKind,
    ObligationKind,
    VerifiedEvent,
)


@dataclass(frozen=True)
class RewardConfig:
    setup_weight: float = 1.0
    trigger_weight: float = 2.0
    violation_weight: float = 4.0
    impact_weight: float = 8.0
    lambda_cost: float = 0.05
    lambda_repeat: float = 0.10
    gamma_s: float = 0.99
    storage_dependency_weight: float = 1.0
    call_dependency_weight: float = 1.0
    asset_dependency_weight: float = 1.0

    def weight(self, kind: ObligationKind) -> float:
        return {
            ObligationKind.SETUP: self.setup_weight,
            ObligationKind.TRIGGER: self.trigger_weight,
            ObligationKind.VIOLATION: self.violation_weight,
            ObligationKind.IMPACT: self.impact_weight,
        }[kind]

    def dependency_weight(self, kind: DependencyKind) -> float:
        return {
            DependencyKind.STORAGE_READ_AFTER_WRITE: self.storage_dependency_weight,
            DependencyKind.CALL_RESULT: self.call_dependency_weight,
            DependencyKind.ASSET_FLOW: self.asset_dependency_weight,
        }[kind]


@dataclass(frozen=True)
class ProgressState:
    """Paper Eq. (3) state with normalized setup and transaction-prefix progress."""

    setup_satisfied: int = 0
    setup_total: int = 1
    executable_prefix: int = 0
    transaction_total: int = 1
    violation_observed: bool = False
    impact_observed: bool = False

    def __post_init__(self) -> None:
        if self.setup_total <= 0 or self.transaction_total <= 0:
            raise ValueError("progress denominators must be positive")
        if not 0 <= self.setup_satisfied <= self.setup_total:
            raise ValueError("setup progress is outside its declared range")
        if not 0 <= self.executable_prefix <= self.transaction_total:
            raise ValueError("transaction-prefix progress is outside its declared range")
        if self.impact_observed and not self.violation_observed:
            raise ValueError("impact progress requires a verified violation")


@dataclass(frozen=True)
class DependencyRewardResult:
    """Dependency-weighted specialist rewards and their auditable attribution."""

    operation_rewards: Mapping[str, float]
    event_attributions: Mapping[str, Mapping[str, float]]
    assignment_returns: Mapping[str, float]
    positive_event_reward: float
    distributed_positive_reward: float
    undistributed_positive_reward: float
    total_penalties: float


@dataclass(frozen=True)
class RewardStep:
    potential_before: float
    potential_after: float
    delta_potential: float
    event_rewards: Mapping[str, float]
    operation_reward: float
    assignment_id: str | None
    repeat_penalty: float
    cost_penalty: float


class ProgressPotential:
    """Compute Φ = q + 2l + 4v + 8i from distinct satisfied obligations."""

    def __init__(self, config: RewardConfig | None = None) -> None:
        self.config = config or RewardConfig()

    def value(self, events: Iterable[VerifiedEvent]) -> float:
        kinds = {event.obligation for event in events}
        return sum(self.config.weight(kind) for kind in kinds)

    def state_value(self, state: ProgressState) -> float:
        """Compute q + 2l + 4v + 8i exactly as paper Eq. (3)."""

        setup_fraction = state.setup_satisfied / state.setup_total
        prefix_fraction = state.executable_prefix / state.transaction_total
        return (
            setup_fraction
            + self.config.trigger_weight * prefix_fraction
            + self.config.violation_weight * float(state.violation_observed)
            + self.config.impact_weight * float(state.impact_observed)
        )


class RewardAllocator:
    """Allocate each first execution-backed obligation event exactly once."""

    def __init__(self, config: RewardConfig | None = None) -> None:
        self.config = config or RewardConfig()
        self.potential = ProgressPotential(self.config)
        self._seen_event_ids: set[str] = set()
        self._seen_kinds: set[ObligationKind] = set()

    def step(
        self,
        verified_events: Sequence[VerifiedEvent],
        *,
        trace_event_ids: Iterable[str],
        operation: AgentOperation | None = None,
        cost: float = 0.0,
        repeated_attempt: bool = False,
    ) -> RewardStep:
        """Score one operation using only events present in its execution trace.

        A verified event without a matching trace id is history/agent output and earns
        no positive reward. Repeated logical events earn no positive reward and may
        receive the configured repeat penalty.
        """

        trace_ids = set(trace_event_ids)
        # The explicit kind set is the authoritative state; event IDs are retained
        # separately so a repeated trace cannot create a new positive event.
        potential_before = sum(self.config.weight(kind) for kind in self._seen_kinds)
        first_events: list[VerifiedEvent] = []
        repeated = repeated_attempt
        for event in verified_events:
            evidence_ids = set(event.trace_event_ids)
            if not evidence_ids or not evidence_ids & trace_ids:
                continue
            if event.event_id in self._seen_event_ids or event.obligation in self._seen_kinds:
                repeated = True
                continue
            first_events.append(event)
        for event in first_events:
            self._seen_event_ids.add(event.event_id)
            self._seen_kinds.add(event.obligation)
        potential_after = sum(self.config.weight(kind) for kind in self._seen_kinds)
        delta = potential_after - potential_before
        event_rewards = {
            event.event_id: self.config.weight(event.obligation) for event in first_events
        }
        repeat_penalty = self.config.lambda_repeat if repeated else 0.0
        cost_penalty = self.config.lambda_cost * max(cost, 0.0)
        return RewardStep(
            potential_before=potential_before,
            potential_after=potential_after,
            delta_potential=delta,
            event_rewards=event_rewards,
            operation_reward=delta - repeat_penalty - cost_penalty,
            assignment_id=operation.assignment_id if operation is not None else None,
            repeat_penalty=repeat_penalty,
            cost_penalty=cost_penalty,
        )

    def aggregate_assignment_returns(
        self, steps: Sequence[RewardStep]
    ) -> dict[str, float]:
        """Aggregate specialist rewards into discounted coordinator assignment returns."""

        totals: dict[str, float] = defaultdict(float)
        for index, step in enumerate(steps):
            if step.assignment_id is not None:
                totals[step.assignment_id] += step.operation_reward * (self.config.gamma_s**index)
        return dict(totals)

    def redistribute_dependency_rewards(
        self,
        *,
        event_rewards: Mapping[str, float],
        verified_events: Sequence[VerifiedEvent],
        dependencies: Sequence[DependencyEdge],
        operations: Sequence[AgentOperation],
        costs: Mapping[str, float] | None = None,
        repeated_operation_ids: Iterable[str] = (),
    ) -> DependencyRewardResult:
        """Implement paper Eq. (5)-(8) over execution-supported edges.

        For each verified event, an operation receives one contribution per
        dependency *type*. Repeated edges of the same type do not multiply its
        strength; an edge's explicit weight scales the configured type weight.
        Positive reward is normalized independently for every event, then
        operation costs and repeated-failure penalties are applied once.
        """

        operation_by_id = {operation.operation_id: operation for operation in operations}
        event_by_id = {event.event_id: event for event in verified_events}
        operation_rewards: dict[str, float] = defaultdict(float)
        attributions: dict[str, dict[str, float]] = {}
        distributed = 0.0
        positive = sum(max(float(value), 0.0) for value in event_rewards.values())

        for event_id, raw_reward in event_rewards.items():
            reward = max(float(raw_reward), 0.0)
            event = event_by_id.get(event_id)
            if event is None or reward == 0.0:
                continue
            trace_ids = set(event.trace_event_ids)
            strengths: dict[str, dict[DependencyKind, float]] = defaultdict(dict)
            for edge in dependencies:
                if (
                    edge.target_event_id not in trace_ids
                    or edge.source_operation_id not in operation_by_id
                ):
                    continue
                weighted = self.config.dependency_weight(edge.kind) * edge.weight
                current = strengths[edge.source_operation_id].get(edge.kind, 0.0)
                strengths[edge.source_operation_id][edge.kind] = max(current, weighted)
            totals = {
                operation_id: sum(by_kind.values())
                for operation_id, by_kind in strengths.items()
                if sum(by_kind.values()) > 0.0
            }
            denominator = sum(totals.values())
            if denominator <= 0.0:
                continue
            event_attribution: dict[str, float] = {}
            for operation_id, strength in totals.items():
                allocated = reward * strength / denominator
                operation_rewards[operation_id] += allocated
                event_attribution[operation_id] = allocated
                distributed += allocated
            attributions[event_id] = event_attribution

        normalized_costs = costs or {}
        repeated = set(repeated_operation_ids)
        penalties = 0.0
        for operation in operations:
            cost_penalty = self.config.lambda_cost * max(
                float(normalized_costs.get(operation.operation_id, 0.0)), 0.0
            )
            repeat_penalty = (
                self.config.lambda_repeat if operation.operation_id in repeated else 0.0
            )
            penalties += cost_penalty + repeat_penalty
            operation_rewards[operation.operation_id] -= cost_penalty + repeat_penalty

        assignment_returns: dict[str, float] = defaultdict(float)
        offsets: dict[str, int] = defaultdict(int)
        for operation in operations:
            offset = offsets[operation.assignment_id]
            assignment_returns[operation.assignment_id] += (
                operation_rewards[operation.operation_id] * self.config.gamma_s**offset
            )
            offsets[operation.assignment_id] += 1

        return DependencyRewardResult(
            operation_rewards=dict(operation_rewards),
            event_attributions=attributions,
            assignment_returns=dict(assignment_returns),
            positive_event_reward=positive,
            distributed_positive_reward=distributed,
            undistributed_positive_reward=max(positive - distributed, 0.0),
            total_penalties=penalties,
        )


def reward_conservation(steps: Sequence[RewardStep]) -> tuple[float, float]:
    """Return (positive event reward, potential delta) for a conservation assertion."""

    positive = sum(sum(max(value, 0.0) for value in step.event_rewards.values()) for step in steps)
    potential_delta = sum(step.delta_potential for step in steps)
    return positive, potential_delta
