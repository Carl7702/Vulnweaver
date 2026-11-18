"""Controlled replay examples for the independent validation pipeline.

These examples exercise artifact mechanics only. They are not members of the paper's
training or evaluation datasets and must not be used to report paper metrics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from vulnweaver.common.schema import (
    AgentRole,
    CaseSpec,
    EnvironmentKind,
    EnvironmentSpec,
    FindingSpec,
    ObligationKind,
    ObligationSpec,
    PredicateSpec,
    Severity,
    TaskSpec,
    TraceEvent,
)


@dataclass(frozen=True)
class ExampleReplay:
    case: CaseSpec
    vulnerable_trace: tuple[TraceEvent, ...]
    vulnerable_state_diff: dict[str, Any]
    neutralized_trace: tuple[TraceEvent, ...]
    neutralized_state_diff: dict[str, Any]


def _environment(case_id: str, kind: EnvironmentKind) -> EnvironmentSpec:
    suffix = {
        EnvironmentKind.VULNERABLE: "ev",
        EnvironmentKind.ROOT_CAUSE_NEUTRALIZED: "er",
        EnvironmentKind.OFFICIAL_PATCHED: "ep",
    }[kind]
    example_name = case_id.removeprefix("golden-")
    context: dict[str, Any] = {"attacker": "0xbeef"}
    if example_name == "authorization":
        context["owner"] = "deployer"
    elif example_name == "accounting":
        context["initial_credit"] = "0x64"
    elif example_name == "asset-flow":
        context["owner"] = "0xa11ce"
        context["caller"] = "0xbeef"
    elif example_name == "multi-transaction":
        context["owner"] = "deployer"
    return EnvironmentSpec(
        environment_id=f"{case_id}-{suffix}",
        kind=kind,
        repository=f"examples/{example_name}/environments/{suffix}",
        commit="0000000000000000000000000000000000000001",
        chain="local",
        chain_id=31337,
        fork_block=0,
        foundry_version="1.3.1",
        solc_version="0.8.24+commit.e11b9ed9",
        settings={"compose_workspace": True, "context": context},
    )


def _case(
    case_id: str,
    vulnerability_type: str,
    title: str,
    report: str,
    root_cause: str,
    obligations: tuple[ObligationSpec, ...],
) -> CaseSpec:
    return CaseSpec(
        case_id=case_id,
        source="controlled-example-foundry",
        project_id=case_id,
        attack_family=vulnerability_type,
        finding=FindingSpec(
            finding_id=f"{case_id}-finding",
            title=title,
            vulnerability_type=vulnerability_type,
            severity=Severity.HIGH,
            report=report,
            root_cause=root_cause,
            affected_functions=("exploit()",),
        ),
        Ev=_environment(case_id, EnvironmentKind.VULNERABLE),
        Er=_environment(case_id, EnvironmentKind.ROOT_CAUSE_NEUTRALIZED),
        obligations=obligations,
        tasks=(
            TaskSpec(
                task_id="prepare",
                description="Prepare deterministic local state",
                required_role=AgentRole.STATE_PREPARATION,
                produces=("prepared-state",),
            ),
            TaskSpec(
                task_id="build",
                description="Build the candidate PoC",
                required_role=AgentRole.POC_BUILDER,
                prerequisites=("prepare",),
                produces=("candidate",),
            ),
            TaskSpec(
                task_id="diagnose",
                description="Diagnose execution evidence",
                required_role=AgentRole.EXECUTION_DIAGNOSIS,
                prerequisites=("build",),
                produces=("evidence",),
            ),
        ),
        allowed_operations={
            AgentRole.STATE_PREPARATION: ("prepare_local_state",),
            AgentRole.POC_BUILDER: ("edit_candidate", "build_candidate"),
            AgentRole.EXECUTION_DIAGNOSIS: ("run_candidate", "slice_trace"),
        },
        conversion_log=(
            "controlled local Foundry fixture; not included in paper evaluation metrics",
            "no RPC, private key, or external asset is required",
        ),
    )


def _event(
    event_id: str,
    sequence: int,
    *,
    target: str,
    selector: str | None,
    event_type: str = "call",
    succeeded: bool = True,
    storage: dict[str, Any] | None = None,
) -> TraceEvent:
    data: dict[str, Any] = {}
    if storage is not None:
        data["storage"] = storage
    return TraceEvent(
        event_id=event_id,
        operation_id="golden-operation",
        sequence=sequence,
        call_depth=1,
        caller="attacker",
        target=target,
        selector=selector,
        succeeded=succeeded,
        event_type=event_type,
        data=data,
    )


def authorization_replay() -> ExampleReplay:
    obligations = (
        ObligationSpec(
            obligation_id="setup",
            kind=ObligationKind.SETUP,
            description="Attacker is not the initial owner",
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
            description="Unprotected owner setter is called",
            predicate=PredicateSpec(
                template="trace_call",
                parameters={"match": {"target": "vault", "selector": "0x13af4035"}},
            ),
        ),
        ObligationSpec(
            obligation_id="violation",
            kind=ObligationKind.VIOLATION,
            description="Owner storage changes without authorization",
            predicate=PredicateSpec(
                template="storage_transition",
                parameters={
                    "target": "vault",
                    "key": "0x0",
                    "after": "0xbeef",
                },
            ),
        ),
        ObligationSpec(
            obligation_id="impact",
            kind=ObligationKind.IMPACT,
            description="Attacker gains owner authority",
            predicate=PredicateSpec(
                template="storage_transition",
                parameters={
                    "target": "vault",
                    "key": "0x0",
                    "after": "0xbeef",
                },
            ),
        ),
    )
    call = _event("call-0000", 0, target="vault", selector="0x13af4035")
    write = _event(
        "storage-0001",
        1,
        target="vault",
        selector=None,
        event_type="storage_write",
        storage={"key": "0x0", "before": "0x1", "after": "0xbeef"},
    )
    base = {
        "context": {"attacker": "0xbeef", "owner": "deployer"},
        "before": {"storage": {"vault": {"0x0": "0x1"}}},
    }
    return ExampleReplay(
        case=_case(
            "golden-authorization",
            "authorization",
            "Unprotected owner update",
            "An attacker can replace the owner.",
            "The owner setter omits caller authorization.",
            obligations,
        ),
        vulnerable_trace=(call, write),
        vulnerable_state_diff={
            **base,
            "after": {"storage": {"vault": {"0x0": "0xbeef"}}},
        },
        neutralized_trace=(call,),
        neutralized_state_diff={
            "context": base["context"],
            "before": {"storage": {}},
            "after": {"storage": {}},
        },
    )


def accounting_replay() -> ExampleReplay:
    obligations = (
        ObligationSpec(
            obligation_id="setup",
            kind=ObligationKind.SETUP,
            description="Attacker has one withdrawal credit",
            predicate=PredicateSpec(
                template="value",
                parameters={"path": "context.initial_credit", "expected": "0x64"},
            ),
        ),
        ObligationSpec(
            obligation_id="trigger",
            kind=ObligationKind.TRIGGER,
            description="The vulnerable withdrawal executes twice",
            predicate=PredicateSpec(
                template="trace_call",
                parameters={
                    "match": {"target": "bank", "selector": "0x2e1a7d4d"},
                    "min_count": 2,
                },
            ),
        ),
        ObligationSpec(
            obligation_id="violation",
            kind=ObligationKind.VIOLATION,
            description="Credit remains after withdrawal",
            predicate=PredicateSpec(
                template="storage_transition",
                parameters={
                    "target": "bank",
                    "key": "0x0",
                    "before": "0x0",
                    "after": "0x64",
                },
            ),
        ),
        ObligationSpec(
            obligation_id="impact",
            kind=ObligationKind.IMPACT,
            description="Attacker withdraws more than its credit",
            predicate=PredicateSpec(
                template="delta",
                parameters={
                    "before_path": "before.storage.bank.0x1",
                    "after_path": "after.storage.bank.0x1",
                    "operator": "ge",
                    "threshold": 200,
                },
            ),
        ),
    )
    first = _event("call-0000", 0, target="bank", selector="0x2e1a7d4d")
    decrement = _event(
        "storage-0001",
        1,
        target="bank",
        selector=None,
        event_type="storage_write",
        storage={"key": "0x0", "before": "0x64", "after": "0x0"},
    )
    restore = _event(
        "storage-0002",
        2,
        target="bank",
        selector=None,
        event_type="storage_write",
        storage={"key": "0x0", "before": "0x0", "after": "0x64"},
    )
    paid = _event(
        "storage-0003",
        3,
        target="bank",
        selector=None,
        event_type="storage_write",
        storage={"key": "0x1", "before": "0x0", "after": "0xc8"},
    )
    second = _event("call-0004", 4, target="bank", selector="0x2e1a7d4d")
    base = {
        "context": {"attacker": "0xbeef", "initial_credit": "0x64"},
        "before": {"storage": {"bank": {"0x0": "0x64", "0x1": "0x0"}}},
    }
    return ExampleReplay(
        case=_case(
            "golden-accounting",
            "accounting_state",
            "Withdrawal credit is not consumed",
            "The same credit can be withdrawn repeatedly.",
            "The withdrawal path transfers assets without decrementing credit.",
            obligations,
        ),
        vulnerable_trace=(first, decrement, restore, paid, second),
        vulnerable_state_diff={
            **base,
            "after": {"storage": {"bank": {"0x0": "0x64", "0x1": "0xc8"}}},
        },
        neutralized_trace=(first, decrement, paid, second),
        neutralized_state_diff={
            **base,
            "after": {"storage": {"bank": {"0x0": "0x0", "0x1": "0x64"}}},
        },
    )


def asset_flow_replay() -> ExampleReplay:
    obligations = (
        ObligationSpec(
            obligation_id="setup",
            kind=ObligationKind.SETUP,
            description="Caller is not authorized",
            predicate=PredicateSpec(
                template="compare",
                parameters={
                    "left_path": "context.caller",
                    "right_path": "context.owner",
                    "operator": "ne",
                },
            ),
        ),
        ObligationSpec(
            obligation_id="trigger",
            kind=ObligationKind.TRIGGER,
            description="Drain entry point is reached",
            predicate=PredicateSpec(
                template="trace_call",
                parameters={"match": {"target": "treasury", "selector": "0xf6b19c74"}},
            ),
        ),
        ObligationSpec(
            obligation_id="violation",
            kind=ObligationKind.VIOLATION,
            description="Transfer occurs while authorization is false",
            predicate=PredicateSpec(
                template="storage_transition",
                parameters={
                    "target": "treasury",
                    "key": "0x1",
                    "before": "0x3e8",
                    "after": "0x1f4",
                },
            ),
        ),
        ObligationSpec(
            obligation_id="impact",
            kind=ObligationKind.IMPACT,
            description="Attacker receives treasury tokens",
            predicate=PredicateSpec(
                template="delta",
                parameters={
                    "before_path": "before.storage.treasury.0x2",
                    "after_path": "after.storage.treasury.0x2",
                    "operator": "ge",
                    "threshold": 500,
                },
            ),
        ),
    )
    call = _event("call-0000", 0, target="treasury", selector="0xf6b19c74")
    drain = _event(
        "storage-0001",
        1,
        target="treasury",
        selector=None,
        event_type="storage_write",
        storage={"key": "0x1", "before": "0x3e8", "after": "0x1f4"},
    )
    gain = _event(
        "storage-0002",
        2,
        target="treasury",
        selector=None,
        event_type="storage_write",
        storage={"key": "0x2", "before": "0x0", "after": "0x1f4"},
    )
    base = {
        "context": {"caller": "0xbeef", "owner": "0xa11ce", "attacker": "0xbeef"},
        "before": {"storage": {"treasury": {"0x1": "0x3e8", "0x2": "0x0"}}},
    }
    return ExampleReplay(
        case=_case(
            "golden-asset-flow",
            "asset_flow",
            "Unauthorized treasury drain",
            "An arbitrary caller can transfer treasury tokens.",
            "The drain entry point omits its ownership check.",
            obligations,
        ),
        vulnerable_trace=(call, drain, gain),
        vulnerable_state_diff={
            **base,
            "after": {"storage": {"treasury": {"0x1": "0x1f4", "0x2": "0x1f4"}}},
        },
        neutralized_trace=(call,),
        neutralized_state_diff={
            "context": base["context"],
            "before": {"storage": {}},
            "after": {"storage": {}},
        },
    )


def example_replays() -> tuple[ExampleReplay, ...]:
    return authorization_replay(), accounting_replay(), asset_flow_replay()
