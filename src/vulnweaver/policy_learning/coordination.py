"""Deterministic six-specialist workflow for a controlled construction example."""

from __future__ import annotations

import time
from pathlib import Path

from vulnweaver.common.schema import (
    AgentOperation,
    AgentRole,
    Assignment,
    Budget,
    CaseSpec,
    ConstructionState,
    HistoryEntry,
    Observation,
    OperationResult,
    OperationStatus,
    Trajectory,
)
from vulnweaver.task_construction.isolation import construction_view
from vulnweaver.validation.execution import DockerFoundryBackend

_ORDER = (
    (AgentRole.STATE_PREPARATION, "inspect_local_fixture"),
    (AgentRole.AUTHORIZATION, "model_caller_constraints"),
    (AgentRole.ASSET_FLOW, "set_bounded_impact"),
    (AgentRole.DEPENDENCY, "order_dependent_calls"),
    (AgentRole.POC_BUILDER, "write_candidate_test"),
    (AgentRole.EXECUTION_DIAGNOSIS, "compile_and_run_candidate"),
)

_SOURCE_HEADER = """// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.24;

import {KeeperVault} from "../src/KeeperVault.sol";

interface Vm {
    function label(address account, string calldata label) external;
    function prank(address sender) external;
}

contract ExploitTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private constant ATTACKER = address(0xBEEF);
    KeeperVault private target;

    function setUp() public {
        target = new KeeperVault();
        vm.label(address(target), "vault");
        vm.label(ATTACKER, "attacker");
    }

    function testExploit() public {
"""

_SOURCE_STEPS = """        vm.prank(ATTACKER);
        target.setKeeper(ATTACKER);
        vm.prank(ATTACKER);
        target.sweep(ATTACKER, 1_000);
"""

_SOURCE_FOOTER = """    }
}
"""


class HeuristicSixAgentWorkflow:
    """Run allow-listed specialist operations against the local multi-tx recipe."""

    def __init__(self, repository_root: Path) -> None:
        self.repository_root = repository_root.resolve(strict=True)

    def run(self, case: CaseSpec, output: Path) -> tuple[Trajectory, ConstructionState]:
        visible_case = construction_view(case)
        if case.case_id != "golden-multi-transaction":
            raise ValueError(
                "controlled workflow currently supports golden-multi-transaction"
            )
        state = ConstructionState(case_id=visible_case.case_id, remaining_budget=case.budget)
        trajectory = Trajectory(case_id=case.case_id)
        output.mkdir(parents=True, exist_ok=True)
        candidate_file = output / "Exploit.t.sol"

        for sequence, (role, capability) in enumerate(_ORDER):
            allowed = visible_case.allowed_operations.get(role, ())
            if capability not in allowed:
                raise ValueError(f"operation {capability!r} is not allowed for {role.value}")
            assignment = Assignment(
                assignment_id=f"assignment-{sequence}",
                task_id=f"task-{role.value}",
                agent_role=role,
                sequence=sequence,
            )
            operation = AgentOperation(
                operation_id=f"operation-{sequence}",
                assignment_id=assignment.assignment_id,
                role=role,
                capability=capability,
            )
            trajectory.assignments.append(assignment)
            trajectory.operations.append(operation)
            result = self._execute(
                role, operation.operation_id, candidate_file, output, visible_case
            )
            trajectory.results.append(result)
            state.observations.extend(result.observations)
            state.history.append(
                HistoryEntry(
                    sequence=sequence,
                    assignment_id=assignment.assignment_id,
                    operation_id=operation.operation_id,
                    summary=result.message,
                )
            )
            if result.status is not OperationStatus.SUCCEEDED:
                break

        if len(trajectory.results) == len(_ORDER) and all(
            result.status is OperationStatus.SUCCEEDED for result in trajectory.results
        ):
            state.candidate_files["Exploit.t.sol"] = candidate_file.read_text(encoding="utf-8")
        return trajectory, state

    def _execute(
        self,
        role: AgentRole,
        operation_id: str,
        candidate_file: Path,
        output: Path,
        case: CaseSpec,
    ) -> OperationResult:
        started = time.monotonic()
        observations: list[Observation] = []
        message = ""
        try:
            if role is AgentRole.STATE_PREPARATION:
                fixture = (
                    self.repository_root / "examples/multi-transaction/environments/ev"
                )
                if not (fixture / "foundry.toml").is_file():
                    raise FileNotFoundError("local Ev fixture is incomplete")
                message = "confirmed deterministic local deployment and attacker account"
                observations.append(Observation(source=operation_id, kind="prepared_state"))
            elif role is AgentRole.AUTHORIZATION:
                message = "modeled an unprivileged caller and the keeper authorization transition"
                observations.append(
                    Observation(
                        source=operation_id,
                        kind="caller_constraint",
                        data={"caller": "attacker", "required_transition": "setKeeper"},
                    )
                )
            elif role is AgentRole.ASSET_FLOW:
                message = "bounded the local asset-flow probe to the fixture treasury balance"
                observations.append(
                    Observation(
                        source=operation_id,
                        kind="asset_constraint",
                        data={"amount": 1_000, "unit": "fixture_native_units"},
                    )
                )
            elif role is AgentRole.DEPENDENCY:
                message = "ordered keeper takeover before the dependent sweep call"
                observations.append(
                    Observation(
                        source=operation_id,
                        kind="call_dependency",
                        data={"before": "setKeeper", "after": "sweep"},
                    )
                )
            elif role is AgentRole.POC_BUILDER:
                candidate_file.write_text(
                    _SOURCE_HEADER + _SOURCE_STEPS + _SOURCE_FOOTER,
                    encoding="utf-8",
                )
                message = "generated a two-transaction Foundry candidate from approved recipe steps"
                observations.append(
                    Observation(
                        source=operation_id,
                        kind="candidate_written",
                        data={"path": candidate_file.name, "transactions": 2},
                    )
                )
            elif role is AgentRole.EXECUTION_DIAGNOSIS:
                backend = DockerFoundryBackend(
                    image="vulnweaver-foundry:1.3.1-solc0.8.24",
                    repository_root=self.repository_root,
                )
                backend.reset(case, case.vulnerable_environment)
                build = backend.build(output)
                if build.status is not OperationStatus.SUCCEEDED:
                    raise ValueError(f"candidate build failed: {build.message}")
                run = backend.run(output, test_name="testExploit")
                if run.status is not OperationStatus.SUCCEEDED:
                    raise ValueError(f"candidate execution failed: {run.message}")
                message = "compiled and executed the two-call candidate in the local Ev container"
                observations.append(
                    Observation(
                        source=operation_id,
                        kind="candidate_execution",
                        data={"trace_events": len(backend.trace())},
                    )
                )
            else:
                raise ValueError(f"unsupported controlled-example role: {role.value}")
            status = OperationStatus.SUCCEEDED
        except (OSError, ValueError) as error:
            message = str(error)
            status = OperationStatus.FAILED
        return OperationResult(
            operation_id=operation_id,
            status=status,
            message=message,
            observations=observations,
            duration_seconds=time.monotonic() - started,
        )


def multi_transaction_case() -> CaseSpec:
    """Return the controlled case and its six-role operation allow-list."""

    from vulnweaver.common.schema import (
        EnvironmentKind,
        FindingSpec,
        ObligationKind,
        ObligationSpec,
        PredicateSpec,
        Severity,
        TaskSpec,
    )
    from vulnweaver.task_construction.example_cases import _environment


    tasks = tuple(
        TaskSpec(
            task_id=role.value,
            description=f"Run {role.value} specialist",
            required_role=role,
            prerequisites=(() if index == 0 else (AgentRole.STATE_PREPARATION.value,)),
        )
        for index, (role, _) in enumerate(_ORDER)
    )
    obligations = (
        ObligationSpec(
            obligation_id="setup",
            kind=ObligationKind.SETUP,
            description="The attacker starts without keeper authority",
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
            description="The multi-step keeper takeover path executes",
            predicate=PredicateSpec(
                template="trace_call",
                parameters={"match": {"target": "vault", "selector": "0x748747e6"}},
            ),
        ),
        ObligationSpec(
            obligation_id="violation",
            kind=ObligationKind.VIOLATION,
            description="An unauthorized caller becomes keeper",
            predicate=PredicateSpec(
                template="storage_transition",
                parameters={"target": "vault", "key": "0x1", "after": "0xbeef"},
            ),
        ),
        ObligationSpec(
            obligation_id="impact",
            kind=ObligationKind.IMPACT,
            description="The attacker receives the fixture treasury balance",
            predicate=PredicateSpec(
                template="delta",
                parameters={
                    "before_path": "before.storage.vault.0x3",
                    "after_path": "after.storage.vault.0x3",
                    "operator": "ge",
                    "threshold": 1_000,
                },
            ),
        ),
    )
    return CaseSpec(
        case_id="golden-multi-transaction",
        source="controlled-example-foundry",
        project_id="golden-multi-transaction",
        attack_family="authorization_to_asset_flow",
        finding=FindingSpec(
            finding_id="golden-multi-transaction-finding",
            title="Unauthorized keeper takeover enables treasury sweep",
            vulnerability_type="authorization",
            severity=Severity.HIGH,
            report="An arbitrary caller can become keeper and sweep the local treasury.",
            root_cause="The keeper setter omits owner authorization.",
            affected_functions=("setKeeper(address)", "sweep(address,uint256)"),
        ),
        Ev=_environment("golden-multi-transaction", EnvironmentKind.VULNERABLE),
        Er=_environment("golden-multi-transaction", EnvironmentKind.ROOT_CAUSE_NEUTRALIZED),
        obligations=obligations,
        tasks=tasks,
        allowed_operations={role: (capability,) for role, capability in _ORDER},
        budget=Budget(),
    )


def export_multi_transaction_case(path: Path) -> CaseSpec:
    case = multi_transaction_case()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(case.model_dump_json(by_alias=True, indent=2) + "\n", encoding="utf-8")
    return case
