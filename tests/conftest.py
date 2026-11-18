from __future__ import annotations

from pathlib import Path

import pytest

from vulnweaver.common.schema import (
    AgentRole,
    Budget,
    CaseSpec,
    DatasetSplit,
    EnvironmentKind,
    EnvironmentSpec,
    FindingSpec,
    ObligationKind,
    ObligationSpec,
    PredicateSpec,
    Severity,
    TaskSpec,
)


@pytest.fixture()
def sample_case() -> CaseSpec:
    environment = EnvironmentSpec(
        environment_id="golden-ev",
        kind=EnvironmentKind.VULNERABLE,
        repository="https://example.invalid/repository.git",
        commit="0123456789abcdef",
        chain="local",
        chain_id=31337,
        fork_block=0,
        foundry_version="1.3.1",
        solc_version="0.8.24",
    )
    obligations = tuple(
        ObligationSpec(
            obligation_id=f"obligation-{kind.value}",
            kind=kind,
            description=f"Check {kind.value}",
            predicate=PredicateSpec(template=f"test.{kind.value}", parameters={}),
        )
        for kind in ObligationKind
    )
    return CaseSpec(
        case_id="golden-001",
        source="unit-test",
        split=DatasetSplit.TEST,
        project_id="golden",
        finding=FindingSpec(
            finding_id="finding-001",
            title="Synthetic authorization issue",
            vulnerability_type="authorization",
            severity=Severity.HIGH,
            report="An unauthorized caller can mutate protected state.",
            root_cause="The function omits an authorization check.",
            affected_functions=("mutate()",),
        ),
        Ev=environment,
        obligations=obligations,
        tasks=(
            TaskSpec(
                task_id="prepare",
                description="Prepare accounts",
                required_role=AgentRole.STATE_PREPARATION,
                produces=("accounts",),
            ),
            TaskSpec(
                task_id="build",
                description="Build candidate",
                required_role=AgentRole.POC_BUILDER,
                prerequisites=("prepare",),
                produces=("candidate",),
            ),
        ),
        allowed_operations={
            AgentRole.STATE_PREPARATION: ("propose_accounts",),
            AgentRole.POC_BUILDER: ("edit_candidate",),
        },
        budget=Budget(),
    )


@pytest.fixture()
def sample_case_path(tmp_path: Path, sample_case: CaseSpec) -> Path:
    path = tmp_path / "case.json"
    path.write_text(sample_case.model_dump_json(by_alias=True, indent=2), encoding="utf-8")
    return path

