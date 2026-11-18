from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from vulnweaver.cli import app
from vulnweaver.common.schema import AgentRole, OperationStatus, VerificationStatus
from vulnweaver.policy_learning.coordination import (
    HeuristicSixAgentWorkflow,
    multi_transaction_case,
)
from vulnweaver.task_construction.isolation import construction_view


def test_controlled_workflow_runs_all_six_specialists_and_keeps_verifier_inputs_hidden(
    tmp_path: Path,
) -> None:
    case = multi_transaction_case()
    visible = construction_view(case)
    assert visible.neutralized_environment is None
    assert visible.patched_environment is None
    assert visible.reference_poc is None

    trajectory, state = HeuristicSixAgentWorkflow(Path.cwd()).run(case, tmp_path)

    assert [item.agent_role for item in trajectory.assignments] == list(AgentRole)
    assert all(item.status is OperationStatus.SUCCEEDED for item in trajectory.results)
    assert len(state.observations) == 6
    source = (tmp_path / "Exploit.t.sol").read_text(encoding="utf-8")
    assert source.count("vm.prank(ATTACKER)") == 2
    assert "target.setKeeper(ATTACKER)" in source
    assert "target.sweep(ATTACKER, 1_000)" in source


def test_controlled_cli_construct_returns_causal_validation(tmp_path: Path) -> None:
    case_path = tmp_path / "case.json"
    case_path.write_text(
        multi_transaction_case().model_dump_json(by_alias=True, indent=2), encoding="utf-8"
    )
    result = CliRunner().invoke(
        app,
        [
            "construct",
            str(case_path),
            "--output",
            str(tmp_path / "candidate"),
            "--repository-root",
            str(Path.cwd()),
        ],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["validation"]["status"] == VerificationStatus.CAUSALLY_VALIDATED.value
    assert len(payload["assignments"]) == 6
