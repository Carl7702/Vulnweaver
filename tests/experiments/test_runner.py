from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnweaver.experiments.runner import (
    ExperimentBudget,
    ExperimentFailure,
    ExperimentMethod,
    discover_experiment_cases,
    load_experiment_run,
    run_experiment,
    write_experiment_summary,
)


def test_offline_methods_share_case_pool_and_emit_manifest(tmp_path: Path) -> None:
    cases = discover_experiment_cases(Path("examples"))
    output = tmp_path / "evaluation"
    run = run_experiment(
        cases,
        output,
        methods=(
            ExperimentMethod.DIRECT_PROMPTING,
            ExperimentMethod.PROGRESS_GUIDED_REWARD,
        ),
    )

    assert run.case_pool_sha256
    assert all(item.project_id for item in run.cases)
    assert run.evaluation_mode == "offline_replay"
    assert run.resource_accounting == "profiled"
    assert {item.case_id for item in run.cases} == {
        "golden-authorization",
        "golden-accounting",
        "golden-asset-flow",
    }
    assert len(run.results) == 6
    assert all(item.causal_validation for item in run.results)
    assert all(item.usage.within(run.budget) for item in run.results)
    assert run.metrics[0].epr == 1.0
    assert run.metrics[1].reward_mode.value == "progress_guided"
    assert list(output.rglob("Candidate.t.sol"))
    assert "source_file" not in (output / "experiment.json").read_text(encoding="utf-8")
    assert load_experiment_run(output / "experiment.json").run_id == run.run_id

    write_experiment_summary(output / "summary.md", run)
    assert "progress_guided_reward" in (output / "summary.md").read_text(encoding="utf-8")
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["data_hashes"]["case_pool"] == run.case_pool_sha256
    assert len(manifest["config"]["code_sha256"]) == 64
    assert manifest["config"]["resource_accounting"] == "profiled"
    assert all(f"replay:{item.case_id}" in manifest["data_hashes"] for item in run.cases)


def test_budget_gate_is_recorded_per_case(tmp_path: Path) -> None:
    cases = discover_experiment_cases(Path("examples"))[:1]
    run = run_experiment(
        cases,
        tmp_path / "budget",
        methods=(ExperimentMethod.HIERARCHICAL_COORDINATION,),
        budget=ExperimentBudget(model_calls=1),
    )
    result = run.results[0]
    assert result.failure_type is ExperimentFailure.BUDGET
    assert result.causal_validation is False


def test_case_discovery_rejects_replay_hash_mismatch(tmp_path: Path) -> None:
    source = Path("examples/authorization")
    destination = tmp_path / "golden-authorization"
    destination.mkdir()
    (destination / "case.json").write_bytes((source / "case.json").read_bytes())
    payload = json.loads((source / "replay.json").read_text(encoding="utf-8"))
    payload["case_sha256"] = "0" * 64
    (destination / "replay.json").write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="replay/case hash mismatch"):
        discover_experiment_cases(tmp_path)


def test_case_pool_rejects_duplicates_before_running(tmp_path: Path) -> None:
    case = discover_experiment_cases(Path("examples"))[0]
    with pytest.raises(ValueError, match="case ids must be unique"):
        run_experiment([case, case], tmp_path / "run")
    assert not (tmp_path / "run").exists()


def test_changed_replay_is_rejected_before_running(tmp_path: Path) -> None:
    case = discover_experiment_cases(Path("examples"))[0]
    replay = tmp_path / "replay.json"
    replay.write_bytes(Path(case.replay_path).read_bytes() + b"\n")
    altered = case.model_copy(update={"replay_path": str(replay)})
    with pytest.raises(ValueError, match="input changed since discovery"):
        run_experiment([altered], tmp_path / "run")
    assert not (tmp_path / "run").exists()
