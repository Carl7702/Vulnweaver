from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from vulnweaver.cli import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == "0.1.0"


def test_help_lists_research_commands() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0, result.stdout
    for command in ("construct", "verify", "train", "evaluate", "report", "dataset"):
        assert command in result.stdout


def test_fake_model_smoke() -> None:
    result = runner.invoke(app, ["smoke-fake-model"])

    assert result.exit_code == 0
    assert result.stdout.strip() == "offline-ok"


def test_case_inspect(sample_case_path: Path) -> None:
    result = runner.invoke(app, ["case", "inspect", str(sample_case_path)])

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["case"]["case_id"] == "golden-001"
    assert len(payload["hash"]) == 64


def test_dataset_admit(sample_case_path: Path) -> None:
    result = runner.invoke(
        app,
        ["dataset", "admit", str(sample_case_path), "--no-verify-inputs"],
    )

    assert result.exit_code == 0, result.stdout
    assert json.loads(result.stdout)["status"] == "SCHEMA_VALID"


def test_export_and_verify_controlled_replay(tmp_path: Path) -> None:
    output = tmp_path / "examples"
    exported = runner.invoke(app, ["case", "export-examples", "--output", str(output)])
    assert exported.exit_code == 0, exported.stdout
    case_dir = output / "authorization"

    verified = runner.invoke(
        app,
        [
            "verify",
            str(case_dir / "case.json"),
            str(case_dir),
            "--replay",
            str(case_dir / "replay.json"),
        ],
    )

    assert verified.exit_code == 0, verified.stdout
    assert json.loads(verified.stdout)["status"] == "CAUSALLY_VALIDATED"


def test_evaluate_to_project_clustered_report(tmp_path: Path) -> None:
    evaluated = runner.invoke(
        app,
        [
            "evaluate",
            "--cases-root",
            "examples",
            "--output",
            str(tmp_path / "run"),
            "--methods",
            "direct_prompting",
        ],
    )
    assert evaluated.exit_code == 0, evaluated.stdout
    run = json.loads(evaluated.stdout)
    assert run["evaluation_mode"] == "offline_replay"
    assert all(case["project_id"] for case in run["cases"])
    reported = runner.invoke(
        app,
        [
            "report",
            str(tmp_path / "run" / "experiment.json"),
            "--output",
            str(tmp_path / "report"),
            "--bootstrap-samples",
            "50",
        ],
    )
    assert reported.exit_code == 0, reported.stdout
    report = json.loads(reported.stdout)
    assert report["resampling_unit"] == "project"
    assert report["bootstrap_samples"] == 50
    assert (tmp_path / "report" / "paper-table.csv").is_file()
