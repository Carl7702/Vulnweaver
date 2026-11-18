from __future__ import annotations

import os
from pathlib import Path

import pytest

from vulnweaver.common.schema import (
    CaseSpec,
    ErrorKind,
    OperationStatus,
    VerificationStatus,
)
from vulnweaver.task_construction.example_cases import ExampleReplay, example_replays
from vulnweaver.validation.execution import DockerFoundryBackend, ExecutionPolicyError
from vulnweaver.validation.obligations import TemplateObligationEvaluator
from vulnweaver.validation.verifier import IndependentVerifier


def test_execution_command_is_hardened(tmp_path: Path) -> None:
    backend = DockerFoundryBackend()

    command = backend._command(tmp_path, ("forge", "build"))

    assert "--network" in command
    assert "none" in command
    assert "--read-only" in command
    assert "no-new-privileges" in command
    assert "--cap-drop" in command
    assert command[command.index("--entrypoint") + 1] == "forge"
    assert command[-1] == "build"


def test_execution_blocks_broadcast(tmp_path: Path) -> None:
    backend = DockerFoundryBackend()

    with pytest.raises(ExecutionPolicyError, match="broadcast"):
        backend._command(tmp_path, ("forge", "test", "--broadcast"))


def test_execution_blocks_arbitrary_commands(tmp_path: Path) -> None:
    backend = DockerFoundryBackend()

    with pytest.raises(ExecutionPolicyError, match="only forge"):
        backend._command(tmp_path, ("sh", "-c", "id"))


def test_docker_daemon_failure_is_environment_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Completed:
        returncode = 125
        stdout = ""
        stderr = "Cannot connect to the Docker daemon"

    monkeypatch.setattr(
        "vulnweaver.validation.execution.subprocess.run",
        lambda *args, **kwargs: Completed(),
    )
    backend = DockerFoundryBackend()

    result = backend.build(tmp_path)

    assert result.status is OperationStatus.FAILED
    assert result.error_kind is ErrorKind.ENVIRONMENT


@pytest.mark.integration
@pytest.mark.skipif(os.getenv("VW_RUN_DOCKER_TESTS") != "1", reason="opt-in Docker test")
def test_pinned_foundry_container_smoke(tmp_path: Path) -> None:
    result = DockerFoundryBackend().smoke(tmp_path)

    assert result.status is OperationStatus.SUCCEEDED, result.message
    assert "forge" in result.message.lower()


@pytest.mark.integration
@pytest.mark.skipif(os.getenv("VW_RUN_DOCKER_TESTS") != "1", reason="opt-in Docker test")
def test_foundry_json_trace_and_storage_are_parsed(sample_case: CaseSpec) -> None:
    repository_root = Path(__file__).parents[2]
    candidate = repository_root / "examples" / "authorization" / "candidate"
    backend = DockerFoundryBackend(
        image="vulnweaver-foundry:1.3.1-solc0.8.24",
        repository_root=repository_root,
    )
    environment = sample_case.vulnerable_environment.model_copy(
        update={
            "repository": "examples/authorization/environments/ev",
            "settings": {
                "compose_workspace": True,
                "context": {"attacker": "0xbeef"},
            },
        }
    )
    backend.reset(sample_case, environment)

    build = backend.build(candidate)
    run = backend.run(candidate, test_name="testExploit")

    assert build.status is OperationStatus.SUCCEEDED, build.message
    assert run.status is OperationStatus.SUCCEEDED, run.message
    assert any(event.event_type == "storage_write" for event in backend.trace())
    after = backend.state_diff()["after"]
    assert isinstance(after, dict)
    assert after["storage"]["vault"]["0x0"] == "0xbeef"
    assert backend.state_diff()["context"] == {"attacker": "0xbeef"}


@pytest.mark.integration
@pytest.mark.skipif(os.getenv("VW_RUN_DOCKER_TESTS") != "1", reason="opt-in Docker test")
@pytest.mark.parametrize("golden", example_replays(), ids=lambda item: item.case.case_id)
def test_live_golden_cases_are_causally_validated(golden: ExampleReplay) -> None:
    repository_root = Path(__file__).parents[2]
    fixture_name = golden.case.case_id.removeprefix("golden-")
    candidate = repository_root / "examples" / fixture_name / "candidate"
    verifier = IndependentVerifier(
        lambda: DockerFoundryBackend(
            image="vulnweaver-foundry:1.3.1-solc0.8.24",
            repository_root=repository_root,
        ),
        TemplateObligationEvaluator(),
    )

    report = verifier.verify(candidate, golden.case)

    assert report.status is VerificationStatus.CAUSALLY_VALIDATED, report.errors
    assert report.prefix_equivalent is True
    assert report.errors == ()
