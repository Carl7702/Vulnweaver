from __future__ import annotations

from pathlib import Path

import pytest

from vulnweaver.common.schema import EnvironmentKind, EnvironmentSpec
from vulnweaver.task_construction.workspace import (
    WorkspaceMaterializationError,
    materialize_foundry_workspace,
)


def _environment(repository: str) -> EnvironmentSpec:
    return EnvironmentSpec(
        environment_id="workspace-test",
        kind=EnvironmentKind.VULNERABLE,
        repository=repository,
        commit="abcdef123456",
        chain="local",
        chain_id=31337,
        fork_block=0,
        foundry_version="1.3.1",
        solc_version="0.8.24",
        settings={"compose_workspace": True},
    )


def test_materializer_exposes_target_and_solidity_candidate_only(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    target = repository / "target"
    candidate = tmp_path / "candidate"
    (target / "src").mkdir(parents=True)
    (target / "test").mkdir()
    candidate.mkdir()
    (target / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (target / "src" / "Target.sol").write_text("contract Target {}\n", encoding="utf-8")
    (target / "test" / "sealed.sol").write_text("sealed\n", encoding="utf-8")
    (candidate / "Exploit.sol").write_text("contract Exploit {}\n", encoding="utf-8")
    (candidate / "notes.txt").write_text("not executable\n", encoding="utf-8")

    output = materialize_foundry_workspace(
        environment=_environment("target"),
        candidate_dir=candidate,
        repository_root=repository,
        destination=tmp_path / "output",
    )

    assert (output / "src" / "Target.sol").is_file()
    assert (output / "test" / "Exploit.sol").is_file()
    assert not (output / "test" / "sealed.sol").exists()
    assert not (output / "test" / "notes.txt").exists()


def test_materializer_rejects_candidate_symlinks(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    target = repository / "target"
    candidate = tmp_path / "candidate"
    target.mkdir(parents=True)
    candidate.mkdir()
    (target / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    source = tmp_path / "outside.sol"
    source.write_text("contract Outside {}\n", encoding="utf-8")
    (candidate / "Exploit.sol").symlink_to(source)

    with pytest.raises(WorkspaceMaterializationError, match="symlinks"):
        materialize_foundry_workspace(
            environment=_environment("target"),
            candidate_dir=candidate,
            repository_root=repository,
            destination=tmp_path / "output",
        )
