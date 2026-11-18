"""Container-only Foundry execution with an intentionally narrow command surface."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

from vulnweaver.common.hashing import stable_hash, tree_sha256
from vulnweaver.common.schema import (
    CaseSpec,
    EnvironmentSpec,
    ErrorKind,
    OperationResult,
    OperationStatus,
    TraceEvent,
)
from vulnweaver.task_construction.workspace import materialize_foundry_workspace
from vulnweaver.validation.foundry_parser import FoundryParseError, parse_foundry_json

_TEST_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_FORBIDDEN = {"--broadcast", "broadcast", "private-key", "private_key"}
_ENVIRONMENT_ERRORS = (
    "cannot connect to the docker daemon",
    "error during connect",
    "no such image",
    "manifest unknown",
)
DEFAULT_FOUNDRY_IMAGE = (
    "ghcr.io/foundry-rs/foundry@"
    "sha256:2dbf3d0fc58593ad9d01ef57677f93f83f4987acd295d17f303448d82e3a3ae7"
)


class ExecutionPolicyError(ValueError):
    pass


class DockerFoundryBackend:
    """Run only `forge build` and `forge test` in an ephemeral hardened container."""

    def __init__(
        self,
        *,
        image: str = DEFAULT_FOUNDRY_IMAGE,
        timeout_seconds: int = 120,
        docker_binary: str = "docker",
        network: str = "none",
        repository_root: Path | None = None,
    ) -> None:
        if network != "none":
            raise ExecutionPolicyError("network access is disabled by policy")
        self.image = image
        self.timeout_seconds = timeout_seconds
        self.docker_binary = docker_binary
        self.network = network
        self.repository_root = (repository_root or Path.cwd()).resolve()
        self._trace: tuple[TraceEvent, ...] = ()
        self._state_diff: dict[str, object] = {}
        self._reset_digest: str | None = None
        self._environment: EnvironmentSpec | None = None
        self._temporary_workspace: tempfile.TemporaryDirectory[str] | None = None
        self._candidate_source: Path | None = None

    def _ensure_available(self) -> None:
        if shutil.which(self.docker_binary) is None:
            raise RuntimeError(f"Docker executable not found: {self.docker_binary}")

    def _command(self, candidate_dir: Path, forge_args: Sequence[str]) -> list[str]:
        resolved = candidate_dir.resolve(strict=True)
        if not resolved.is_dir():
            raise ExecutionPolicyError("candidate path must be a directory")
        lowered = {part.lower() for part in forge_args}
        if lowered & _FORBIDDEN or any("broadcast" in part.lower() for part in forge_args):
            raise ExecutionPolicyError("broadcast and private-key arguments are forbidden")
        if not forge_args or tuple(forge_args[:2]) not in {
            ("forge", "build"),
            ("forge", "test"),
            ("forge", "--version"),
        }:
            raise ExecutionPolicyError(
                "only forge build, forge test, and forge --version are allowed"
            )
        return [
            self.docker_binary,
            "run",
            "--rm",
            "--network",
            self.network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=256m",
            "--mount",
            f"type=bind,src={resolved},dst=/workspace",
            "--workdir",
            "/workspace",
            "--entrypoint",
            "forge",
            self.image,
            *forge_args[1:],
        ]

    def _execute(
        self,
        candidate_dir: Path,
        forge_args: Sequence[str],
        operation_id: str,
    ) -> OperationResult:
        self._ensure_available()
        execution_dir = self._execution_directory(candidate_dir)
        started = time.monotonic()
        try:
            completed = subprocess.run(
                self._command(execution_dir, forge_args),
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                env={"PATH": "/usr/bin:/bin:/usr/local/bin"},
            )
        except subprocess.TimeoutExpired as error:
            timeout_output = error.stdout or ""
            if isinstance(timeout_output, bytes):
                timeout_output = timeout_output.decode("utf-8", errors="replace")
            return OperationResult(
                operation_id=operation_id,
                status=OperationStatus.TIMED_OUT,
                error_kind=ErrorKind.TIMEOUT,
                message=timeout_output[-4000:],
                duration_seconds=time.monotonic() - started,
            )
        output = (completed.stdout + "\n" + completed.stderr).strip()[-20_000:]
        succeeded = completed.returncode == 0
        error_kind = ErrorKind.NONE
        if succeeded and forge_args[1] == "test" and "--json" in forge_args:
            expected_test: str | None = None
            if "--match-test" in forge_args:
                match_index = forge_args.index("--match-test")
                expected_test = forge_args[match_index + 1]
            try:
                parsed = parse_foundry_json(completed.stdout, expected_test=expected_test)
            except FoundryParseError as error:
                succeeded = False
                error_kind = ErrorKind.INTERNAL
                output = f"Foundry evidence parsing failed: {error}"
            else:
                self._trace = parsed.trace
                parsed_diff = parsed.state_diff
                if self._environment is not None:
                    parsed_diff["context"] = dict(
                        self._environment.settings.get("context", {})
                    )
                self._state_diff = parsed_diff
                output = (
                    f"{parsed.suite}::{parsed.test} status={parsed.status} "
                    f"events={len(parsed.trace)}"
                )
        if not succeeded and error_kind is ErrorKind.NONE:
            lowered_output = output.lower()
            if any(fragment in lowered_output for fragment in _ENVIRONMENT_ERRORS):
                error_kind = ErrorKind.ENVIRONMENT
            elif forge_args[1] == "build":
                error_kind = ErrorKind.COMPILE
            else:
                error_kind = ErrorKind.REVERT
        return OperationResult(
            operation_id=operation_id,
            status=OperationStatus.SUCCEEDED if succeeded else OperationStatus.FAILED,
            error_kind=error_kind,
            message=output,
            duration_seconds=time.monotonic() - started,
        )

    def reset(self, case: CaseSpec, environment: EnvironmentSpec) -> str:
        if self._temporary_workspace is not None:
            self._temporary_workspace.cleanup()
            self._temporary_workspace = None
            self._candidate_source = None
        self._trace = ()
        self._state_diff = {}
        self._environment = environment
        self._reset_digest = self.digest(case, environment)
        return self._reset_digest

    def _execution_directory(self, candidate_dir: Path) -> Path:
        environment = self._environment
        if environment is None or not environment.settings.get("compose_workspace", False):
            return candidate_dir
        resolved_candidate = candidate_dir.resolve(strict=True)
        if self._temporary_workspace is not None:
            if self._candidate_source != resolved_candidate:
                raise ExecutionPolicyError("candidate changed within one environment replay")
            return Path(self._temporary_workspace.name)
        self._temporary_workspace = tempfile.TemporaryDirectory(prefix="vulnweaver-foundry-")
        self._candidate_source = resolved_candidate
        destination = Path(self._temporary_workspace.name)
        return materialize_foundry_workspace(
            environment=environment,
            candidate_dir=resolved_candidate,
            repository_root=self.repository_root,
            destination=destination,
        )

    def build(self, candidate_dir: Path) -> OperationResult:
        return self._execute(candidate_dir, ("forge", "build"), "foundry-build")

    def run(self, candidate_dir: Path, *, test_name: str | None = None) -> OperationResult:
        args = ["forge", "test", "-vvvvv", "--json"]
        if test_name is not None:
            if not _TEST_NAME.fullmatch(test_name):
                raise ExecutionPolicyError("invalid Foundry test name")
            args.extend(("--match-test", test_name))
        return self._execute(candidate_dir, args, "foundry-test")

    def trace(self) -> Sequence[TraceEvent]:
        # Returning no invented evidence when no structured trace is available is deliberate.
        return self._trace

    def state_diff(self) -> Mapping[str, object]:
        return self._state_diff

    def digest(self, case: CaseSpec, environment: EnvironmentSpec) -> str:
        target_digest: str | None = None
        if environment.settings.get("compose_workspace", False):
            target_root = (self.repository_root / environment.repository).resolve(strict=True)
            if not target_root.is_relative_to(self.repository_root):
                raise ExecutionPolicyError("environment repository escapes repository root")
            target_digest = tree_sha256(target_root)
        return stable_hash(
            {
                "case": case,
                "environment": environment,
                "image": self.image,
                "network": self.network,
                "target_digest": target_digest,
            }
        )

    def candidate_digest(self, candidate_dir: Path) -> str:
        return tree_sha256(candidate_dir.resolve(strict=True))

    def smoke(self, workspace: Path) -> OperationResult:
        return self._execute(workspace, ("forge", "--version"), "foundry-smoke")

