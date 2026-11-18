"""Run-manifest creation and atomic persistence."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

from vulnweaver.common.config import config_snapshot
from vulnweaver.common.schema import RunManifest


def _git_value(repository: Path, *args: str) -> str | None:
    completed = subprocess.run(
        ("git", "-C", str(repository), *args),
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip() if completed.returncode == 0 else None


def create_manifest(
    *,
    repository: Path,
    command: tuple[str, ...],
    config: dict[str, Any],
    case_id: str | None = None,
    seed: int = 42,
) -> RunManifest:
    snapshot, digest = config_snapshot(config)
    commit = _git_value(repository, "rev-parse", "HEAD")
    status = _git_value(repository, "status", "--porcelain")
    return RunManifest(
        run_id=uuid.uuid4().hex,
        case_id=case_id,
        command=command,
        seed=seed,
        config=snapshot,
        config_sha256=digest,
        code_commit=commit,
        code_dirty=bool(status) if status is not None else None,
    )


def write_manifest(path: Path, manifest: RunManifest) -> None:
    """Atomically persist a manifest to avoid half-written research records."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        manifest.model_dump(mode="json", by_alias=True),
        sort_keys=True,
        indent=2,
        ensure_ascii=False,
    )
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(payload + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise

