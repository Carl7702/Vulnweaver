"""Case loading and admission checks."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from vulnweaver.common.hashing import file_sha256, stable_hash
from vulnweaver.common.schema import CaseSpec


class CaseLoadError(ValueError):
    pass


def load_case(path: Path, *, verify_inputs: bool = False) -> CaseSpec:
    try:
        case = CaseSpec.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError, json.JSONDecodeError) as error:
        raise CaseLoadError(f"cannot load case {path}: {error}") from error

    if verify_inputs:
        base = path.parent.resolve()
        for artifact in case.inputs:
            artifact_path = (base / artifact.path).resolve()
            if not artifact_path.is_relative_to(base):
                raise CaseLoadError(f"input escapes case directory: {artifact.path}")
            if not artifact_path.is_file():
                raise CaseLoadError(f"input is missing: {artifact.path}")
            actual = file_sha256(artifact_path)
            if actual != artifact.sha256:
                raise CaseLoadError(
                    f"input hash mismatch for {artifact.path}: "
                    f"expected {artifact.sha256}, got {actual}"
                )
    return case


def case_hash(case: CaseSpec) -> str:
    """The same normalized case always maps to the same SHA-256 digest."""

    return stable_hash(case)

