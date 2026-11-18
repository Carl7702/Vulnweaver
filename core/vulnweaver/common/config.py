"""Configuration loading with secret redaction."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from vulnweaver.common.hashing import stable_hash

_SECRET_KEY = re.compile(r"(api[_-]?key|private[_-]?key|secret|password|token|rpc[_-]?url)", re.I)


def load_config(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        value = tomllib.load(stream)
    return value


def redact_secrets(value: Any) -> Any:
    """Remove secret-like values before persisting run configuration."""

    if isinstance(value, dict):
        return {
            str(key): "<redacted>" if _SECRET_KEY.search(str(key)) else redact_secrets(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_secrets(item) for item in value)
    return value


def config_snapshot(config: dict[str, Any]) -> tuple[dict[str, Any], str]:
    redacted = redact_secrets(config)
    return redacted, stable_hash(redacted)

