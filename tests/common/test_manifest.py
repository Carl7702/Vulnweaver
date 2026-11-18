from __future__ import annotations

import json
from pathlib import Path

from vulnweaver.common.manifest import create_manifest, write_manifest


def test_manifest_redacts_secrets_and_is_atomic(tmp_path: Path) -> None:
    manifest = create_manifest(
        repository=tmp_path,
        command=("vw", "construct"),
        config={
            "model": {"api_key": "do-not-store", "name": "fake"},
            "rpc_url": "https://secret.invalid",
        },
    )
    path = tmp_path / "run" / "manifest.json"

    write_manifest(path, manifest)
    persisted = json.loads(path.read_text(encoding="utf-8"))

    assert persisted["config"]["model"]["api_key"] == "<redacted>"
    assert persisted["config"]["rpc_url"] == "<redacted>"
    assert "do-not-store" not in path.read_text(encoding="utf-8")

