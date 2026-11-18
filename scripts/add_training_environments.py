#!/usr/bin/env python3
"""Add isolated D_tra workspaces to the pinned environment manifest."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/processed"
DEFI = ROOT / "data/raw/DeFiHackLabs"
WORKSPACES = DATA / "environments/workspaces"
MANIFEST = DATA / "environments/manifest.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    if path.is_file():
        digest.update(path.read_bytes())
        return digest.hexdigest()
    for item in sorted(path.rglob("*")):
        if item.is_file() and not item.is_symlink():
            digest.update(str(item.relative_to(path)).encode())
            digest.update(hashlib.sha256(item.read_bytes()).digest())
    return digest.hexdigest()


def main() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    existing = {row["record_id"] for row in manifest["records"]}
    candidates = sorted((DATA / "defihacklabs/candidates").glob("*.json"))
    added = 0
    for path in candidates:
        candidate = json.loads(path.read_text(encoding="utf-8"))
        record_id = candidate["case_id"]
        if record_id in existing:
            continue
        workspace = WORKSPACES / record_id
        if workspace.exists():
            shutil.rmtree(workspace)
        workspace.mkdir(parents=True)
        (workspace / "source-root.txt").write_text(str(DEFI.resolve()) + "\n", encoding="utf-8")
        (workspace / "foundry.toml").write_text(
            "[profile.default]\n"
            "src = 'src'\n"
            "out = 'out'\n"
            "libs = ['lib']\n"
            "evm_version = 'shanghai'\n"
            "offline = true\n",
            encoding="utf-8",
        )
        # Keep all imports inside the isolated Foundry root.  Symlinks to the
        # source checkout are rejected by Foundry's allowed-directory check.
        shutil.copytree(DEFI / "src", workspace / "src")
        shutil.copytree(DEFI / "lib", workspace / "lib")
        source = DEFI / candidate["source_file"]
        manifest["records"].append(
            {
                "record_id": record_id,
                "dataset": "D_tra",
                "source_root": str(DEFI.resolve()),
                "source_file": candidate["source_file"],
                "workspace": str(workspace.resolve()),
                "source_exists": source.is_file(),
                "fork_block": candidate.get("fork", {}).get("block"),
                "source_commit": candidate["source_commit"],
                "status": "COMPILE_PENDING" if source.is_file() else "SOURCE_MISSING",
                "compile_evidence": "case_level_forge_build",
                "source_sha256": sha256(source) if source.is_file() else None,
                "workspace_sha256": sha256(workspace),
            }
        )
        added += 1
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"added": added, "total": len(manifest["records"])}, indent=2))


if __name__ == "__main__":
    main()
