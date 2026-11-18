#!/usr/bin/env python3
"""Attach pinned vulnerable and patched CVE snapshots as case workspaces.

This is a snapshot-materialization step, not executable admission.  Each case
gets an Ev/Ep pair and immutable source metadata; status remains
``SNAPSHOT_READY`` until case-specific build, reset, obligations, and replay
checks pass.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
CATALOG = DATA / "processed/cve/catalog.json"
ENVIRONMENTS = DATA / "processed/environments"
MANIFEST = ENVIRONMENTS / "manifest.json"


def replace_link(target: Path, source: Path) -> None:
    if target.exists() or target.is_symlink():
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        else:
            target.unlink()
    target.symlink_to(source.resolve(), target_is_directory=True)


def main() -> None:
    catalog = json.loads(CATALOG.read_text())["records"]
    manifest = json.loads(MANIFEST.read_text())
    rows = {row["record_id"]: row for row in manifest["records"]}
    for item in catalog:
        record_id = f"cve-{item['cve_id'].lower()}"
        workspace = ENVIRONMENTS / "workspaces" / record_id
        workspace.mkdir(parents=True, exist_ok=True)
        vulnerable = DATA / "raw" / item["vulnerable_snapshot"]
        patched = DATA / "raw" / item["fixed_snapshot"]
        replace_link(workspace / "Ev", vulnerable)
        replace_link(workspace / "Ep", patched)
        case_manifest = {
            "case_id": record_id,
            "project_id": item["project_id"],
            "vulnerable_version": item["vulnerable_version"],
            "fixed_version": item["fixed_version"],
            "vulnerable_commit": item["vulnerable_commit"],
            "fixed_commit": item["fixed_commit"],
            "vulnerable_snapshot_sha256": item["vulnerable_snapshot_sha256"],
            "fixed_snapshot_sha256": item["fixed_snapshot_sha256"],
            "admission": "snapshot-only; build and replay pending",
        }
        (workspace / "environment.json").write_text(
            json.dumps(case_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        rows[record_id] = {
            "record_id": record_id,
            "dataset": "D_cve",
            "status": "SNAPSHOT_READY",
            "workspace": str(workspace.resolve()),
            "vulnerable_source": str(vulnerable.resolve()),
            "patched_source": str(patched.resolve()),
            "source_commit": item["vulnerable_commit"],
            "patched_commit": item["fixed_commit"],
            "source_sha256": item["vulnerable_snapshot_sha256"],
            "patched_sha256": item["fixed_snapshot_sha256"],
            "reason": "pinned Ev/Ep sources collected; case-specific execution pending",
        }
    manifest["records"] = list(rows.values())
    MANIFEST.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"cve_snapshot_workspaces": len(catalog), "status": "SNAPSHOT_READY"}))


if __name__ == "__main__":
    main()
