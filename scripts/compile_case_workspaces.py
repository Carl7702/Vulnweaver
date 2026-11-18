#!/usr/bin/env python3
"""Compile every imported case workspace and update the environment manifest.

Each case has an isolated workspace, so compilation can run concurrently. The
manifest is rewritten only after all workers finish and contains command, exit
code, output, and content hashes for every case.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from solidity_toolchain import resolve

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "data/processed/environments/manifest.json"


def digest(path: Path) -> str:
    h = hashlib.sha256()
    if path.is_file():
        h.update(path.read_bytes())
    else:
        for item in sorted(path.rglob("*")):
            if item.is_file() and not item.is_symlink():
                h.update(str(item.relative_to(path)).encode())
                h.update(hashlib.sha256(item.read_bytes()).digest())
    return h.hexdigest()


def compile_one(row: dict) -> dict:
    workspace = Path(row["workspace"])
    source_root = workspace / "source"
    if not source_root.exists():
        source_root = workspace / "src"
    target = None
    if row["dataset"] in {"D_inc", "D_tra"}:
        target = workspace / row["source_file"]
    elif source_root.exists():
        files = sorted(source_root.rglob("*.sol"))
        target = files[0] if files else None
    if not target or not target.exists():
        row.update({"status": "SOURCE_MISSING", "compile_exit_code": 2,
                    "compile_command": "forge build --offline --no-cache", 
                    "compile_output": "target Solidity source missing"})
        return row
    solc, closure, missing, pragmas = resolve(workspace, target)
    command = ["forge", "build", "--offline", "--no-cache"]
    if solc:
        command += ["--use", str(solc)]
    command += ["--contracts", str(target.relative_to(workspace))]
    try:
        proc = subprocess.run(command, cwd=workspace, capture_output=True, text=True, timeout=120)
        output = (proc.stdout + "\n" + proc.stderr).strip()
        code = proc.returncode
    except subprocess.TimeoutExpired as exc:
        output = f"timeout after 120 seconds: {exc}"
        code = 124
    except OSError as exc:
        output = str(exc)
        code = 125
    profile = "standard"
    if code != 0 and "stack too deep" in output.lower():
        retry = [*command, "--via-ir"]
        try:
            via_ir = subprocess.run(
                retry, cwd=workspace, capture_output=True, text=True, timeout=120
            )
            retry_output = (via_ir.stdout + "\n" + via_ir.stderr).strip()
            if via_ir.returncode == 0:
                code, output, profile = via_ir.returncode, retry_output, "via-ir"
                command = retry
            else:
                output = output + "\n[via-ir retry]\n" + retry_output
        except (subprocess.TimeoutExpired, OSError) as exc:
            output = output + f"\n[via-ir retry failed] {exc}"
    row.update({
        "status": "COMPILE_OK" if code == 0 else "COMPILE_FAILED",
        "compile_exit_code": code,
        "compile_command": " ".join(command),
        "compile_output": output[-3000:],
        "source_sha256": digest(target),
        "workspace_sha256": digest(workspace),
        "compiler_resolution": {
            "compiler": str(solc) if solc else None,
            "closure_file_count": len(closure),
            "missing_imports": missing,
            "pragmas": pragmas,
            "profile": profile,
        },
    })
    if row["dataset"] in {"D_inc", "D_tra"}:
        row["exit_code"] = code
        row["output"] = output[-3000:]
    return row


def main() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    rows = manifest["records"]
    requested = set(sys.argv[1:])
    work = [
        row for row in rows
        if row.get("workspace")
        and row["status"] not in {"CATALOG_ONLY"}
        and (not requested or row.get("dataset") in requested)
    ]
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(compile_one, row.copy()): row["record_id"] for row in work}
        updated = {futures[future]: future.result() for future in as_completed(futures)}
    for index, row in enumerate(rows):
        if row["record_id"] in updated:
            rows[index] = updated[row["record_id"]]
    manifest["records"] = rows
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    from collections import Counter
    print(
        json.dumps(
            {"total": len(rows), "status": Counter(row["status"] for row in rows)},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
