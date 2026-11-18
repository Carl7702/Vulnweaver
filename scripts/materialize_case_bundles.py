#!/usr/bin/env python3
"""Materialize one traceable directory per paper dataset case.

The canonical view contains the four main paper datasets (D_tra, D_mix,
D_log, and D_inc) plus the separately reported D_cve practicality set.  Each
case links its immutable report metadata, relevant source, and isolated
workspace.  Rejected D_inc inventory rows remain in the import inventory but
are intentionally excluded from the canonical 123-case benchmark view.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
RECORDS = DATA / "processed/evaluation/records"
TRAIN_RECORDS = DATA / "processed/defihacklabs/candidates"
FORGE = DATA / "raw/FORGE-Artifacts"
DEFI = DATA / "raw/DeFiHackLabs"
CVES = DATA / "processed/cve/catalog.json"
OUT = DATA / "processed/cases"
CANONICAL = DATA / "processed/datasets"

DATASET_DIRS = {
    "D_tra": "01_training_Dtra",
    "D_mix": "02_evaluation_Dmix",
    "D_log": "03_evaluation_Dlog",
    "D_inc": "04_evaluation_Dinc",
    "D_cve": "05_practicality_Dcve",
}


def forge_index() -> dict[str, dict]:
    return {
        item["source_file"]: item
        for item in (
            json.loads(line) for line in (DATA / "processed/forge/candidates.jsonl").open()
        )
    }


def link(target: Path, source: Path) -> bool:
    if target.exists() or target.is_symlink():
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        else:
            target.unlink()
    if not source.exists():
        return False
    target.symlink_to(source.resolve(), target_is_directory=source.is_dir())
    return True


def main() -> None:
    forge = forge_index()
    cve = {item["source_file"]: item for item in json.loads(CVES.read_text())["records"]}
    environment_rows = {
        item["record_id"]: item
        for item in json.loads(
            (DATA / "processed/environments/manifest.json").read_text()
        )["records"]
    }
    inputs = [
        (path, json.loads(path.read_text())) for path in sorted(RECORDS.glob("*.json"))
    ]
    inputs.extend(
        (path, json.loads(path.read_text()))
        for path in sorted(TRAIN_RECORDS.glob("*.json"))
    )
    rows = []
    for path, record in inputs:
        dataset = record.get("dataset", "D_tra")
        record_id = record.get("record_id") or record["case_id"]
        if dataset == "D_inc" and record.get("status") != "METADATA_READY":
            continue
        case_dir = OUT / dataset / record_id
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "case.json").write_text(path.read_text(), encoding="utf-8")
        report_ok = source_ok = False
        source_kind = "none"
        if dataset in {"D_mix", "D_log"}:
            item = forge.get(record["source_file"])
            if item:
                # Sparse FORGE snapshots always contain the structured audit report
                # even when the optional original PDF artifact was not checked out.
                report_ok = link(
                    case_dir / "vulnerability-report.json",
                    FORGE / item["source_file"],
                )
                original_report = FORGE / item["report_path"]
                if original_report.is_file():
                    link(case_dir / "original-report.pdf", original_report)
                roots = [FORGE / "dataset" / value for value in item["project_paths"].values()]
                if roots:
                    source_ok = link(case_dir / "source", roots[0])
                source_kind = "forge_project"
        elif dataset in {"D_inc", "D_tra"}:
            report_ok = link(case_dir / "vulnerability-report.json", path)
            source_ok = link(case_dir / "reference-poc.sol", DEFI / record["source_file"])
            source_kind = "defihacklabs_exploit_source"
        elif dataset == "D_cve":
            item = cve.get(record["source_file"])
            if item:
                report_ok = link(
                    case_dir / "vulnerability-report.json", DATA / "raw" / item["source_file"]
                )
                source_ok = link(
                    case_dir / "vulnerable-source", DATA / "raw" / item["vulnerable_snapshot"]
                )
                link(case_dir / "patched-source", DATA / "raw" / item["fixed_snapshot"])
                source_kind = "cve_vulnerable_and_patched_snapshots"
        environment_ok = False
        environment = environment_rows.get(record_id)
        if environment and environment.get("workspace"):
            environment_ok = link(case_dir / "environment", Path(environment["workspace"]))
        bundle = {
            "case_id": record_id,
            "dataset": dataset,
            "status": record["status"],
            "source_kind": source_kind,
            "report_present": report_ok,
            "source_present": source_ok,
            "environment_present": environment_ok,
            "environment_status": environment.get("status") if environment else "CATALOG_ONLY",
            "environment_manifest": str((DATA / "processed/environments/manifest.json").resolve()),
            "reference_only": True,
        }
        (case_dir / "bundle.json").write_text(json.dumps(bundle, indent=2) + "\n")
        canonical_dir = CANONICAL / DATASET_DIRS[dataset] / "cases"
        canonical_dir.mkdir(parents=True, exist_ok=True)
        link(canonical_dir / record_id, case_dir)
        rows.append(bundle)
    manifest = {
        "schema_version": "1.0",
        "case_count": len(rows),
        "datasets": {
            dataset: sum(row["dataset"] == dataset for row in rows)
            for dataset in {row["dataset"] for row in rows}
        },
        "bundles_with_report": sum(row["report_present"] for row in rows),
        "bundles_with_source": sum(row["source_present"] for row in rows),
        "bundles_with_environment": sum(row["environment_present"] for row in rows),
        "canonical_view": str(CANONICAL.resolve()),
        "note": (
            "Bundles link immutable imported inputs; they do not expose reference PoCs "
            "to construction."
        ),
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    (CANONICAL / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
