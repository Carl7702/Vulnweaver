#!/usr/bin/env python3
"""Build the paper-aligned RQ3 source, control, and patch inventory.

Every control slot is bound to a collected benchmark case, but it becomes
measured evidence only after a fixed candidate and independent Ev/Er replay are
attached. The 18 pinned CVE vulnerable/fixed snapshots are cataloged as
auxiliary patch material; they are not misrepresented as the paper's undisclosed
72-case RQ3 patch selection.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/processed"
OUT = DATA / "rq3-dataset"
ADMISSION = DATA / "admission/admission-manifest.json"
CVES = DATA / "cve/catalog.json"

CATEGORIES = (
    ("positive_valid_causal", "positive", 90, "unchanged_candidate"),
    ("negative_trigger_only", "negative", 30, "truncate_after_reported_trigger"),
    ("negative_unrelated_impact", "negative", 30, "substitute_unrelated_harm"),
    ("negative_persistent_impact", "negative", 30, "add_intervention_independent_harm"),
)


def relative(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT.resolve()))


def replace_link(target: Path, source: Path) -> bool:
    if target.exists() or target.is_symlink():
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        else:
            target.unlink()
    if not source.exists():
        return False
    target.symlink_to(source.resolve(), target_is_directory=source.is_dir())
    return True


def source_cases() -> list[dict[str, object]]:
    rows = json.loads(ADMISSION.read_text())["records"]
    eligible = [
        row
        for row in rows
        if row["dataset"] in {"D_tra", "D_mix", "D_log", "D_inc"}
        and row["admission_status"] == "COMPILE_OK"
    ]
    eligible.sort(key=lambda row: (str(row["case_id"]), str(row["dataset"])))
    return eligible


def build_controls() -> list[dict[str, object]]:
    sources = source_cases()
    target_count = sum(item[2] for item in CATEGORIES)
    if len(sources) < target_count:
        raise RuntimeError(f"need {target_count} compile-ready source cases, found {len(sources)}")
    controls: list[dict[str, object]] = []
    source_index = 0
    for category, polarity, count, construction in CATEGORIES:
        category_dir = OUT / "controls" / category
        category_dir.mkdir(parents=True, exist_ok=True)
        for index in range(1, count + 1):
            source = sources[source_index]
            source_index += 1
            control_id = f"rq3-{category}-{index:03d}"
            control_dir = category_dir / control_id
            control_dir.mkdir(parents=True, exist_ok=True)
            source_case = DATA / "cases" / str(source["dataset"]) / str(source["case_id"])
            source_linked = replace_link(control_dir / "source-case", source_case)
            row: dict[str, object] = {
                "control_id": control_id,
                "category": category,
                "polarity": polarity,
                "source_case_id": source["case_id"],
                "source_dataset": source["dataset"],
                "source_case": relative(source_case) if source_case.exists() else None,
                "source_case_linked": source_linked,
                "construction": construction,
                "candidate_poc": None,
                "ev_replay": None,
                "er_replay": None,
                "prefix_equivalent": None,
                "impact_prevented": None,
                "status": "SOURCE_CASE_COLLECTED",
                "admission_note": (
                    "The category and transformation are prescribed, but this row is not "
                    "measured until a fixed candidate and replay evidence are present."
                ),
            }
            (control_dir / "control.json").write_text(
                json.dumps(row, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            controls.append(row)
    return controls


def build_patch_pairs() -> list[dict[str, object]]:
    records = json.loads(CVES.read_text())["records"]
    rows: list[dict[str, object]] = []
    for index in range(1, 73):
        patch_id = f"rq3-official-patch-{index:03d}"
        pair_dir = OUT / "patch_pairs" / patch_id
        pair_dir.mkdir(parents=True, exist_ok=True)
        source = records[index - 1] if index <= len(records) else None
        if source:
            vulnerable = ROOT / "data/raw" / source["vulnerable_snapshot"]
            patched = ROOT / "data/raw" / source["fixed_snapshot"]
            vulnerable_present = replace_link(pair_dir / "vulnerable-contracts", vulnerable)
            patch_present = replace_link(pair_dir / "official-patch", patched)
            row: dict[str, object] = {
                "patch_id": patch_id,
                "case_id": source["cve_id"].lower(),
                "project_id": source["project_id"],
                "source_scope": "auxiliary_Dcve_snapshot_not_original_RQ3_selection",
                "vulnerable_snapshot": source["vulnerable_snapshot"],
                "vulnerable_sha256": source["vulnerable_snapshot_sha256"],
                "official_patch": source["fixed_snapshot"],
                "official_patch_sha256": source["fixed_snapshot_sha256"],
                "sources_present": vulnerable_present and patch_present,
                "candidate_poc": None,
                "er_decision": None,
                "ep_decision": None,
                "agreement": None,
                "status": "PATCH_SOURCES_COLLECTED_REPLAY_PENDING",
            }
        else:
            row = {
                "patch_id": patch_id,
                "case_id": None,
                "source_scope": "original_RQ3_selection_required",
                "sources_present": False,
                "candidate_poc": None,
                "er_decision": None,
                "ep_decision": None,
                "agreement": None,
                "status": "PENDING_COLLECTION",
            }
        (pair_dir / "pair.json").write_text(
            json.dumps(row, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        rows.append(row)
    return rows


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    controls = build_controls()
    patches = build_patch_pairs()
    (OUT / "controls.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in controls),
        encoding="utf-8",
    )
    (OUT / "official-patches.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in patches),
        encoding="utf-8",
    )
    manifest = {
        "schema_version": "2.0",
        "paper_section": "5.3 Independent Validation (RQ3)",
        "controls": {
            "target": 180,
            "source_cases_collected": len(controls),
            "measured_replays": sum(row["status"] == "REPLAY_VERIFIED" for row in controls),
            "by_category": {
                category: sum(row["category"] == category for row in controls)
                for category, _, _, _ in CATEGORIES
            },
        },
        "official_patch_comparisons": {
            "target": 72,
            "pinned_auxiliary_pairs": sum(bool(row["sources_present"]) for row in patches),
            "original_rq3_pairs_collected": 0,
            "measured_replays": 0,
        },
        "metric_policy": "No paper percentage is treated as locally reproduced evidence.",
    }
    (OUT / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
