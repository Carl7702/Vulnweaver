#!/usr/bin/env python3
"""Create the paper-aligned dataset, method, and result layout.

The layout is metadata-only: it records source references and admission state without
inventing RQ3 controls or replay evidence that are not present in the pinned inputs.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
EVAL = DATA / "processed/evaluation/records"
FORGE = DATA / "processed/forge/candidates.jsonl"
CVES = DATA / "processed/cve/catalog.json"
RQ3 = DATA / "processed/rq3-dataset"


def mkdirs() -> None:
    for path in [
        RQ3 / "controls/positive_valid_causal",
        RQ3 / "controls/negative_trigger_only",
        RQ3 / "controls/negative_unrelated_impact",
        RQ3 / "controls/negative_persistent_impact",
        RQ3 / "patch_pairs/vulnerable_contracts",
        RQ3 / "patch_pairs/official_patches",
        RQ3 / "patch_pairs/replay_evidence",
        ROOT / "method/01_exploit_oriented_task_construction",
        ROOT / "method/02_hierarchical_coordination_policy_learning",
        ROOT / "method/03_policy_guided_poc_construction_validation",
        ROOT / "results/training/01_ppo_checkpoints",
        ROOT / "results/training/02_validation_curves",
        ROOT / "results/training/03_reward_ablations",
        ROOT / "results/evaluation/01_rq1_main_benchmark",
        ROOT / "results/evaluation/02_rq2_coordination_reward",
        ROOT / "results/evaluation/03_rq3_independent_validation",
        ROOT / "results/evaluation/04_rq4_cve_generalization",
        ROOT / "results/evaluation/05_baselines",
        ROOT / "results/evaluation/06_reports_tables",
    ]:
        path.mkdir(parents=True, exist_ok=True)


def load_evaluation() -> list[dict]:
    return [json.loads(path.read_text()) for path in sorted(EVAL.glob("*.json"))]


def write_case_catalog() -> None:
    rows = []
    for record in load_evaluation():
        if record["dataset"] in {"D_mix", "D_log", "D_inc", "D_cve"}:
            rows.append(
                {
                    "case_id": record["record_id"],
                    "dataset": record["dataset"],
                    "source_report": record["source_file"],
                    "source_sha256": record["source_sha256"],
                    "project_id": record["project_id"],
                    "attack_family": record["attack_family"],
                    "status": record["status"],
                    "environment_status": "PENDING_ADMISSION",
                    "vulnerable_replay": False,
                    "root_cause_replay": False,
                    "patched_replay": bool(record.get("official_patch_replayed", False)),
                    "note": "Source and report are referenced by immutable input metadata.",
                }
            )
    (RQ3 / "case-catalog.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8"
    )


def write_rq3_catalog() -> None:
    controls = []
    categories = [
        ("positive_valid_causal", 90, "positive"),
        ("negative_trigger_only", 30, "negative"),
        ("negative_unrelated_impact", 30, "negative"),
        ("negative_persistent_impact", 30, "negative"),
    ]
    for category, count, label in categories:
        for index in range(1, count + 1):
            controls.append(
                {
                    "control_id": f"rq3-{category}-{index:03d}",
                    "category": category,
                    "label": label,
                    "expected_ev": category != "negative_trigger_only",
                    "expected_er": category == "positive_valid_causal",
                    "status": "SOURCE_REQUIRED",
                    "source_case": None,
                    "candidate_poc": None,
                    "replay_evidence": None,
                }
            )
    (RQ3 / "controls/catalog.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in controls), encoding="utf-8"
    )
    cve_catalog = json.loads(CVES.read_text())["records"]
    patches = []
    for item in cve_catalog:
        patches.append(
            {
                "case_id": item["cve_id"].lower(),
                "project_id": item["project_id"],
                "vulnerable_snapshot": item.get("vulnerable_snapshot"),
                "vulnerable_snapshot_sha256": item.get("vulnerable_snapshot_sha256"),
                "official_patch": item.get("fixed_snapshot"),
                "official_patch_sha256": item.get("fixed_snapshot_sha256"),
                "patch_replay_status": "PENDING_REPLAY",
                "source_status": "SNAPSHOT_PRESENT",
            }
        )
    (RQ3 / "patch_pairs/catalog.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in patches), encoding="utf-8"
    )
    summary = {
        "schema_version": "1.0",
        "paper_section": "§5.3 Independent Validation",
        "controls_target": 180,
        "controls_cataloged": len(controls),
        "controls_with_source": 0,
        "official_patch_pairs_target": 72,
        "official_patch_snapshots_cataloged": len(patches),
        "official_patch_replay_evidence": 0,
        "status": "METADATA_LAYOUT_READY",
        "note": (
            "The 180 controls and 72 replay pairs require case-level PoCs/evidence; "
            "no results are fabricated."
        ),
    }
    (RQ3 / "manifest.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")


def write_readmes() -> None:
    method = {
        "01_exploit_oriented_task_construction": (
            "Paper §3.2. Parses findings, target sources, environments, obligations, "
            "and feasible operations."
        ),
        "02_hierarchical_coordination_policy_learning": (
            "Paper §3.3. Coordinator/specialist action masking, PPO, dependency-aware "
            "reward attribution."
        ),
        "03_policy_guided_poc_construction_validation": (
            "Paper §3.4. Frozen policies construct candidates; independent Ev/Er/Ep "
            "replay produces evidence."
        ),
    }
    for name, description in method.items():
        path = ROOT / "method" / name / "README.md"
        path.write_text(
            f"# {name}\n\n{description}\n\n"
            "Implementation mapping: `src/vulnweaver/`; generated artifacts: `results/`.\n",
            encoding="utf-8",
        )
    (RQ3 / "README.md").write_text(
        "# rq3-dataset\n\n"
        "Paper §5.3 validation layout. `controls/` contains the 180 required labeled slots; "
        "`patch_pairs/` catalogs the available vulnerable/fixed snapshots and replay slots. "
        "A `SOURCE_REQUIRED` or `PENDING_REPLAY` row is not experimental evidence.\n",
        encoding="utf-8",
    )


def main() -> None:
    mkdirs()
    # Keep the canonical materializers authoritative.  The older helpers above
    # are retained only to read schema-v1 snapshots and must not overwrite the
    # schema-v2 RQ3 inventory.
    from materialize_case_bundles import main as materialize_cases
    from prepare_rq3_controls import main as prepare_rq3

    materialize_cases()
    prepare_rq3()
    print(
        json.dumps(
            {
                "rq3": str(RQ3),
                "canonical_cases": str(DATA / "processed/datasets"),
                "status": "layout_ready",
            }
        )
    )


if __name__ == "__main__":
    main()
