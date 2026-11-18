#!/usr/bin/env python3
"""Check generated dataset inventories, provenance, and admission boundaries."""

import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "processed"


def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def records(path):
    return [read(p) for p in sorted(path.glob("*.json"))]


def check(condition, message):
    if not condition:
        raise AssertionError(message)


train_manifest = read(DATA / "defihacklabs/import-manifest.json")
all_manifest = read(DATA / "defihacklabs-all/import-manifest.json")
evaluation = read(DATA / "evaluation/import-manifest.json")
catalog_path = DATA / "cve/catalog.json"
catalog = read(catalog_path)
case_manifest = read(DATA / "cases/manifest.json")
rq3_manifest = read(DATA / "rq3-dataset/manifest.json")
train = records(DATA / "defihacklabs/candidates")
all_cases = records(DATA / "defihacklabs-all/candidates")
eval_records = records(DATA / "evaluation/records")
check(len(train) == train_manifest["discovered_source_count"] == 184, "training count")
check(Counter(x["split"] for x in train) == {"train": 160, "validation": 24}, "training splits")
for key in ("project_id", "attack_family"):
    a = {x[key] for x in train if x["split"] == "train"}
    b = {x[key] for x in train if x["split"] == "validation"}
    check(not a & b, f"training split overlap: {key}")
check(len(all_cases) == all_manifest["discovered_source_count"] == 920, "all inventory count")
check(
    Counter(x["status"] for x in all_cases) == {"METADATA_READY": 865, "REJECTED": 55},
    "all inventory statuses",
)
check(
    train_manifest["source_tree_sha256"]
    == all_manifest["source_tree_sha256"]
    == evaluation["source_inputs"]["defihacklabs_source"],
    "source tree hash mismatch",
)
check(
    digest(catalog_path) == evaluation["source_inputs"]["cve_catalog"], "CVE catalog hash mismatch"
)
check(catalog["record_count"] == len(catalog["records"]) == 18, "CVE catalog count")
check(
    case_manifest["datasets"]
    == {"D_tra": 184, "D_mix": 121, "D_log": 122, "D_inc": 123, "D_cve": 18},
    "canonical case bundle counts",
)
check(case_manifest["case_count"] == 568, "canonical case bundle total")
check(case_manifest["bundles_with_report"] == 568, "case reports")
check(case_manifest["bundles_with_source"] == 568, "case sources")
check(rq3_manifest["controls"]["source_cases_collected"] == 180, "RQ3 controls")
check(
    rq3_manifest["controls"]["by_category"]
    == {
        "positive_valid_causal": 90,
        "negative_trigger_only": 30,
        "negative_unrelated_impact": 30,
        "negative_persistent_impact": 30,
    },
    "RQ3 control categories",
)
check(rq3_manifest["official_patch_comparisons"]["target"] == 72, "RQ3 patch slots")
for dataset, summary in evaluation["dataset_summaries"].items():
    subset = [r for r in eval_records if r["dataset"] == dataset]
    counts = Counter(r["status"] for r in subset)
    check(len(subset) == summary["discovered_count"], f"{dataset} discovered count")
    for status, field in [
        ("CANDIDATE", "candidate_count"),
        ("METADATA_READY", "metadata_ready_count"),
        ("READY", "ready_count"),
        ("REJECTED", "rejected_count"),
    ]:
        check(counts[status] == summary[field], f"{dataset} {status} count")
    print(
        f"{dataset}: total={len(subset)} "
        f"metadata_ready={counts['METADATA_READY']} "
        f"ready={counts['READY']} rejected={counts['REJECTED']}"
    )
inc = [r for r in eval_records if r["dataset"] == "D_inc" and r["status"] == "METADATA_READY"]
check(len(inc) == 123, "D_inc selected count")
for key in ("project_id", "attack_family"):
    check(not ({r[key] for r in inc} & {r[key] for r in train}), f"D_inc overlap: {key}")
cves = [r for r in eval_records if r["dataset"] == "D_cve"]
check(len(cves) == 18 and all(r["status"] == "REJECTED" for r in cves), "CVE gate status")
check(
    {r["record_id"].removeprefix("cve-").upper() for r in cves}
    == {r["cve_id"] for r in catalog["records"]},
    "CVE identities",
)
for product, manifest in [("defihacklabs", train_manifest), ("defihacklabs-all", all_manifest)]:
    card = (DATA / product / "data-card.md").read_text()
    check(manifest["source_tree_sha256"] in card, f"{product} card hash")
card = (DATA / "evaluation/data-card.md").read_text()
for value in evaluation["source_inputs"].values():
    check(value in card, "evaluation card input hash")
print("D_tra: train=160 validation=24 project_overlap=0 family_overlap=0")
print("D_inc: project_overlap=0 family_overlap=0")
print("DeFiHackLabs all: total=920 metadata_ready=865 rejected=55")
print("Canonical bundles: Dtra=184 Dmix=121 Dlog=122 Dinc=123 Dcve=18 reports=568")
print("RQ3: controls=180 source-bound, patch_slots=72, measured_replays=0")
print("Provenance hashes, data cards, and CVE identities: OK")
