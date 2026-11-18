#!/usr/bin/env python3
"""Reconstruct paper-sized evaluation candidates from pinned FORGE metadata.

CWE labels are a transparent preliminary proxy; case review and replay are required.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from vulnweaver.common.hashing import stable_hash
from vulnweaver.experiments.datasets import (
    EvaluationDataset,
    EvaluationRecord,
    EvaluationStatus,
    _finalize,
    build_evaluation_manifest,
    evaluation_input_hashes,
    write_evaluation_import,
)

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/processed"
FORGE = DATA / "forge/candidates.jsonl"
LOGIC = {"CWE-682", "CWE-691", "CWE-435"}
LOGIC_TERMS = (
    "logic",
    "account",
    "reward",
    "price",
    "fee",
    "deposit",
    "withdraw",
    "loan",
    "liquid",
    "swap",
    "balance",
    "token",
    "share",
    "mint",
    "burn",
)
IMPLEMENTATION = {
    "CWE-284",
    "CWE-269",
    "CWE-285",
    "CWE-862",
    "CWE-863",
    "CWE-664",
    "CWE-703",
    "CWE-754",
    "CWE-693",
}


def project_key(candidate):
    for url in candidate["repository_urls"]:
        p = urlparse(url)
        parts = p.path.strip("/").split("/")
        if p.hostname and len(parts) >= 2:
            return (p.hostname.lower() + "/" + "/".join(parts[:2])).removesuffix(".git").lower()
    return "report:" + candidate["project_id"]


def labels(candidate):
    return {v.upper() for values in candidate["finding"]["categories"].values() for v in values}


def select(pool, count, projects, quotas, used_projects):
    ranked = sorted(pool, key=lambda x: stable_hash(x["candidate_id"]))
    chosen = []
    counts = Counter()
    local_projects = set()
    # First maximise distinct projects, then add cases from selected projects.
    for existing in (False, True):
        for item in ranked:
            project = project_key(item)
            severity = item["finding"]["severity"]
            if project in used_projects or (project in local_projects) != existing:
                continue
            if any(c["candidate_id"] == item["candidate_id"] for c in chosen):
                continue
            if counts[severity] >= quotas.get(severity, 0):
                continue
            if not existing and len(local_projects) >= projects:
                continue
            chosen.append(item)
            local_projects.add(project)
            counts[severity] += 1
            if len(chosen) == count:
                break
        if len(chosen) == count:
            break
    if len(chosen) != count or len(local_projects) != projects or counts != Counter(quotas):
        raise RuntimeError(
            f"selection shortfall: {len(chosen)} cases, {len(local_projects)} projects, {counts}"
        )
    return chosen


def main():
    candidates = [json.loads(line) for line in FORGE.open(encoding="utf-8")]
    candidates = [
        c
        for c in candidates
        if c["status"] == "METADATA_READY" and c["repository_urls"] and c["commits"]
    ]
    mix = select(
        [c for c in candidates if labels(c) & IMPLEMENTATION],
        121,
        104,
        {"critical": 61, "high": 60},
        set(),
    )
    used_ids = {c["candidate_id"] for c in mix}
    log = select(
        [
            c
            for c in candidates
            if c["candidate_id"] not in used_ids
            and (
                labels(c) & LOGIC
                or any(
                    term in (c["finding"]["title"] + " " + c["finding"]["description"]).lower()
                    for term in LOGIC_TERMS
                )
            )
        ],
        122,
        97,
        {"critical": 122},
        set(),
    )
    source_commit = json.loads((DATA / "forge/import-manifest.json").read_text())["source_commit"]
    records = []
    for dataset, chosen in ((EvaluationDataset.D_MIX, mix), (EvaluationDataset.D_LOG, log)):
        for c in chosen:
            family = "+".join(sorted(labels(c))) or "unknown"
            records.append(
                _finalize(
                    EvaluationRecord(
                        record_id=dataset.value.lower() + "-" + c["candidate_id"],
                        dataset=dataset,
                        source_file=c["source_file"],
                        source_sha256=c["source_sha256"],
                        source_commit=source_commit,
                        project_id=project_key(c),
                        attack_family=family,
                        status=EvaluationStatus.CANDIDATE,
                        provenance=(
                            f"FORGE finding {c['finding']['finding_id']}; "
                            f"severity {c['finding']['severity']}",
                            f"project commit: {', '.join(c['commits'])}",
                            "CWE/text heuristic preliminary classification; manual review, "
                            "environment and replay pending",
                        ),
                    )
                )
            )
    records += [
        EvaluationRecord.model_validate_json(p.read_text())
        for p in sorted((DATA / "evaluation/records").glob("*.json"))
        if json.loads(p.read_text())["dataset"] in ("D_inc", "D_cve")
    ]
    hashes = evaluation_input_hashes(
        {
            "forge_candidates": FORGE,
            "defihacklabs_source": ROOT / "data/raw/DeFiHackLabs",
            "cve_catalog": DATA / "cve/catalog.json",
        }
    )
    targets = {"D_mix": 121, "D_log": 122, "D_inc": 123, "D_cve": 18}
    manifest = build_evaluation_manifest(records, source_inputs=hashes, target_counts=targets)
    write_evaluation_import(DATA / "evaluation", records, manifest)
    print("D_mix: 121 candidates, 104 repositories, 61 critical / 60 high")
    print("D_log: 122 candidates, 97 repositories, 122 critical")
    overlap = len({project_key(c) for c in mix} & {project_key(c) for c in log})
    print(f"D_mix/D_log repository overlap: {overlap}; classification and replay pending")


if __name__ == "__main__":
    main()
