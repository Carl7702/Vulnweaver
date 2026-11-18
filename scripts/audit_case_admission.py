#!/usr/bin/env python3
"""Audit imported cases against the paper's execution-admission gates.

This audit deliberately separates source preflight from executable validation.
``COMPILE_OK`` is evidence of a build only; it never implies Ev replay,
causal validation, or readiness for a reported experiment.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from vulnweaver.common.schema import (
    AgentRole,
    Budget,
    CaseSpec,
    DatasetSplit,
    EnvironmentKind,
    EnvironmentSpec,
    FindingSpec,
    ObligationKind,
    ObligationSpec,
    PredicateSpec,
    TaskSpec,
)

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/processed"
ENV_MANIFEST = DATA / "environments/manifest.json"
EVAL_RECORDS = DATA / "evaluation/records"
TRAIN_RECORDS = DATA / "defihacklabs/candidates"
OUT = DATA / "admission"
SPECS = OUT / "case-specs"


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def load_records() -> list[dict[str, Any]]:
    records = [json.loads(path.read_text()) for path in sorted(EVAL_RECORDS.glob("*.json"))]
    records.extend(json.loads(path.read_text()) for path in sorted(TRAIN_RECORDS.glob("*.json")))
    return records


def obligations() -> tuple[ObligationSpec, ...]:
    # These are controlled predicate templates for the task-construction draft.
    # Case-specific parameters must be reviewed before any execution claim.
    return (
        ObligationSpec(
            obligation_id="setup",
            kind=ObligationKind.SETUP,
            description="Required accounts, balances, roles, and external state exist.",
            predicate=PredicateSpec(
                template="value", parameters={"path": "setup.ready", "expected": True}
            ),
        ),
        ObligationSpec(
            obligation_id="trigger",
            kind=ObligationKind.TRIGGER,
            description="The report-bound vulnerable operation is reached.",
            predicate=PredicateSpec(
                template="trace_call", parameters={"match": {"event_type": "call"}}
            ),
        ),
        ObligationSpec(
            obligation_id="violation",
            kind=ObligationKind.VIOLATION,
            description="The reported unsafe transition is observed in execution evidence.",
            predicate=PredicateSpec(
                template="trace_call", parameters={"match": {"event_type": "violation"}}
            ),
        ),
        ObligationSpec(
            obligation_id="impact",
            kind=ObligationKind.IMPACT,
            description="The report-bound security impact is observed in state or asset evidence.",
            predicate=PredicateSpec(
                template="changed",
                parameters={"before_path": "impact.before", "after_path": "impact.after"},
            ),
        ),
    )


def tasks() -> tuple[TaskSpec, ...]:
    return (
        TaskSpec(
            task_id="prepare-state",
            description="Prepare the report-bound initial state.",
            required_role=AgentRole.STATE_PREPARATION,
            produces=("state",),
        ),
        TaskSpec(
            task_id="authorize",
            description="Satisfy caller and permission prerequisites.",
            required_role=AgentRole.AUTHORIZATION,
            prerequisites=("prepare-state",),
            produces=("authorization",),
        ),
        TaskSpec(
            task_id="route-assets",
            description="Prepare required asset flow and balances.",
            required_role=AgentRole.ASSET_FLOW,
            prerequisites=("prepare-state",),
            produces=("asset-flow",),
        ),
        TaskSpec(
            task_id="resolve-dependencies",
            description="Resolve external contract and transaction dependencies.",
            required_role=AgentRole.DEPENDENCY,
            prerequisites=("authorize", "route-assets"),
            produces=("dependencies",),
        ),
        TaskSpec(
            task_id="construct-poc",
            description="Assemble an executable candidate PoC.",
            required_role=AgentRole.POC_BUILDER,
            prerequisites=("resolve-dependencies",),
            produces=("candidate",),
        ),
        TaskSpec(
            task_id="diagnose",
            description="Diagnose compiler and execution feedback.",
            required_role=AgentRole.EXECUTION_DIAGNOSIS,
            prerequisites=("construct-poc",),
            produces=("evidence",),
        ),
    )


def split_value(record: dict[str, Any]) -> DatasetSplit:
    value = record.get("split", "unassigned")
    return (
        DatasetSplit(value)
        if value in {item.value for item in DatasetSplit}
        else DatasetSplit.UNASSIGNED
    )


def source_commit(record: dict[str, Any]) -> str:
    value = str(record.get("source_commit", "0000000"))
    return value if len(value) >= 7 else (value + "0" * 7)[:7]


def draft_case(record: dict[str, Any], env: dict[str, Any]) -> CaseSpec:
    case_id = record.get("case_id") or record.get("record_id")
    dataset = record.get("dataset", "D_tra")
    workspace = env.get("workspace") or ""
    fork = record.get("fixed_fork_block")
    if fork is None:
        fork = record.get("fork", {}).get("block", 0)
    network = record.get("fork", {}).get("network", "local")
    attack_family = record.get("attack_family") or "unknown"
    finding = FindingSpec(
        finding_id=f"{case_id}-finding",
        title=f"Imported {dataset} finding ({attack_family})",
        vulnerability_type=attack_family,
        report="Imported report metadata; case-specific manual review is required.",
        root_cause="Imported root-cause metadata; case-specific intervention is required.",
    )
    ev = EnvironmentSpec(
        environment_id=f"{case_id}-Ev",
        kind=EnvironmentKind.VULNERABLE,
        repository=workspace or f"data/processed/environments/workspaces/{case_id}",
        commit=source_commit(record),
        chain=network,
        chain_id=31337 if network == "local" else 1,
        fork_block=int(fork or 0),
        foundry_version="1.3.1",
        solc_version=str(env.get("compiler_resolution", {}).get("compiler") or "unresolved"),
        settings={"source_file": record.get("source_file"), "admission": "preflight-only"},
    )
    return CaseSpec(
        case_id=case_id,
        source=dataset,
        split=split_value(record),
        project_id=str(record.get("project_id", "unknown")),
        attack_family=attack_family,
        finding=finding,
        Ev=ev,
        obligations=obligations(),
        tasks=tasks(),
        allowed_operations={role: () for role in AgentRole},
        budget=Budget(),
        conversion_log=(
            "Generated by audit_case_admission.py from imported metadata.",
            "This draft contains no Ev replay, reset digest, Er intervention, "
            "or Ep replay evidence.",
        ),
    )


def classify(record: dict[str, Any], env: dict[str, Any] | None) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if env is None:
        return "UNRESOLVED", ["no environment manifest record"]
    status = env.get("status")
    if status in {"COMPILE_FAILED", "SOURCE_MISSING"}:
        return "ENVERROR", [status.lower(), "Foundry build did not succeed"]
    if status == "CATALOG_ONLY":
        return "UNRESOLVED", ["catalog-only record has no executable workspace"]
    if status != "COMPILE_OK":
        return "UNRESOLVED", [f"preflight status={status}"]
    fork = record.get("fixed_fork_block")
    if fork is None:
        fork = record.get("fork", {}).get("block")
    if fork is None:
        return "UNRESOLVED", ["fixed fork block is missing"]
    reasons.extend(
        [
            "compile succeeded",
            "fixed fork block is present",
            "execution replay not yet run",
            "reset digest pair not yet recorded",
            "Er root-cause intervention not yet recorded",
        ]
    )
    return "COMPILE_OK", reasons


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    SPECS.mkdir(parents=True, exist_ok=True)
    env_rows = {row["record_id"]: row for row in json.loads(ENV_MANIFEST.read_text())["records"]}
    rows: list[dict[str, Any]] = []
    for record in load_records():
        record_id = record.get("case_id") or record.get("record_id")
        env = env_rows.get(record_id)
        status, reasons = classify(record, env)
        spec_path: str | None = None
        if env and env.get("status") == "COMPILE_OK":
            try:
                spec = draft_case(record, env)
                path = SPECS / f"{record_id}.json"
                path.write_text(spec.model_dump_json(by_alias=True, indent=2) + "\n")
                spec_path = str(path.relative_to(ROOT))
            except Exception as error:  # keep one malformed record from hiding the inventory
                status = "UNRESOLVED"
                reasons.append(f"case spec generation failed: {error}")
        rows.append(
            {
                "case_id": record_id,
                "dataset": record.get("dataset", "D_tra"),
                "project_id": record.get("project_id"),
                "environment_status": env.get("status") if env else None,
                "admission_status": status,
                "reasons": reasons,
                "workspace": env.get("workspace") if env else None,
                "compile_exit_code": env.get("compile_exit_code") if env else None,
                "compiler_resolution": env.get("compiler_resolution") if env else None,
                "case_spec": spec_path,
            }
        )
    manifest = {
        "schema_version": "1.0",
        "generated_by": "scripts/audit_case_admission.py",
        "paper_gates": [
            "fixed chain and fork block",
            "Foundry build",
            "setup/trigger/violation/impact obligations",
            "two reset digests equal",
            "Ev replay evidence",
            "Er PrefixEq and reported impact disappearance",
            "optional Ep patch replay",
        ],
        "records": rows,
        "counts": {
            f"{dataset}:{status}": count
            for (dataset, status), count in Counter(
                (row["dataset"], row["admission_status"]) for row in rows
            ).items()
        },
        "records_sha256": digest(rows),
        "note": (
            "COMPILE_OK is preflight evidence only and is not an executable or "
            "validated result."
        ),
    }
    (OUT / "admission-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps({"total": len(rows), "counts": manifest["counts"]}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
