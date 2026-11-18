#!/usr/bin/env python3
"""Run the three deterministic verifier fixtures and save machine-readable evidence."""

from __future__ import annotations

import json
from pathlib import Path

from vulnweaver.common.hashing import stable_hash
from vulnweaver.task_construction.example_cases import example_replays
from vulnweaver.validation.obligations import TemplateObligationEvaluator
from vulnweaver.validation.replay import ExecutionReplayRecord, ReplayExecutionBackend
from vulnweaver.validation.verifier import IndependentVerifier

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results/rq3-controlled-smoke.json"


def main() -> None:
    rows = []
    for example in example_replays():
        case = example.case
        records = {
            case.vulnerable_environment.environment_id: ExecutionReplayRecord(
                environment_id=case.vulnerable_environment.environment_id,
                digest=stable_hash({"case": case.case_id, "environment": "Ev"}),
                trace=example.vulnerable_trace,
                state_diff=example.vulnerable_state_diff,
            ),
            case.neutralized_environment.environment_id: ExecutionReplayRecord(
                environment_id=case.neutralized_environment.environment_id,
                digest=stable_hash({"case": case.case_id, "environment": "Er"}),
                trace=example.neutralized_trace,
                state_diff=example.neutralized_state_diff,
            ),
        }
        verifier = IndependentVerifier(
            lambda records=records: ReplayExecutionBackend(records),
            TemplateObligationEvaluator(),
        )
        report = verifier.verify(
            ROOT / "examples" / case.case_id.removeprefix("golden-") / "candidate", case
        )
        rows.append(report.model_dump(mode="json"))
    payload = {
        "schema_version": "1.0",
        "scope": "controlled-example-smoke",
        "excluded_from_paper_metrics": True,
        "reports": rows,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"reports": len(rows), "statuses": [row["status"] for row in rows]}, indent=2))


if __name__ == "__main__":
    main()
