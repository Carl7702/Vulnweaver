from __future__ import annotations

import json
from pathlib import Path

from vulnweaver.experiments.adapters.forge import ForgeStatus, scan_forge


def test_scan_forge_counts_findings_and_checks_source(tmp_path: Path) -> None:
    results = tmp_path / "dataset" / "results"
    contract = tmp_path / "dataset" / "contracts" / "demo" / "Vault.sol"
    results.mkdir(parents=True)
    contract.parent.mkdir(parents=True)
    contract.write_text("contract Vault {}", encoding="utf-8")
    (results / "report.json").write_text(
        json.dumps(
            {
                "path": "report.pdf",
                "project_info": {
                    "url": "https://example.invalid/demo",
                    "commit_id": "abcdef1",
                    "project_path": {"demo": "contracts/demo"},
                },
                "findings": [
                    {
                        "id": 1,
                        "title": "Missing authorization",
                        "description": "Anyone can call withdraw.",
                        "severity": "high",
                        "files": ["Vault.sol"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    candidates, manifest = scan_forge(tmp_path)

    assert manifest.report_count == 1
    assert manifest.finding_count == 1
    assert manifest.metadata_ready_count == 1
    assert candidates[0].status is ForgeStatus.METADATA_READY
    assert candidates[0].source_available
