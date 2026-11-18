from __future__ import annotations

import csv
import json
import subprocess
from pathlib import Path

from vulnweaver.experiments.adapters.cve import build_cve_catalog


def test_build_cve_catalog_joins_official_record_and_paper_table(tmp_path: Path) -> None:
    records = tmp_path / "raw" / "cve" / "records"
    records.mkdir(parents=True)
    (records / "CVE-2025-0001.json").write_text(
        json.dumps(
            {
                "cveMetadata": {"cveId": "CVE-2025-0001", "serial": 1},
                "containers": {
                    "cna": {
                        "affected": [{"vendor": "Vendor", "product": "Product"}],
                        "descriptions": [{"lang": "en", "value": "Description"}],
                        "references": [{"url": "https://example.invalid/advisory"}],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    table = tmp_path / "paper.csv"
    with table.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["cve", "root_cause", "repository", "vulnerable", "fixed"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "cve": "2025-0001",
                "root_cause": "Authorization",
                "repository": "openzeppelin-contracts",
                "vulnerable": "v1.1",
                "fixed": "v1.2",
            }
        )
    repository = tmp_path / "repos" / "openzeppelin-contracts"
    repository.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(["git", "-C", str(repository), "config", "user.name", "Test"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    (repository / "README").write_text("v1.1", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "add", "README"], check=True)
    subprocess.run(["git", "-C", str(repository), "commit", "-qm", "v1.1"], check=True)
    subprocess.run(["git", "-C", str(repository), "tag", "v1.1"], check=True)
    (repository / "README").write_text("v1.2", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "commit", "-qam", "v1.2"], check=True)
    subprocess.run(["git", "-C", str(repository), "tag", "v1.2"], check=True)
    snapshots = tmp_path / "raw" / "cve" / "snapshots" / "openzeppelin-contracts"
    for tag in ("v1.1", "v1.2"):
        snapshot = snapshots / tag / "contracts"
        snapshot.mkdir(parents=True)
        (snapshot / "Contract.sol").write_text(f"// {tag}", encoding="utf-8")

    catalog = build_cve_catalog(
        records,
        table,
        tmp_path / "repos",
        tmp_path / "raw" / "cve" / "snapshots",
    )

    assert catalog["record_count"] == 1
    record = catalog["records"][0]
    assert record["cve_id"] == "CVE-2025-0001"
    assert record["fixed_version"] == "v1.2"
    assert record["vulnerable_version"] == "v1.1"
    assert record["vulnerable_snapshot_sha256"]
    assert record["vulnerable_environment"] is False
