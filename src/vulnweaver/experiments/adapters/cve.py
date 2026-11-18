"""Build a versioned CVE catalog from official CVEProject records."""

from __future__ import annotations

import csv
import json
import subprocess
from pathlib import Path
from typing import Any

from vulnweaver.common.hashing import file_sha256, stable_hash, tree_sha256


def _english_description(container: dict[str, Any]) -> str:
    for item in container.get("descriptions", []):
        if isinstance(item, dict) and item.get("lang") == "en":
            return str(item.get("value", ""))
    return ""


def _paper_rows(path: Path) -> dict[str, dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return {f"CVE-{row['cve']}": row for row in csv.DictReader(handle)}


def _tag_commit(repository: Path, tag: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", f"refs/tags/{tag}^{{}}"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def build_cve_catalog(
    records_dir: Path,
    paper_table: Path,
    repositories_dir: Path,
    snapshots_dir: Path,
) -> dict[str, object]:
    """Combine official CVE JSON with the paper's declared 18-case selection."""

    paper = _paper_rows(paper_table)
    records: list[dict[str, object]] = []
    for cve_id in sorted(paper):
        path = records_dir / f"{cve_id}.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        metadata = payload.get("cveMetadata", {})
        if metadata.get("cveId") != cve_id:
            raise ValueError(f"official record ID mismatch for {cve_id}")
        cna = payload.get("containers", {}).get("cna", {})
        affected = cna.get("affected", [])
        primary = affected[0] if affected and isinstance(affected[0], dict) else {}
        references = [
            str(item["url"])
            for item in cna.get("references", [])
            if isinstance(item, dict) and item.get("url")
        ]
        row = paper[cve_id]
        repository_name = row["repository"]
        repository = repositories_dir / repository_name
        vulnerable_snapshot = snapshots_dir / repository_name / row["vulnerable"]
        fixed_snapshot = snapshots_dir / repository_name / row["fixed"]
        repository_url = (
            "https://github.com/OpenZeppelin/openzeppelin-contracts.git"
            if repository_name == "openzeppelin-contracts"
            else "https://github.com/risc0/risc0-ethereum.git"
        )
        records.append(
            {
                "cve_id": cve_id,
                "project_id": str(primary.get("product", "unknown-project")),
                "vendor": str(primary.get("vendor", "unknown-vendor")),
                "attack_family": row["root_cause"],
                "affected": affected,
                "source_repository": repository_url,
                "vulnerable_version": row["vulnerable"],
                "fixed_version": row["fixed"],
                "vulnerable_commit": _tag_commit(repository, row["vulnerable"]),
                "fixed_commit": _tag_commit(repository, row["fixed"]),
                "vulnerable_snapshot": vulnerable_snapshot.relative_to(
                    snapshots_dir.parent.parent
                ).as_posix(),
                "fixed_snapshot": fixed_snapshot.relative_to(
                    snapshots_dir.parent.parent
                ).as_posix(),
                "vulnerable_snapshot_sha256": tree_sha256(vulnerable_snapshot),
                "fixed_snapshot_sha256": tree_sha256(fixed_snapshot),
                "description": _english_description(cna),
                "references": references,
                "source_file": path.relative_to(records_dir.parent.parent).as_posix(),
                "source_url": f"https://cveawg.mitre.org/api/cve/{cve_id}",
                "source_sha256": file_sha256(path),
                "source_serial": metadata.get("serial"),
                "source_date_updated": metadata.get("dateUpdated"),
                "vulnerable_environment": False,
                "neutralized_environment": False,
                "patched_environment": False,
                "manual_reviewed": False,
                "official_patch_replayed": False,
            }
        )
    if set(paper) != {str(item["cve_id"]) for item in records}:
        raise ValueError("paper CVE table and official records do not match")
    return {
        "schema_version": "1.0",
        "source": "CVEProject CVE Services API plus the paper's declared RQ4 table",
        "record_count": len(records),
        "records_sha256": stable_hash(records),
        "records": records,
    }


def write_cve_catalog(output: Path, catalog: dict[str, object]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n", encoding="utf-8")
