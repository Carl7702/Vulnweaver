from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from vulnweaver.experiments.adapters.defihacklabs import (
    PINNED_COMMIT,
    DefiHackLabsRejectionReason,
    DefiHackLabsStatus,
    PinnedRevisionError,
    construction_view,
    manifest_digest,
    scan_defihacklabs,
    write_defihacklabs_import,
)


def _checkout(tmp_path: Path, files: dict[str, str]) -> tuple[Path, str]:
    root = tmp_path / "defihacklabs"
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    subprocess.run(("git", "-C", str(root), "init", "-q"), check=True)
    subprocess.run(
        ("git", "-C", str(root), "config", "user.email", "tests@example.invalid"),
        check=True,
    )
    subprocess.run(
        ("git", "-C", str(root), "config", "user.name", "VulnWeaver tests"),
        check=True,
    )
    subprocess.run(("git", "-C", str(root), "add", "."), check=True)
    subprocess.run(("git", "-C", str(root), "commit", "-qm", "fixture"), check=True)
    commit = subprocess.check_output(("git", "-C", str(root), "rev-parse", "HEAD"), text=True)
    return root, commit.strip()


def _source(*, block: str = "12_345", tx: str | None = "0x" + "a" * 64) -> str:
    tx_line = f"// Attack Tx: https://etherscan.io/tx/{tx}\n" if tx else ""
    return f"{tx_line}function test() public {{ vm.createSelectFork(\"mainnet\", {block}); }}\n"


def test_scan_extracts_metadata_and_seals_reference(tmp_path: Path) -> None:
    root, pinned = _checkout(
        tmp_path,
        {
            "README.md": "fixture\n",
            "src/test/2022-12/Example_exp.sol": _source(),
        },
    )

    candidates, manifest = scan_defihacklabs(root, pinned_commit=pinned, validation_count=0)

    assert manifest.discovered_source_count == 1
    assert manifest.metadata_ready_count == 1
    candidate = candidates[0]
    assert candidate.status is DefiHackLabsStatus.METADATA_READY
    assert candidate.fork is not None and candidate.fork.block == 12_345
    view = construction_view(candidate)
    assert view["reference_poc_sealed"] is True
    assert "source_file" not in view
    assert "attack_tx_hash" not in view
    assert manifest_digest(manifest) == manifest_digest(manifest)


def test_default_cutoff_matches_paper_and_excludes_january_2023(tmp_path: Path) -> None:
    root, pinned = _checkout(
        tmp_path,
        {
            "src/test/2022-12/December_exp.sol": _source(),
            "src/test/2023-01/January_exp.sol": _source(tx="0x" + "b" * 64),
        },
    )

    candidates, manifest = scan_defihacklabs(root, pinned_commit=pinned, validation_count=0)

    assert manifest.cutoff_month == "2022-12"
    assert manifest.discovered_source_count == 1
    assert [item.source_file for item in candidates] == ["src/test/2022-12/December_exp.sol"]


def test_scan_records_each_metadata_rejection(tmp_path: Path) -> None:
    root, pinned = _checkout(
        tmp_path,
        {
            "src/test/2022-12/NoTx_exp.sol": _source(tx=None),
            "src/test/2022-12/NoBlock_exp.sol": _source(block=""),
            "src/test/2022-12/NoFork_exp.sol": "// Attack Tx: 0x" + "b" * 64 + "\n",
        },
    )

    candidates, manifest = scan_defihacklabs(root, pinned_commit=pinned, validation_count=0)
    by_project = {item.project_id: item for item in candidates}

    assert DefiHackLabsRejectionReason.MISSING_ATTACK_TX in by_project["notx"].warnings
    assert DefiHackLabsRejectionReason.MISSING_FORK_BLOCK in by_project[
        "noblock"
    ].rejection_reasons
    assert DefiHackLabsRejectionReason.MISSING_FORK in by_project["nofork"].rejection_reasons
    assert manifest.rejection_counts == {"missing_fork": 1, "missing_fork_block": 1}
    assert manifest.warning_counts == {"missing_attack_tx": 1}


def test_wrong_pinned_commit_is_rejected(tmp_path: Path) -> None:
    root, _ = _checkout(tmp_path, {"src/test/2022-12/Example_exp.sol": _source()})

    with pytest.raises(PinnedRevisionError, match="expected pinned commit"):
        scan_defihacklabs(root, pinned_commit=PINNED_COMMIT)


def test_split_is_deterministic_and_leakage_free(tmp_path: Path) -> None:
    files = {
        f"src/test/2022-12/Project{index}_exp.sol": (
            "// oracle\n" if index % 2 else "// reentrancy\n"
        )
        + _source(tx="0x" + format(index, "064x"))
        for index in range(4)
    }
    root, pinned = _checkout(tmp_path, files)

    first, first_manifest = scan_defihacklabs(root, pinned_commit=pinned, validation_count=2)
    second, second_manifest = scan_defihacklabs(root, pinned_commit=pinned, validation_count=2)

    assert first_manifest.candidates_sha256 == second_manifest.candidates_sha256
    assert [item.split for item in first] == [item.split for item in second]
    assert first_manifest.leakage["overlap"] == {"projects": [], "attack_families": []}
    assert first_manifest.actual_validation_count == 2
    assert json.loads(first[0].model_dump_json()) == json.loads(second[0].model_dump_json())


def test_write_import_does_not_copy_solidity(tmp_path: Path) -> None:
    root, pinned = _checkout(
        tmp_path,
        {"src/test/2022-12/Example_exp.sol": _source()},
    )
    candidates, manifest = scan_defihacklabs(root, pinned_commit=pinned, validation_count=0)
    output = tmp_path / "import"
    write_defihacklabs_import(output, candidates, manifest)

    assert (output / "import-manifest.json").is_file()
    assert (output / "data-card.md").is_file()
    assert not list(output.rglob("*.sol"))


def test_reimport_removes_stale_candidate_records(tmp_path: Path) -> None:
    root, pinned = _checkout(tmp_path, {"src/test/2022-12/Example_exp.sol": _source()})
    candidates, manifest = scan_defihacklabs(root, pinned_commit=pinned, validation_count=0)
    output = tmp_path / "import"
    write_defihacklabs_import(output, candidates, manifest)
    stale = output / "candidates" / "stale.json"
    stale.write_text("{}")
    write_defihacklabs_import(output, candidates, manifest)
    assert not stale.exists()
    assert len(list((output / "candidates").glob("*.json"))) == len(candidates)
