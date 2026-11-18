"""Pinned, metadata-only importer for the DeFiHackLabs exploit corpus.

The importer records source provenance and reproducibility metadata without copying
Solidity sources into VulnWeaver.  A record is metadata-ready only when its source
checkout is at the requested commit, its file is under the historical test layout,
and both a fixed fork block and an attack transaction hash are discoverable.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections import Counter, defaultdict
from collections.abc import Iterable
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field

from vulnweaver.common.hashing import file_sha256, stable_hash, tree_sha256
from vulnweaver.common.schema import DatasetSplit, StrictModel

REPOSITORY_URL = "https://github.com/SunWeb3Sec/DeFiHackLabs.git"
PINNED_COMMIT = "6bbb7b7893d3ccd2ef3d6018d991dc309ccdc281"
DEFAULT_CUTOFF_MONTH = "2022-12"
_MONTH = re.compile(r"^(?P<year>20\d{2})-(?P<month>0[1-9]|1[0-2])$")
_TX_HASH = re.compile(r"0x[a-fA-F0-9]{64}")
_FORK_LITERAL = re.compile(
    r"(?:createSelectFork|createFork|selectFork)\s*\(\s*"
    r"['\"](?P<network>[A-Za-z0-9_-]+)['\"]"
    r"(?:\s*,\s*(?P<block>[^,;)]+))?",
    re.IGNORECASE,
)
_FORK_ENV = re.compile(
    r"(?:createSelectFork|createFork|selectFork)\s*\(\s*"
    r"[^,;]*?envString\(\s*['\"](?P<network>[A-Za-z0-9_-]+)['\"]\s*\)"
    r"(?:\s*,\s*(?P<block>[^,;)]+))?",
    re.IGNORECASE,
)
_ROLL_FORK = re.compile(r"rollFork\s*\(\s*(?P<block>[^);]+)", re.IGNORECASE)
_INTEGER_DECLARATION = re.compile(
    r"uint(?:256)?(?:\s+(?:internal|public|private|constant|immutable))*\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>[^;]+);"
)


class DefiHackLabsStatus(StrEnum):
    METADATA_READY = "METADATA_READY"
    REJECTED = "REJECTED"


class DefiHackLabsRejectionReason(StrEnum):
    INVALID_CHECKOUT = "invalid_checkout"
    WRONG_COMMIT = "wrong_commit"
    INVALID_PATH = "invalid_path"
    MISSING_FORK = "missing_fork"
    MISSING_FORK_BLOCK = "missing_fork_block"
    MISSING_ATTACK_TX = "missing_attack_tx"
    DUPLICATE_PROJECT_FAMILY = "duplicate_project_family"


class ForkSpec(StrictModel):
    network: str = Field(min_length=1)
    block: int = Field(ge=0)


class DefiHackLabsCandidate(StrictModel):
    """One source PoC's reproducibility metadata and split assignment."""

    schema_version: Literal["1.0"] = "1.0"
    case_id: str = Field(pattern=r"^defihacklabs-[a-z0-9][a-z0-9._-]*$")
    source_file: str = Field(min_length=1)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    repository: str = REPOSITORY_URL
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    incident_month: str = Field(pattern=r"^20\d{2}-(0[1-9]|1[0-2])$")
    project_id: str = Field(min_length=1)
    attack_family: str = Field(min_length=1)
    fork: ForkSpec | None = None
    attack_tx_hash: str | None = Field(default=None, pattern=r"^0x[a-fA-F0-9]{64}$")
    status: DefiHackLabsStatus
    rejection_reasons: tuple[DefiHackLabsRejectionReason, ...] = ()
    warnings: tuple[DefiHackLabsRejectionReason, ...] = ()
    split: DatasetSplit = DatasetSplit.UNASSIGNED
    reference_poc_sealed: Literal[True] = True
    conversion_log: tuple[str, ...] = (
        "source Solidity was inspected for metadata only",
        "reference PoC remains outside the construction view",
    )
    candidate_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class DefiHackLabsManifest(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    adapter: Literal["defihacklabs"] = "defihacklabs"
    repository: str = REPOSITORY_URL
    source: str
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    pinned_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    cutoff_month: str = Field(pattern=r"^20\d{2}-(0[1-9]|1[0-2])$")
    source_tree_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    metadata_files_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    discovered_source_count: int = Field(ge=0)
    project_count: int = Field(ge=0)
    metadata_ready_count: int = Field(ge=0)
    rejected_count: int = Field(ge=0)
    duplicate_project_family_count: int = Field(ge=0)
    split_counts: dict[str, int]
    rejection_counts: dict[str, int]
    warning_counts: dict[str, int]
    leakage: dict[str, object]
    target_validation_count: int = Field(ge=0)
    actual_validation_count: int = Field(ge=0)
    candidates_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class PinnedRevisionError(ValueError):
    """Raised when a local checkout is not exactly the requested revision."""


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ("git", "-C", str(root), *args),
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        message = completed.stderr.strip() or completed.stdout.strip() or "git command failed"
        raise PinnedRevisionError(message)
    return completed.stdout.strip()


def verify_pinned_checkout(root: Path, *, pinned_commit: str = PINNED_COMMIT) -> str:
    """Require a detached or checked-out tree at the exact pinned commit."""

    if not root.is_dir():
        raise PinnedRevisionError(f"checkout does not exist: {root}")
    head = _git(root, "rev-parse", "HEAD").lower()
    if head != pinned_commit.lower():
        raise PinnedRevisionError(
            f"checkout is at {head}, expected pinned commit {pinned_commit}; no fallback is allowed"
        )
    _git(root, "cat-file", "-e", f"{pinned_commit}^{{commit}}")
    return head


def _month_value(value: str) -> tuple[int, int]:
    match = _MONTH.fullmatch(value)
    if match is None:
        raise ValueError(f"invalid incident month: {value}")
    return int(match.group("year")), int(match.group("month"))


def _project_id(path: Path) -> str:
    value = re.sub(r"_exp(?:[0-9]+)?$", "", path.stem, flags=re.IGNORECASE)
    value = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    value = {"uniswap-erc777": "lendfme", "cream-2": "cream"}.get(value, value)
    return value or "unknown-project"


def _case_slug(path: Path) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "-", path.stem).strip("-").lower()
    return value or "unknown-case"


_FAMILY_RULES: tuple[tuple[str, str], ...] = (
    ("reentrancy", r"reentr"),
    ("oracle", r"oracle|price.?feed"),
    ("access-control", r"access.?control|onlyowner|auth"),
    ("rounding", r"round"),
    ("overflow", r"overflow|underflow"),
    ("signature", r"signature|permit|ecrecover"),
    ("approval", r"approval|allowance"),
    ("governance", r"govern"),
    ("bridge", r"bridge"),
    ("upgrade", r"upgrade|proxy"),
    ("deflationary-token", r"deflation|fee.?on.?transfer"),
    ("price-manipulation", r"price|reserve|spot"),
    ("flash-loan", r"flash.?loan|flashloan"),
    ("accounting", r"account|balance"),
)


def infer_attack_family(text: str) -> str:
    """Return a stable, explainable family label from source comments/code."""

    labels = [label for label, pattern in _FAMILY_RULES if re.search(pattern, text, re.IGNORECASE)]
    return "+".join(labels) if labels else "other"


def _integer_value(expression: str, declarations: dict[str, str]) -> int | None:
    value = expression.strip()
    seen: set[str] = set()
    while re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        if value in seen or value not in declarations:
            return None
        seen.add(value)
        value = declarations[value].strip()
    compact = value.replace(" ", "")
    if re.fullmatch(r"[0-9_]+(?:[+-][0-9_]+)*", compact) is None:
        return None
    terms = re.findall(r"[+-]?[0-9_]+", compact)
    return sum(int(term.replace("_", "")) for term in terms)


def _network_name(value: str) -> str:
    normalized = value.lower().removesuffix("_rpc_url").removesuffix("_url")
    return {"eth": "mainnet", "ethereum": "mainnet"}.get(normalized, normalized)


def _fork_metadata(text: str) -> tuple[ForkSpec | None, bool]:
    declarations = {
        match.group("name"): match.group("value")
        for match in _INTEGER_DECLARATION.finditer(text)
    }
    matches = sorted(
        [*_FORK_LITERAL.finditer(text), *_FORK_ENV.finditer(text)],
        key=lambda match: match.start(),
    )
    if not matches:
        return None, False
    for match in matches:
        raw_block = match.group("block")
        block = _integer_value(raw_block, declarations) if raw_block is not None else None
        if block is not None:
            return (
                ForkSpec(
                    network=_network_name(match.group("network")),
                    block=block,
                ),
                True,
            )
    for match in _ROLL_FORK.finditer(text):
        block = _integer_value(match.group("block"), declarations)
        if block is not None:
            return ForkSpec(network=_network_name(matches[0].group("network")), block=block), True
    return ForkSpec(network=_network_name(matches[0].group("network")), block=0), False


def _attack_tx(text: str) -> str | None:
    labelled = re.search(
        r"(?i)(?:attack\s*(?:tx|transaction)|transaction\s*(?:hash|tx))[^\n]*"
        r"(0x[a-fA-F0-9]{64})",
        text,
    )
    if labelled is not None:
        return labelled.group(1)
    match = _TX_HASH.search(text)
    return match.group(0) if match is not None else None


def _candidate_from_source(
    root: Path,
    path: Path,
    *,
    source_commit: str,
    cutoff_month: str,
) -> DefiHackLabsCandidate:
    relative = path.relative_to(root).as_posix()
    month = path.parent.name
    reasons: list[DefiHackLabsRejectionReason] = []
    if _MONTH.fullmatch(month) is None or path.suffix.lower() != ".sol":
        reasons.append(DefiHackLabsRejectionReason.INVALID_PATH)
    text = path.read_text(encoding="utf-8", errors="replace")
    fork, has_block = _fork_metadata(text)
    if fork is None:
        reasons.append(DefiHackLabsRejectionReason.MISSING_FORK)
    elif not has_block:
        reasons.append(DefiHackLabsRejectionReason.MISSING_FORK_BLOCK)
    attack_tx = _attack_tx(text)
    warnings = (
        (DefiHackLabsRejectionReason.MISSING_ATTACK_TX,) if attack_tx is None else ()
    )
    project_id = _project_id(path)
    family = infer_attack_family(text)
    case_id = f"defihacklabs-{month}-{_case_slug(path)}"
    candidate = DefiHackLabsCandidate(
        case_id=case_id,
        source_file=relative,
        source_sha256=file_sha256(path),
        source_commit=source_commit,
        incident_month=month,
        project_id=project_id,
        attack_family=family,
        fork=fork if has_block else None,
        attack_tx_hash=attack_tx,
        status=DefiHackLabsStatus.REJECTED if reasons else DefiHackLabsStatus.METADATA_READY,
        rejection_reasons=tuple(dict.fromkeys(reasons)),
        warnings=warnings,
    )
    digest = stable_hash(candidate.model_dump(mode="json", exclude={"candidate_sha256"}))
    return candidate.model_copy(update={"candidate_sha256": digest})


def _inherit_project_environment(
    candidates: list[DefiHackLabsCandidate],
) -> list[DefiHackLabsCandidate]:
    environments: dict[tuple[str, str], DefiHackLabsCandidate] = {}
    for candidate in candidates:
        if candidate.fork is not None:
            environments.setdefault((candidate.incident_month, candidate.project_id), candidate)
    inherited: list[DefiHackLabsCandidate] = []
    for candidate in candidates:
        donor = environments.get((candidate.incident_month, candidate.project_id))
        if candidate.fork is not None or donor is None or donor.fork is None:
            inherited.append(candidate)
            continue
        reasons = tuple(
            reason
            for reason in candidate.rejection_reasons
            if reason
            not in {
                DefiHackLabsRejectionReason.MISSING_FORK,
                DefiHackLabsRejectionReason.MISSING_FORK_BLOCK,
            }
        )
        updated = candidate.model_copy(
            update={
                "fork": donor.fork,
                "attack_tx_hash": candidate.attack_tx_hash or donor.attack_tx_hash,
                "status": DefiHackLabsStatus.REJECTED
                if reasons
                else DefiHackLabsStatus.METADATA_READY,
                "rejection_reasons": reasons,
                "conversion_log": (
                    *candidate.conversion_log,
                    f"fork metadata inherited from {donor.source_file}",
                ),
            }
        )
        digest = stable_hash(updated.model_dump(mode="json", exclude={"candidate_sha256"}))
        inherited.append(updated.model_copy(update={"candidate_sha256": digest}))
    return inherited


def _component_groups(candidates: list[DefiHackLabsCandidate]) -> list[list[int]]:
    parent = list(range(len(candidates)))

    def find(value: int) -> int:
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    groups: dict[tuple[str, str], int] = {}
    for index, candidate in enumerate(candidates):
        for key in (("project", candidate.project_id), ("family", candidate.attack_family)):
            if key in groups:
                union(index, groups[key])
            else:
                groups[key] = index
    components: dict[int, list[int]] = defaultdict(list)
    for index in range(len(candidates)):
        components[find(index)].append(index)
    return sorted(components.values(), key=lambda item: min(candidates[i].case_id for i in item))


def _validation_indices(candidates: list[DefiHackLabsCandidate], target: int) -> set[int]:
    if target <= 0 or not candidates:
        return set()
    components = _component_groups(candidates)
    # Subset-sum keeps project and family groups intact while making the result as close
    # as possible to the requested validation size.  The corpus is small enough that a
    # bitset DP is both deterministic and clearer than a random split.
    states: dict[int, tuple[int, ...]] = {0: ()}
    for component_index, component in enumerate(components):
        size = len(component)
        for total in sorted(tuple(states), reverse=True):
            new_total = total + size
            if new_total not in states:
                states[new_total] = states[total] + (component_index,)
    selected_total = min(
        states,
        key=lambda total: (abs(total - target), total > target, total),
    )
    selected: set[int] = set()
    for component_index in states[selected_total]:
        selected.update(components[component_index])
    return selected


def _assign_splits(
    candidates: list[DefiHackLabsCandidate], *, validation_count: int
) -> tuple[list[DefiHackLabsCandidate], dict[str, object]]:
    selected = _validation_indices(candidates, validation_count)
    assigned: list[DefiHackLabsCandidate] = []
    for index, candidate in enumerate(candidates):
        split = DatasetSplit.VALIDATION if index in selected else DatasetSplit.TRAIN
        assigned.append(candidate.model_copy(update={"split": split}))
    train = [item for item in assigned if item.split is DatasetSplit.TRAIN]
    validation = [item for item in assigned if item.split is DatasetSplit.VALIDATION]
    train_projects = {item.project_id for item in train}
    validation_projects = {item.project_id for item in validation}
    train_families = {item.attack_family for item in train}
    validation_families = {item.attack_family for item in validation}
    overlap = {
        "projects": sorted(train_projects & validation_projects),
        "attack_families": sorted(train_families & validation_families),
    }
    if overlap["projects"] or overlap["attack_families"]:
        raise ValueError(f"split leakage detected: {overlap}")
    return assigned, {
        "train_projects": len(train_projects),
        "validation_projects": len(validation_projects),
        "train_attack_families": len(train_families),
        "validation_attack_families": len(validation_families),
        "overlap": overlap,
    }


def scan_defihacklabs(
    source: Path,
    *,
    cutoff_month: str = DEFAULT_CUTOFF_MONTH,
    validation_count: int = 24,
    pinned_commit: str = PINNED_COMMIT,
) -> tuple[list[DefiHackLabsCandidate], DefiHackLabsManifest]:
    """Build a deterministic, metadata-only candidate pool from a pinned checkout."""

    _month_value(cutoff_month)
    source_commit = verify_pinned_checkout(source, pinned_commit=pinned_commit)
    paths = sorted(source.glob("src/test/*/*.sol"))
    paths = [
        path
        for path in paths
        if _MONTH.fullmatch(path.parent.name) is not None
        and _month_value(path.parent.name) <= _month_value(cutoff_month)
    ]
    raw = _inherit_project_environment([
        _candidate_from_source(
            source,
            path,
            source_commit=source_commit,
            cutoff_month=cutoff_month,
        )
        for path in paths
    ])

    ready = [item for item in raw if item.status is DefiHackLabsStatus.METADATA_READY]
    ready, leakage = _assign_splits(ready, validation_count=validation_count)
    ready_by_path = {item.source_file: item for item in ready}
    final = [ready_by_path.get(item.source_file, item) for item in raw]
    rejection_counts = Counter(
        reason.value for item in final for reason in item.rejection_reasons
    )
    split_counts = Counter(item.split.value for item in ready)
    warning_counts = Counter(reason.value for item in final for reason in item.warnings)
    project_family_counts = Counter((item.project_id, item.attack_family) for item in final)
    metadata_files = [
        (path.relative_to(source).as_posix(), file_sha256(path))
        for path in sorted(
            (source / "README.md", source / "foundry.toml", source / "remappings.txt")
        )
        if path.is_file()
    ]
    manifest = DefiHackLabsManifest(
        source=str(source.resolve()),
        source_commit=source_commit,
        pinned_commit=pinned_commit,
        cutoff_month=cutoff_month,
        source_tree_sha256=tree_sha256(source),
        metadata_files_sha256=stable_hash(metadata_files),
        discovered_source_count=len(paths),
        project_count=len({item.project_id for item in final}),
        metadata_ready_count=len(ready),
        rejected_count=len(final) - len(ready),
        duplicate_project_family_count=sum(
            count - 1 for count in project_family_counts.values() if count > 1
        ),
        split_counts=dict(sorted(split_counts.items())),
        rejection_counts=dict(sorted(rejection_counts.items())),
        warning_counts=dict(sorted(warning_counts.items())),
        leakage=leakage,
        target_validation_count=validation_count,
        actual_validation_count=split_counts.get(DatasetSplit.VALIDATION.value, 0),
        candidates_sha256=stable_hash(
            [item.candidate_sha256 for item in final if item.candidate_sha256 is not None]
        ),
    )
    return final, manifest


def construction_view(candidate: DefiHackLabsCandidate) -> dict[str, object]:
    """Return the non-reference metadata visible to a construction policy."""

    return {
        "case_id": candidate.case_id,
        "project_id": candidate.project_id,
        "attack_family": candidate.attack_family,
        "incident_month": candidate.incident_month,
        "fork": candidate.fork.model_dump(mode="json") if candidate.fork else None,
        "reference_poc_sealed": True,
    }


def write_defihacklabs_import(
    output: Path,
    candidates: Iterable[DefiHackLabsCandidate],
    manifest: DefiHackLabsManifest,
) -> None:
    """Write metadata records and a human-readable data card, never source files."""

    output.mkdir(parents=True, exist_ok=True)
    candidate_dir = output / "candidates"
    candidate_dir.mkdir(exist_ok=True)
    materialized = list(candidates)
    for candidate in materialized:
        (candidate_dir / f"{candidate.case_id}.json").write_text(
            candidate.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
    expected_files = {candidate.case_id + ".json" for candidate in materialized}
    for stale in candidate_dir.glob("*.json"):
        if stale.name not in expected_files:
            stale.unlink()
    (output / "import-manifest.json").write_text(
        manifest.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    rejection_lines = "\n".join(
        f"- `{key}`: {value}" for key, value in manifest.rejection_counts.items()
    ) or "- none"
    split_lines = "\n".join(
        f"- `{key}`: {value}" for key, value in manifest.split_counts.items()
    ) or "- none"
    card = f"""# DeFiHackLabs metadata data card

- Repository: `{manifest.repository}`
- Pinned commit: `{manifest.pinned_commit}`
- Checkout commit observed: `{manifest.source_commit}`
- Historical cutoff: `{manifest.cutoff_month}` inclusive
- Source files discovered: `{manifest.discovered_source_count}`
- Metadata-ready candidates: `{manifest.metadata_ready_count}`
- Rejected candidates: `{manifest.rejected_count}`
- Source tree SHA-256: `{manifest.source_tree_sha256}`

## Splits

{split_lines}

The splitter keeps project identifiers and inferred attack-family identifiers disjoint
between training and validation.  The manifest contains the machine-readable overlap
check and the actual validation size.

## Rejections

{rejection_lines}

The importer reads Solidity only to extract hashes, fixed fork metadata, transaction
metadata, and an explainable attack-family label.  It writes no source code and marks
the source PoC as sealed; construction views omit `source_file`, source contents, and
the transaction hash.  Compilation and independent execution remain separate admission
gates.
"""
    (output / "data-card.md").write_text(card, encoding="utf-8")


def load_defihacklabs_manifest(path: Path) -> DefiHackLabsManifest:
    return DefiHackLabsManifest.model_validate_json(path.read_text(encoding="utf-8"))


def manifest_digest(manifest: DefiHackLabsManifest) -> str:
    return hashlib.sha256(
        json.dumps(
            manifest.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
