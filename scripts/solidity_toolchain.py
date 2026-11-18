"""Resolve a Solidity compiler from the transitive imports of one target.

The imported repositories contain many unrelated Solidity versions.  Selecting a
compiler from the first pragma (or from the whole repository) is therefore
incorrect.  This module walks only the target's import closure and chooses the
newest locally installed compiler accepted by every file in that closure.
"""

from __future__ import annotations

import re
from pathlib import Path

_IMPORT = re.compile(r"\bimport\s+(?:[^\"']+\s+from\s+)?[\"']([^\"']+)[\"']")
_PRAGMA = re.compile(r"\bpragma\s+solidity\s+([^;]+);")
_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def version(path: Path) -> tuple[int, int, int]:
    return tuple(int(x) for x in path.parent.name.split("."))  # type: ignore[return-value]


def installed_compilers() -> list[Path]:
    paths = list((Path.home() / "Library/Application Support/svm").glob("*/solc-*"))
    paths += list((Path.home() / ".svm").glob("*/solc-*"))
    return sorted({p for p in paths if p.is_file()}, key=version)


def _bounds(
    expression: str,
) -> tuple[tuple[int, int, int] | None, bool, tuple[int, int, int] | None, bool]:
    """Return lower/upper bounds; Solidity's common ^ and ~ forms are covered."""
    expression = expression.strip()
    if "||" in expression:
        # The resolver cannot prove a disjunction through one invocation.  The
        # caller records the unresolved form and uses the broadest local match.
        expression = expression.split("||", 1)[0].strip()
    lower = upper = None
    lower_inclusive = upper_inclusive = True
    parts = expression.replace(",", " ").split()
    if len(parts) == 1 and parts[0][0:1] in "^~=" and _VERSION.search(parts[0]):
        operator, raw = parts[0][0], parts[0][1:]
        low = tuple(int(x) for x in raw.split("."))
        lower = low
        if operator == "=":
            upper = low
        elif operator == "~":
            upper = (low[0], low[1] + 1, 0)
            upper_inclusive = False
        elif low[0] > 0:
            upper = (low[0] + 1, 0, 0)
            upper_inclusive = False
        elif low[1] > 0:
            upper = (0, low[1] + 1, 0)
            upper_inclusive = False
        else:
            upper = (0, 0, low[2] + 1)
            upper_inclusive = False
        return lower, lower_inclusive, upper, upper_inclusive
    for part in parts:
        match = _VERSION.search(part)
        if not match:
            continue
        current = tuple(int(x) for x in match.groups())
        if part.startswith(">="):
            lower, lower_inclusive = current, True
        elif part.startswith(">"):
            lower, lower_inclusive = current, False
        elif part.startswith("<="):
            upper, upper_inclusive = current, True
        elif part.startswith("<"):
            upper, upper_inclusive = current, False
        elif part.startswith("="):
            lower = upper = current
            lower_inclusive = upper_inclusive = True
        elif part[0].isdigit():
            lower = upper = current
    return lower, lower_inclusive, upper, upper_inclusive


def accepts(candidate: tuple[int, int, int], expression: str) -> bool:
    low, low_inc, high, high_inc = _bounds(expression)
    if low is not None and (candidate < low or (candidate == low and not low_inc)):
        return False
    if high is not None and (candidate > high or (candidate == high and not high_inc)):
        return False
    return True


def _remappings(workspace: Path) -> list[tuple[str, Path]]:
    result: list[tuple[str, Path]] = []
    file = workspace / "remappings.txt"
    if file.exists():
        for line in file.read_text(encoding="utf-8", errors="ignore").splitlines():
            if "=" not in line or line.lstrip().startswith("#"):
                continue
            prefix, target = line.split("=", 1)
            result.append((prefix, (workspace / target).resolve()))
    return result


def _resolve_import(workspace: Path, current: Path, name: str) -> Path | None:
    if name.startswith("."):
        candidate = (current.parent / name).resolve()
        return candidate if candidate.is_file() else None
    for prefix, root in _remappings(workspace):
        if name.startswith(prefix):
            candidate = (root / name[len(prefix) :]).resolve()
            if candidate.is_file():
                return candidate
    for base in (workspace / "source", workspace / "src", workspace / "lib", workspace):
        candidates = [
            base / name,
            base / name.split("/", 1)[0] / "src" / "/".join(name.split("/")[1:]),
            base / name.split("/", 1)[0] / "contracts" / "/".join(name.split("/")[1:]),
        ]
        for candidate in candidates:
            candidate = candidate.resolve()
            if candidate.is_file():
                return candidate
    return None


def import_closure(workspace: Path, target: Path) -> tuple[list[Path], list[str]]:
    seen: set[Path] = set()
    missing: set[str] = set()
    stack = [target.resolve()]
    while stack:
        current = stack.pop()
        if current in seen or not current.is_file() or current.suffix != ".sol":
            continue
        seen.add(current)
        text = current.read_text(encoding="utf-8", errors="ignore")
        for name in _IMPORT.findall(text):
            resolved = _resolve_import(workspace, current, name)
            if resolved is None:
                missing.add(name)
            else:
                stack.append(resolved)
    return sorted(seen), sorted(missing)


def resolve(workspace: Path, target: Path) -> tuple[Path | None, list[Path], list[str], list[str]]:
    files, missing = import_closure(workspace, target)
    pragmas: list[str] = []
    for file in files:
        text = file.read_text(encoding="utf-8", errors="ignore")
        pragmas.extend(m.group(1).strip() for m in _PRAGMA.finditer(text))
    candidates = installed_compilers()
    compatible = [p for p in candidates if all(accepts(version(p), req) for req in pragmas)]
    chosen = compatible[-1] if compatible else None
    return chosen, files, missing, sorted(set(pragmas))
