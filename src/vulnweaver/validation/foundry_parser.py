"""Parser for pinned Foundry 1.3.1 `forge test -vvvvv --json` evidence."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from vulnweaver.common.schema import TraceEvent


class FoundryParseError(ValueError):
    pass


@dataclass(frozen=True)
class ParsedFoundryRun:
    suite: str
    test: str
    status: str
    trace: tuple[TraceEvent, ...]
    state_diff: dict[str, Any]
    labels: dict[str, str]


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FoundryParseError(f"{context} must be an object")
    return value


def _list(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise FoundryParseError(f"{context} must be an array")
    return value


def _hex_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16) if value.startswith("0x") else int(value)
    raise FoundryParseError(f"expected integer or hex string, got {type(value).__name__}")


def _normalize_hex(value: Any) -> Any:
    if isinstance(value, str) and value.startswith("0x"):
        body = value[2:].lstrip("0")
        return "0x" + (body or "0")
    return value


class _TraceBuilder:
    def __init__(self, labels: Mapping[str, str]) -> None:
        self.labels = {str(address).lower(): str(label) for address, label in labels.items()}
        self.events: list[TraceEvent] = []
        self.before_storage: dict[str, dict[str, Any]] = {}
        self.after_storage: dict[str, dict[str, Any]] = {}

    def _name(self, address: Any) -> str | None:
        if address is None:
            return None
        normalized = str(address).lower()
        return self.labels.get(normalized, normalized)

    def _append_call(self, node: Mapping[str, Any]) -> None:
        trace = _object(node.get("trace"), "arena node trace")
        data = str(trace.get("data") or "")
        kind = str(trace.get("kind") or "CALL").lower()
        selector = data[:10].lower() if kind != "create" and len(data) >= 10 else None
        event = TraceEvent(
            event_id=f"call-{len(self.events):04d}",
            operation_id="foundry-test",
            sequence=len(self.events),
            call_depth=int(trace.get("depth", 0)),
            caller=self._name(trace.get("caller")),
            target=self._name(trace.get("address")),
            selector=selector,
            value=_hex_int(trace.get("value", 0)),
            succeeded=bool(trace.get("success", False)),
            event_type=kind,
            data={
                "kind": str(trace.get("kind") or "CALL"),
                "status": trace.get("status"),
                "raw_target": str(trace.get("address") or "").lower(),
            },
        )
        self.events.append(event)

    def _append_storage(self, node: Mapping[str, Any], step_index: int) -> None:
        trace = _object(node.get("trace"), "arena node trace")
        steps = _list(trace.get("steps", []), "trace steps")
        if step_index >= len(steps):
            raise FoundryParseError("trace ordering references a missing step")
        step = _object(steps[step_index], "trace step")
        change_value = step.get("storage_change")
        if change_value is None:
            return
        change = _object(change_value, "storage change")
        target = self._name(trace.get("address")) or "<unknown>"
        key = str(change.get("key"))
        before = _normalize_hex(change.get("had_value"))
        after = _normalize_hex(change.get("value"))
        self.before_storage.setdefault(target, {}).setdefault(key, before)
        self.after_storage.setdefault(target, {})[key] = after
        self.events.append(
            TraceEvent(
                event_id=f"storage-{len(self.events):04d}",
                operation_id="foundry-test",
                sequence=len(self.events),
                call_depth=int(trace.get("depth", 0)),
                caller=self._name(trace.get("caller")),
                target=target,
                selector=None,
                succeeded=True,
                event_type="storage_write",
                data={
                    "storage": {
                        "key": key,
                        "before": before,
                        "after": after,
                        "reason": change.get("reason"),
                    }
                },
            )
        )

    def walk_arena(self, arena_value: Any) -> None:
        arena = _list(arena_value, "trace arena")
        nodes: dict[int, Mapping[str, Any]] = {}
        for raw_node in arena:
            node = _object(raw_node, "arena node")
            index = int(node.get("idx", -1))
            if index < 0 or index in nodes:
                raise FoundryParseError("trace arena has invalid or duplicate node index")
            nodes[index] = node
        roots = [node for node in nodes.values() if node.get("parent") is None]
        if len(roots) != 1:
            raise FoundryParseError("execution trace must have exactly one root")

        visited: set[int] = set()

        def walk(node: Mapping[str, Any]) -> None:
            index = int(node["idx"])
            if index in visited:
                raise FoundryParseError("trace arena contains a cycle")
            visited.add(index)
            self._append_call(node)
            ordering = _list(node.get("ordering", []), "trace ordering")
            for raw_order in ordering:
                order = _object(raw_order, "trace ordering item")
                if "Step" in order:
                    self._append_storage(node, int(order["Step"]))
                elif "Call" in order:
                    children = _list(node.get("children", []), "trace child list")
                    child_offset = int(order["Call"])
                    if child_offset < 0 or child_offset >= len(children):
                        raise FoundryParseError(
                            "trace ordering references a missing child offset"
                        )
                    child_index = int(children[child_offset])
                    if child_index not in nodes:
                        raise FoundryParseError("trace ordering references a missing child call")
                    walk(nodes[child_index])
                elif "Log" in order:
                    # Event/asset-flow decoding is handled separately from call/storage data.
                    continue
                else:
                    raise FoundryParseError("unknown trace ordering item")

        walk(roots[0])
        if visited != set(nodes):
            raise FoundryParseError("trace arena contains unreachable nodes")


def parse_foundry_json(output: str, *, expected_test: str | None = None) -> ParsedFoundryRun:
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as error:
        raise FoundryParseError(f"Foundry output is not valid JSON: {error}") from error
    suites = _object(payload, "Foundry output")
    selected: list[tuple[str, str, Mapping[str, Any]]] = []
    for suite_name, raw_suite in suites.items():
        suite = _object(raw_suite, f"suite {suite_name}")
        results = _object(suite.get("test_results"), f"suite {suite_name} test_results")
        for test_name, raw_test in results.items():
            if expected_test is None or test_name == expected_test or (
                test_name.removesuffix("()") == expected_test.removesuffix("()")
            ):
                selected.append((str(suite_name), str(test_name), _object(raw_test, "test")))
    if len(selected) != 1:
        raise FoundryParseError(f"expected exactly one test result, found {len(selected)}")

    suite_name, test_name, test = selected[0]
    labels_value = _object(test.get("labeled_addresses", {}), "labeled_addresses")
    labels = {str(address).lower(): str(label) for address, label in labels_value.items()}
    builder = _TraceBuilder(labels)
    traces = _list(test.get("traces", []), "test traces")
    execution_count = 0
    for raw_phase in traces:
        phase = _list(raw_phase, "trace phase")
        if len(phase) != 2:
            raise FoundryParseError("trace phase must have name and body")
        if phase[0] != "Execution":
            continue
        body = _object(phase[1], "execution phase")
        builder.walk_arena(body.get("arena"))
        execution_count += 1
    if execution_count != 1:
        raise FoundryParseError(f"expected one Execution phase, found {execution_count}")

    return ParsedFoundryRun(
        suite=suite_name,
        test=test_name,
        status=str(test.get("status")),
        trace=tuple(builder.events),
        state_diff={
            "before": {"storage": builder.before_storage},
            "after": {"storage": builder.after_storage},
        },
        labels=labels,
    )
