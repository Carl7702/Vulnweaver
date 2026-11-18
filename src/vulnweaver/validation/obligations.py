"""Controlled, deterministic evaluation of the four verification obligations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from vulnweaver.common.schema import (
    CaseSpec,
    ObligationKind,
    ObligationResult,
    ObligationStatus,
    TraceEvent,
)

_MISSING = object()


def _resolve(root: Mapping[str, Any], path: str) -> Any:
    current: Any = root
    for component in path.split("."):
        if not isinstance(current, Mapping) or component not in current:
            return _MISSING
        current = current[component]
    return current


def _compare(left: Any, operator: str, right: Any) -> bool:
    if operator == "eq":
        return bool(left == right)
    if operator == "ne":
        return bool(left != right)
    if operator == "gt":
        return bool(left > right)
    if operator == "ge":
        return bool(left >= right)
    if operator == "lt":
        return bool(left < right)
    if operator == "le":
        return bool(left <= right)
    raise ValueError(f"unsupported comparison operator: {operator}")


def _numeric(value: Any) -> int | float:
    if isinstance(value, bool):
        raise TypeError("boolean is not a numeric state value")
    if isinstance(value, int | float):
        return value
    if isinstance(value, str):
        return int(value, 16) if value.startswith("0x") else float(value)
    raise TypeError(f"state value is not numeric: {type(value).__name__}")


def _match_event(event: TraceEvent, match: Mapping[str, Any]) -> bool:
    serialized = event.model_dump(mode="python")
    for key, expected in match.items():
        actual = serialized.get(key, _MISSING)
        if actual is _MISSING and key.startswith("data."):
            actual = _resolve(event.data, key.removeprefix("data."))
        if actual is _MISSING or actual != expected:
            return False
    return True


def _required_events_present(
    parameters: Mapping[str, Any],
    trace: Sequence[TraceEvent],
) -> tuple[bool, tuple[str, ...]]:
    required = tuple(str(item) for item in parameters.get("requires_trace_event_ids", ()))
    available = {event.event_id for event in trace}
    return not required or set(required) <= available, required


class TemplateObligationEvaluator:
    """Evaluate allow-listed data templates; never execute model-produced code."""

    templates = frozenset(
        {"value", "compare", "changed", "trace_call", "storage_transition", "delta"}
    )

    def evaluate(
        self,
        case: CaseSpec,
        trace: Sequence[TraceEvent],
        state_diff: Mapping[str, Any],
    ) -> Sequence[ObligationResult]:
        return tuple(
            self._evaluate_one(
                obligation.obligation_id,
                obligation.kind,
                obligation.predicate.template,
                obligation.predicate.parameters,
                trace,
                state_diff,
            )
            for obligation in case.obligations
        )

    def _evaluate_one(
        self,
        obligation_id: str,
        kind: ObligationKind,
        template: str,
        parameters: Mapping[str, Any],
        trace: Sequence[TraceEvent],
        state_diff: Mapping[str, Any],
    ) -> ObligationResult:
        if template not in self.templates:
            return ObligationResult(
                obligation_id=obligation_id,
                kind=kind,
                status=ObligationStatus.FAILED,
                message=f"predicate template is not registered: {template}",
            )
        try:
            satisfied, evidence = self._dispatch(template, parameters, trace, state_diff)
        except (KeyError, TypeError, ValueError) as error:
            return ObligationResult(
                obligation_id=obligation_id,
                kind=kind,
                status=ObligationStatus.FAILED,
                message=f"invalid controlled predicate: {error}",
            )
        return ObligationResult(
            obligation_id=obligation_id,
            kind=kind,
            status=(ObligationStatus.SATISFIED if satisfied else ObligationStatus.FAILED),
            evidence=evidence,
            message="predicate satisfied" if satisfied else "predicate not satisfied",
        )

    def _dispatch(
        self,
        template: str,
        parameters: Mapping[str, Any],
        trace: Sequence[TraceEvent],
        state_diff: Mapping[str, Any],
    ) -> tuple[bool, dict[str, Any]]:
        if template == "value":
            path = str(parameters["path"])
            actual = _resolve(state_diff, path)
            expected = parameters["expected"]
            operator = str(parameters.get("operator", "eq"))
            satisfied = actual is not _MISSING and _compare(actual, operator, expected)
            events_present, event_ids = _required_events_present(parameters, trace)
            return satisfied and events_present, {
                "path": path,
                "actual": None if actual is _MISSING else actual,
                "trace_event_ids": event_ids,
            }

        if template == "compare":
            left_path = str(parameters["left_path"])
            right_path = str(parameters["right_path"])
            left = _resolve(state_diff, left_path)
            right = _resolve(state_diff, right_path)
            operator = str(parameters.get("operator", "eq"))
            satisfied = left is not _MISSING and right is not _MISSING
            if satisfied:
                satisfied = _compare(left, operator, right)
            events_present, event_ids = _required_events_present(parameters, trace)
            return satisfied and events_present, {
                "left_path": left_path,
                "right_path": right_path,
                "left": None if left is _MISSING else left,
                "right": None if right is _MISSING else right,
                "trace_event_ids": event_ids,
            }

        if template == "changed":
            before_path = str(parameters["before_path"])
            after_path = str(parameters["after_path"])
            before = _resolve(state_diff, before_path)
            after = _resolve(state_diff, after_path)
            satisfied = before is not _MISSING and after is not _MISSING and before != after
            if "from" in parameters:
                satisfied = satisfied and before == parameters["from"]
            if "to" in parameters:
                satisfied = satisfied and after == parameters["to"]
            event_ids = tuple(str(item) for item in parameters.get("trace_event_ids", ()))
            events_present, required_ids = _required_events_present(parameters, trace)
            return satisfied and events_present, {
                "before": None if before is _MISSING else before,
                "after": None if after is _MISSING else after,
                "trace_event_ids": event_ids,
                "required_trace_event_ids": required_ids,
            }

        if template == "trace_call":
            match = parameters.get("match")
            if not isinstance(match, Mapping):
                raise TypeError("trace_call.match must be an object")
            matching_event_ids = [
                event.event_id for event in trace if _match_event(event, match)
            ]
            minimum = int(parameters.get("min_count", 1))
            return len(matching_event_ids) >= minimum, {
                "trace_event_ids": tuple(matching_event_ids),
                "match": dict(match),
                "count": len(matching_event_ids),
            }

        if template == "storage_transition":
            target = str(parameters["target"])
            key = str(parameters["key"])
            matching_event_ids = []
            for event in trace:
                storage = event.data.get("storage")
                if event.event_type != "storage_write" or not isinstance(storage, Mapping):
                    continue
                if event.target != target or storage.get("key") != key:
                    continue
                if "before" in parameters and storage.get("before") != parameters["before"]:
                    continue
                if "after" in parameters and storage.get("after") != parameters["after"]:
                    continue
                matching_event_ids.append(event.event_id)
            return bool(matching_event_ids), {
                "trace_event_ids": tuple(matching_event_ids),
                "target": target,
                "key": key,
            }

        if template == "delta":
            before_path = str(parameters["before_path"])
            after_path = str(parameters["after_path"])
            before = _resolve(state_diff, before_path)
            after = _resolve(state_diff, after_path)
            if before is _MISSING or after is _MISSING:
                return False, {"before": None, "after": None}
            delta = _numeric(after) - _numeric(before)
            operator = str(parameters.get("operator", "ge"))
            threshold = parameters["threshold"]
            satisfied = _compare(delta, operator, threshold)
            events_present, required_event_ids = _required_events_present(parameters, trace)
            satisfied = satisfied and events_present
            return satisfied, {
                "before": before,
                "after": after,
                "delta": delta,
                "trace_event_ids": required_event_ids,
            }

        raise ValueError(f"unsupported predicate template: {template}")
