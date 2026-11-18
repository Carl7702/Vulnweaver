"""Execution-evidenced dependency tracing for construction trajectories."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from vulnweaver.common.schema import DependencyEdge, DependencyKind, TraceEvent


def _storage(event: TraceEvent) -> Mapping[str, Any] | None:
    value = event.data.get("storage")
    return value if isinstance(value, Mapping) else None


def _asset(event: TraceEvent) -> Mapping[str, Any] | None:
    value = event.data.get("asset")
    if isinstance(value, Mapping):
        return value
    if event.event_type in {"asset_transfer", "balance_change", "token_transfer"}:
        return event.data
    return None


class DependencyTracker:
    """Find only dependencies supported by concrete trace fields.

    The tracker never treats adjacent operations or agent claims as evidence. Every
    edge points from an observed producer operation to an observed consumer event.
    """

    def trace(self, trace: Sequence[TraceEvent]) -> tuple[DependencyEdge, ...]:
        edges: list[DependencyEdge] = []
        for index, event in enumerate(trace):
            current_storage = _storage(event)
            if current_storage is not None and event.event_type in {
                "storage_read",
                "storage_read_after_write",
            }:
                key = str(current_storage.get("key"))
                for previous in reversed(trace[:index]):
                    previous_storage = _storage(previous)
                    if (
                        previous_storage is not None
                        and previous.event_type == "storage_write"
                        and previous.target == event.target
                        and str(previous_storage.get("key")) == key
                    ):
                        edges.append(
                            DependencyEdge(
                                source_operation_id=previous.operation_id,
                                target_event_id=event.event_id,
                                kind=DependencyKind.STORAGE_READ_AFTER_WRITE,
                                evidence={
                                    "source_event_id": previous.event_id,
                                    "target": event.target,
                                    "key": key,
                                },
                            )
                        )
                        break

            result_of = event.data.get("result_of_event_id")
            if isinstance(result_of, str):
                producer = next(
                    (item for item in trace[:index] if item.event_id == result_of), None
                )
                if producer is not None:
                    edges.append(
                        DependencyEdge(
                            source_operation_id=producer.operation_id,
                            target_event_id=event.event_id,
                            kind=DependencyKind.CALL_RESULT,
                            evidence={
                                "source_event_id": producer.event_id,
                                "result_of_event_id": result_of,
                            },
                        )
                    )
            for previous in reversed(trace[:index]):
                if event.data.get("call_result_from") == previous.event_id:
                    edges.append(
                        DependencyEdge(
                            source_operation_id=previous.operation_id,
                            target_event_id=event.event_id,
                            kind=DependencyKind.CALL_RESULT,
                            evidence={"source_event_id": previous.event_id},
                        )
                    )
                    break

            current_asset = _asset(event)
            if current_asset is not None:
                current_key = self._asset_key(current_asset)
                for previous in reversed(trace[:index]):
                    previous_asset = _asset(previous)
                    if (
                        previous_asset is not None
                        and self._asset_key(previous_asset) == current_key
                    ):
                        edges.append(
                            DependencyEdge(
                                source_operation_id=previous.operation_id,
                                target_event_id=event.event_id,
                                kind=DependencyKind.ASSET_FLOW,
                                evidence={
                                    "source_event_id": previous.event_id,
                                    "asset": current_key,
                                },
                            )
                        )
                        break
        return self._deduplicate(edges)

    @staticmethod
    def _asset_key(asset: Mapping[str, Any]) -> tuple[Any, ...]:
        return (
            asset.get("token", asset.get("asset")),
            asset.get("from"),
            asset.get("to"),
            asset.get("account"),
        )

    @staticmethod
    def _deduplicate(edges: Sequence[DependencyEdge]) -> tuple[DependencyEdge, ...]:
        seen: set[tuple[str, str, DependencyKind]] = set()
        result: list[DependencyEdge] = []
        for edge in edges:
            key = (edge.source_operation_id, edge.target_event_id, edge.kind)
            if key not in seen:
                seen.add(key)
                result.append(edge)
        return tuple(result)
