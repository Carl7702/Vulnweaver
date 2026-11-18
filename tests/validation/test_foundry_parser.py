from __future__ import annotations

import json
from typing import Any

import pytest

from vulnweaver.validation.foundry_parser import FoundryParseError, parse_foundry_json


def _trace_node(
    index: int,
    *,
    parent: int | None,
    address: str,
    data: str,
    ordering: list[dict[str, Any]] | None = None,
    steps: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "parent": parent,
        "children": [],
        "idx": index,
        "trace": {
            "depth": 0 if parent is None else 1,
            "success": True,
            "caller": "0x0000000000000000000000000000000000000001",
            "address": address,
            "kind": "CALL",
            "value": "0x0",
            "data": data,
            "status": "Stop",
            "steps": steps or [],
        },
        "logs": [],
        "ordering": ordering or [],
    }


def _output(*, unknown_order: bool = False) -> str:
    root_order = [{"Unknown": 0}] if unknown_order else [{"Call": 0}]
    storage = {
        "key": "0x0",
        "value": "0x000000000000000000000000000000000000beef",
        "had_value": "0x0000000000000000000000000000000000000001",
        "reason": "SSTORE",
    }
    arena = [
        _trace_node(
            0,
            parent=None,
            address="0x0000000000000000000000000000000000000010",
            data="0xabcdef01",
            ordering=root_order,
        ),
        _trace_node(
            1,
            parent=0,
            address="0x0000000000000000000000000000000000000020",
            data="0x13af403500000000",
            ordering=[{"Step": 0}],
            steps=[{"storage_change": storage}],
        ),
    ]
    arena[0]["children"] = [1]
    return json.dumps(
        {
            "test/Exploit.t.sol:ExploitTest": {
                "test_results": {
                    "testExploit()": {
                        "status": "Success",
                        "traces": [["Execution", {"arena": arena}]],
                        "labeled_addresses": {
                            "0x0000000000000000000000000000000000000020": "vault"
                        },
                    }
                }
            }
        }
    )


def test_parser_extracts_calls_and_storage_transitions() -> None:
    parsed = parse_foundry_json(_output(), expected_test="testExploit")

    assert parsed.status == "Success"
    assert [event.event_type for event in parsed.trace] == ["call", "call", "storage_write"]
    assert parsed.trace[1].target == "vault"
    assert parsed.trace[1].selector == "0x13af4035"
    assert parsed.state_diff["before"]["storage"]["vault"]["0x0"] == "0x1"
    assert parsed.state_diff["after"]["storage"]["vault"]["0x0"] == "0xbeef"


def test_parser_fails_closed_on_unknown_ordering_item() -> None:
    with pytest.raises(FoundryParseError, match="unknown trace ordering"):
        parse_foundry_json(_output(unknown_order=True))


def test_parser_rejects_ambiguous_test_selection() -> None:
    payload = json.loads(_output())
    suite = payload["test/Exploit.t.sol:ExploitTest"]
    suite["test_results"]["testOther()"] = suite["test_results"]["testExploit()"]

    with pytest.raises(FoundryParseError, match="exactly one"):
        parse_foundry_json(json.dumps(payload))
