from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict

from vulnweaver.policy_learning.models import (
    FakeModelBackend,
    ModelMessage,
    ReplayModelBackend,
    write_replay_record,
)


class Answer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: int


def test_fake_backend_validates_structured_response() -> None:
    backend = FakeModelBackend(['{"value": 7}'])

    response = backend.complete(
        [ModelMessage(role="user", content="seven")], response_schema=Answer
    )

    assert response.structured == {"value": 7}
    assert len(response.request_hash) == 64


def test_fake_backend_rejects_bad_model_json() -> None:
    backend = FakeModelBackend(["not-json"])

    with pytest.raises(ValueError, match="schema validation"):
        backend.complete([ModelMessage(role="user", content="bad")], response_schema=Answer)


def test_replay_round_trip(tmp_path: Path) -> None:
    messages = [ModelMessage(role="user", content="replay")]
    response = FakeModelBackend(['{"value": 3}']).complete(messages, response_schema=Answer)
    replay_path = tmp_path / "replay.jsonl"
    write_replay_record(replay_path, response)

    replayed = ReplayModelBackend(replay_path).complete(messages, response_schema=Answer)

    assert replayed == response
    assert "Authorization" not in json.dumps(replayed.model_dump(mode="json"))

