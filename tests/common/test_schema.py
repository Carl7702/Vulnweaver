from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from vulnweaver.common.hashing import stable_hash
from vulnweaver.common.schema import CaseSpec
from vulnweaver.task_construction.cases import case_hash


def test_case_hash_survives_json_key_reordering(sample_case: CaseSpec) -> None:
    payload = sample_case.model_dump(mode="json", by_alias=True)
    reversed_payload = dict(reversed(list(payload.items())))

    reconstructed = CaseSpec.model_validate_json(json.dumps(reversed_payload))

    assert case_hash(sample_case) == case_hash(reconstructed)


def test_stable_hash_normalizes_nested_models(sample_case: CaseSpec) -> None:
    assert stable_hash({"case": sample_case}) == stable_hash(
        {"case": sample_case.model_dump(mode="json", by_alias=True)}
    )


def test_case_rejects_rpc_url(sample_case: CaseSpec) -> None:
    payload = sample_case.model_dump(mode="json", by_alias=True)
    payload["Ev"]["rpc_alias"] = "https://user:secret@example.invalid"

    with pytest.raises(ValidationError, match="rpc_alias"):
        CaseSpec.model_validate(payload)


def test_case_requires_all_four_obligations(sample_case: CaseSpec) -> None:
    payload = sample_case.model_dump(mode="json", by_alias=True)
    payload["obligations"] = payload["obligations"][:-1]

    with pytest.raises(ValidationError, match="exactly the four"):
        CaseSpec.model_validate(payload)


def test_case_rejects_unknown_task_dependency(sample_case: CaseSpec) -> None:
    payload = sample_case.model_dump(mode="json", by_alias=True)
    payload["tasks"][1]["prerequisites"] = ["missing"]

    with pytest.raises(ValidationError, match="unknown prerequisites"):
        CaseSpec.model_validate(payload)

