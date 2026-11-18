from __future__ import annotations

from pathlib import Path

import pytest

from vulnweaver.common.hashing import stable_hash
from vulnweaver.common.schema import ObligationStatus, VerificationStatus
from vulnweaver.task_construction.example_cases import ExampleReplay, example_replays
from vulnweaver.validation.obligations import TemplateObligationEvaluator
from vulnweaver.validation.replay import ExecutionReplayRecord, ReplayExecutionBackend
from vulnweaver.validation.verifier import IndependentVerifier


@pytest.mark.parametrize("example", example_replays(), ids=lambda item: item.case.case_id)
def test_example_replay_satisfies_ev_and_causal_check(
    tmp_path: Path,
    example: ExampleReplay,
) -> None:
    evaluator = TemplateObligationEvaluator()
    vulnerable_results = evaluator.evaluate(
        example.case,
        example.vulnerable_trace,
        example.vulnerable_state_diff,
    )
    assert all(item.status is ObligationStatus.SATISFIED for item in vulnerable_results)

    er = example.case.neutralized_environment
    assert er is not None
    records = {
        example.case.vulnerable_environment.environment_id: ExecutionReplayRecord(
            environment_id=example.case.vulnerable_environment.environment_id,
            digest=stable_hash(example.case.vulnerable_environment),
            trace=example.vulnerable_trace,
            state_diff=example.vulnerable_state_diff,
        ),
        er.environment_id: ExecutionReplayRecord(
            environment_id=er.environment_id,
            digest=stable_hash(er),
            trace=example.neutralized_trace,
            state_diff=example.neutralized_state_diff,
        ),
    }
    verifier = IndependentVerifier(
        lambda: ReplayExecutionBackend(records),
        evaluator,
    )

    report = verifier.verify(tmp_path, example.case)

    assert report.status is VerificationStatus.CAUSALLY_VALIDATED


def test_all_three_example_case_hashes_are_distinct_and_stable() -> None:
    first = [stable_hash(item.case) for item in example_replays()]
    second = [stable_hash(item.case) for item in example_replays()]

    assert first == second
    assert len(set(first)) == 3
