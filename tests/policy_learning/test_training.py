from __future__ import annotations

from pathlib import Path

import numpy as np

from vulnweaver.common.schema import AgentRole
from vulnweaver.policy_learning.training import (
    COORDINATOR_ID,
    HierarchicalConstructionEnv,
    HierarchicalPPOTrainer,
    RandomLegalPolicy,
    TrainingConfig,
)


def test_action_masks_are_deterministic_and_never_all_masked() -> None:
    first = HierarchicalConstructionEnv(seed=42)
    second = HierarchicalConstructionEnv(seed=42)
    first_obs, _ = first.reset(seed=42)
    second_obs, _ = second.reset(seed=42)
    assert np.array_equal(
        first_obs[COORDINATOR_ID]["action_mask"],
        second_obs[COORDINATOR_ID]["action_mask"],
    )
    policy = RandomLegalPolicy(seed=42)
    for _ in range(2 * len(AgentRole)):
        agent = next(iter(first_obs))
        mask = first_obs[agent]["action_mask"]
        assert mask.sum() > 0
        action = policy.action(mask)
        first_obs, _, terminated, truncated, _ = first.step({agent: action})
        if terminated.get("__all__") or truncated.get("__all__"):
            break


def test_each_specialist_has_independent_masked_policy_and_checkpoint_is_exact(
    tmp_path: Path,
) -> None:
    trainer = HierarchicalPPOTrainer(
        TrainingConfig(episodes_per_iteration=8, max_iterations=2, seed=42)
    )
    before = {
        role: next(trainer.specialists[role].parameters()).detach().clone()
        for role in AgentRole
    }
    checkpoint = tmp_path / "m4.pt"
    trainer.train(iterations=2, checkpoint=checkpoint)
    assert set(trainer.specialists) == set(AgentRole)
    assert all(
        not np.array_equal(
            before[role].numpy(),
            next(trainer.specialists[role].parameters()).detach().numpy(),
        )
        for role in AgentRole
    )
    restored = HierarchicalPPOTrainer.load(checkpoint)
    assert restored.greedy_actions() == trainer.greedy_actions()


def test_learned_policy_beats_random_legal_policy_on_smoke_task() -> None:
    trainer = HierarchicalPPOTrainer(
        TrainingConfig(episodes_per_iteration=16, max_iterations=10, seed=42)
    )
    result = trainer.train(iterations=10)
    assert result.coordinator_updates == 10
    assert result.specialist_updates == 10
    assert result.learned_mean_return > result.random_mean_return
