"""Small, deterministic hierarchical PPO implementation for a smoke task.

The environment deliberately keeps the execution surface synthetic and local. It
models the coordinator/specialist control hand-off used by construction, while the
PPO implementation is independent of a model backend and can be overfit quickly.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import gymnasium as gym
import numpy as np
import torch
from ray.rllib.env.multi_agent_env import MultiAgentEnv
from torch import Tensor, nn
from torch.distributions import Categorical

from vulnweaver.common.schema import AgentRole

COORDINATOR_ID = "coordinator"
SPECIALIST_PREFIX = "specialist:"
ROLES: tuple[AgentRole, ...] = tuple(cast(tuple[AgentRole, ...], tuple(AgentRole)))
TASK_COUNT = len(ROLES)
COORDINATOR_ACTIONS = TASK_COUNT * TASK_COUNT
SPECIALIST_ACTIONS = 2
FEATURE_SIZE = 16


def specialist_id(role: AgentRole) -> str:
    return f"{SPECIALIST_PREFIX}{role.value}"


def _role_for_action(action: int) -> AgentRole:
    return ROLES[action % TASK_COUNT]


def _task_for_action(action: int) -> int:
    return action // TASK_COUNT


def masked_logits(logits: Tensor, action_mask: Tensor) -> Tensor:
    """Set masked action logits to a finite, numerically stable negative value."""

    if logits.shape != action_mask.shape:
        raise ValueError(f"logits/mask shape mismatch: {logits.shape} != {action_mask.shape}")
    if not torch.all(action_mask.sum(dim=-1) > 0):
        raise ValueError("an all-masked action row cannot be sampled")
    return logits.masked_fill(action_mask <= 0, torch.finfo(logits.dtype).min)


class HierarchicalConstructionEnv(MultiAgentEnv):
    """Coordinator-first environment with explicit legal-action masks.

    Every task is initially ready. A coordinator action selects a not-yet-completed
    task and its required role. The selected specialist then chooses either its real
    capability (progress) or an allowed no-op (diagnosis/repair attempt). The no-op
    is legal but costs budget, so a trained specialist can beat a random legal policy.
    """

    def __init__(self, *, max_decisions: int = 24, seed: int = 42) -> None:
        super().__init__()  # type: ignore[no-untyped-call]
        self.max_decisions = max_decisions
        self.seed_value = seed
        self._rng = random.Random(seed)
        self._agent_ids = {COORDINATOR_ID} | {specialist_id(role) for role in ROLES}
        self.action_spaces = {
            COORDINATOR_ID: gym.spaces.Discrete(COORDINATOR_ACTIONS),
            **{specialist_id(role): gym.spaces.Discrete(SPECIALIST_ACTIONS) for role in ROLES},
        }
        self.observation_spaces = {
            COORDINATOR_ID: self._observation_space(COORDINATOR_ACTIONS),
            **{
                specialist_id(role): self._observation_space(SPECIALIST_ACTIONS)
                for role in ROLES
            },
        }
        self.completed = [False] * TASK_COUNT
        self.decisions = 0
        self.phase = COORDINATOR_ID
        self.pending_task: int | None = None
        self.pending_role: AgentRole | None = None
        self.last_action = 0

    @staticmethod
    def _observation_space(action_count: int) -> gym.spaces.Dict:
        return gym.spaces.Dict(
            {
                "features": gym.spaces.Box(
                    low=-1.0, high=1.0, shape=(FEATURE_SIZE,), dtype=np.float32
                ),
                "action_mask": gym.spaces.MultiBinary(action_count),
            }
        )

    def _features(self) -> np.ndarray:
        values = [float(value) for value in self.completed]
        values.extend(
            [
                self.decisions / max(self.max_decisions, 1),
                1.0 if self.phase == COORDINATOR_ID else 0.0,
                float(self.last_action) / max(COORDINATOR_ACTIONS, SPECIALIST_ACTIONS),
                float(self.pending_task if self.pending_task is not None else -1) / TASK_COUNT,
                float(self.ROLES_INDEX if self.pending_role is not None else -1) / TASK_COUNT,
            ]
        )
        values.extend([0.0] * (FEATURE_SIZE - len(values)))
        return np.asarray(values[:FEATURE_SIZE], dtype=np.float32)

    @property
    def ROLES_INDEX(self) -> int:
        return ROLES.index(self.pending_role) if self.pending_role is not None else -1

    def _coordinator_mask(self) -> np.ndarray:
        mask = np.zeros(COORDINATOR_ACTIONS, dtype=np.int8)
        for task, done in enumerate(self.completed):
            if not done:
                role = ROLES[task]
                mask[task * TASK_COUNT + ROLES.index(role)] = 1
        return mask

    def _specialist_mask(self) -> np.ndarray:
        return np.ones(SPECIALIST_ACTIONS, dtype=np.int8)

    def _observation(self, agent: str) -> dict[str, np.ndarray]:
        if agent == COORDINATOR_ID:
            mask = self._coordinator_mask()
        else:
            mask = self._specialist_mask()
        return {"features": self._features(), "action_mask": mask}

    def reset(
        self, *, seed: int | None = None, options: dict[str, Any] | None = None
    ) -> tuple[dict[str, dict[str, np.ndarray]], dict[str, dict[str, Any]]]:
        del options
        if seed is not None:
            self.seed_value = seed
            self._rng.seed(seed)
        self.completed = [False] * TASK_COUNT
        self.decisions = 0
        self.phase = COORDINATOR_ID
        self.pending_task = None
        self.pending_role = None
        self.last_action = 0
        return {COORDINATOR_ID: self._observation(COORDINATOR_ID)}, {
            COORDINATOR_ID: {"action_mask": self._coordinator_mask().tolist()}
        }

    def step(  # type: ignore[override]
        self, action_dict: dict[str, int]
    ) -> tuple[
        dict[str, dict[str, np.ndarray]],
        dict[str, float],
        dict[str, bool],
        dict[str, bool],
        dict[str, dict[str, Any]],
    ]:
        if self.phase == COORDINATOR_ID:
            if set(action_dict) != {COORDINATOR_ID}:
                raise ValueError("coordinator phase requires exactly one coordinator action")
            action = int(action_dict[COORDINATOR_ID])
            mask = self._coordinator_mask()
            if action < 0 or action >= COORDINATOR_ACTIONS or not mask[action]:
                raise ValueError("coordinator selected an illegal masked action")
            self.pending_task = _task_for_action(action)
            self.pending_role = _role_for_action(action)
            self.last_action = action
            self.phase = specialist_id(self.pending_role)
            self.decisions += 1
            return (
                {self.phase: self._observation(self.phase)},
                {self.phase: 0.0},
                {self.phase: False, "__all__": False},
                {self.phase: False, "__all__": False},
                {self.phase: {"action_mask": self._specialist_mask().tolist()}},
            )

        specialist = self.phase
        if (
            set(action_dict) != {specialist}
            or self.pending_task is None
            or self.pending_role is None
        ):
            raise ValueError("specialist phase has an invalid active agent")
        action = int(action_dict[specialist])
        if action not in (0, 1):
            raise ValueError("specialist selected an illegal masked action")
        self.last_action = action
        self.decisions += 1
        reward = 0.0
        if action == 0:
            self.completed[self.pending_task] = True
            reward = 1.0
        else:
            reward = -0.10
        completed = all(self.completed)
        truncated = self.decisions >= self.max_decisions and not completed
        terminated = completed or truncated
        info = {
            specialist: {
                "progress": sum(self.completed),
                "correct_action": action == 0,
                "environment_error": False,
            }
        }
        if terminated:
            return (
                {},
                {specialist: reward},
                {specialist: completed, "__all__": completed},
                {specialist: truncated, "__all__": truncated},
                info,
            )
        self.phase = COORDINATOR_ID
        self.pending_task = None
        self.pending_role = None
        return (
            {COORDINATOR_ID: self._observation(COORDINATOR_ID)},
            {specialist: reward},
            {specialist: False, "__all__": False},
            {specialist: False, "__all__": False},
            info,
        )

    def legal_actions(self, agent: str | None = None) -> np.ndarray:
        selected = agent or self.phase
        if selected == COORDINATOR_ID:
            return self._coordinator_mask().copy()
        return self._specialist_mask().copy()


class MaskedActorCritic(nn.Module):
    def __init__(self, feature_size: int, action_count: int, hidden_units: int = 128) -> None:
        super().__init__()
        self.body = nn.Sequential(
            nn.Linear(feature_size, hidden_units),
            nn.Tanh(),
            nn.Linear(hidden_units, hidden_units),
            nn.Tanh(),
        )
        self.policy = nn.Linear(hidden_units, action_count)
        self.value = nn.Linear(hidden_units, 1)

    def forward(self, features: Tensor, action_mask: Tensor) -> tuple[Tensor, Tensor]:
        hidden = self.body(features)
        return masked_logits(self.policy(hidden), action_mask), self.value(hidden).squeeze(-1)


@dataclass(frozen=True)
class TrainingConfig:
    learning_rate: float = 3e-4
    discount: float = 0.99
    gae_lambda: float = 0.95
    ppo_clip: float = 0.2
    hidden_units: int = 128
    episodes_per_iteration: int = 32
    max_iterations: int = 100
    seed: int = 42
    max_decisions: int = 24


@dataclass(frozen=True)
class TrainingResult:
    iterations: int
    learned_mean_return: float
    random_mean_return: float
    coordinator_updates: int
    specialist_updates: int
    checkpoint: str | None = None


@dataclass
class _Transition:
    features: np.ndarray
    mask: np.ndarray
    action: int
    old_log_prob: float
    old_value: float
    reward: float = 0.0
    done: bool = False


def _gae(transitions: list[_Transition], gamma: float, gae_lambda: float) -> tuple[Tensor, Tensor]:
    advantages = np.zeros(len(transitions), dtype=np.float32)
    returns = np.zeros(len(transitions), dtype=np.float32)
    running = 0.0
    for index in range(len(transitions) - 1, -1, -1):
        transition = transitions[index]
        next_value = 0.0 if transition.done else transition.old_value
        delta = transition.reward + gamma * next_value - transition.old_value
        running = delta + gamma * gae_lambda * (0.0 if transition.done else running)
        advantages[index] = running
        returns[index] = advantages[index] + transition.old_value
    return torch.as_tensor(advantages), torch.as_tensor(returns)


class RandomLegalPolicy:
    def __init__(self, seed: int = 42) -> None:
        self.rng = random.Random(seed)

    def action(self, mask: np.ndarray) -> int:
        choices = np.flatnonzero(mask)
        if len(choices) == 0:
            raise ValueError("cannot sample an all-masked action vector")
        return int(self.rng.choice(choices.tolist()))


class HierarchicalPPOTrainer:
    """Two independent masked PPO policies with explicit coordinator hand-off."""

    def __init__(self, config: TrainingConfig | None = None) -> None:
        self.config = config or TrainingConfig()
        random.seed(self.config.seed)
        np.random.seed(self.config.seed)
        torch.manual_seed(self.config.seed)
        self.env = HierarchicalConstructionEnv(
            max_decisions=self.config.max_decisions, seed=self.config.seed
        )
        self.coordinator = MaskedActorCritic(
            FEATURE_SIZE, COORDINATOR_ACTIONS, self.config.hidden_units
        )
        self.specialists = {
            role: MaskedActorCritic(FEATURE_SIZE, SPECIALIST_ACTIONS, self.config.hidden_units)
            for role in ROLES
        }
        self.coordinator_optimizer = torch.optim.Adam(
            self.coordinator.parameters(), lr=self.config.learning_rate
        )
        self.specialist_optimizers = {
            role: torch.optim.Adam(network.parameters(), lr=self.config.learning_rate)
            for role, network in self.specialists.items()
        }
        self.coordinator_updates = 0
        self.specialist_updates = 0

    @staticmethod
    def _role_from_agent(agent: str) -> AgentRole:
        prefix = SPECIALIST_PREFIX
        if not agent.startswith(prefix):
            raise ValueError(f"not a specialist agent: {agent}")
        try:
            return AgentRole(agent.removeprefix(prefix))
        except ValueError as error:
            raise ValueError(f"unknown specialist agent: {agent}") from error

    def _sample(
        self, network: MaskedActorCritic, observation: dict[str, np.ndarray]
    ) -> tuple[int, float, float]:
        features = torch.as_tensor(observation["features"], dtype=torch.float32).unsqueeze(0)
        mask = torch.as_tensor(observation["action_mask"], dtype=torch.float32).unsqueeze(0)
        with torch.no_grad():
            logits, value = network(features, mask)
        distribution = Categorical(logits=logits)  # type: ignore[no-untyped-call]
        action = int(distribution.sample().item())  # type: ignore[no-untyped-call]
        return (
            action,
            float(distribution.log_prob(torch.tensor(action)).item()),  # type: ignore[no-untyped-call]
            float(value.item()),
        )

    def _update(
        self,
        network: MaskedActorCritic,
        optimizer: torch.optim.Optimizer,
        transitions: list[_Transition],
    ) -> None:
        if not transitions:
            return
        advantages, returns = _gae(
            transitions, self.config.discount, self.config.gae_lambda
        )
        advantages = (advantages - advantages.mean()) / (advantages.std() + 1e-8)
        features = torch.as_tensor(np.stack([item.features for item in transitions]))
        masks = torch.as_tensor(np.stack([item.mask for item in transitions]))
        actions = torch.as_tensor([item.action for item in transitions], dtype=torch.int64)
        old_log_probs = torch.as_tensor([item.old_log_prob for item in transitions])
        logits, values = network(features, masks)
        distribution = Categorical(logits=logits)  # type: ignore[no-untyped-call]
        log_probs = distribution.log_prob(actions)  # type: ignore[no-untyped-call]
        ratio = torch.exp(log_probs - old_log_probs)
        clipped = torch.clamp(
            ratio, 1.0 - self.config.ppo_clip, 1.0 + self.config.ppo_clip
        )
        policy_loss = -torch.minimum(ratio * advantages, clipped * advantages).mean()
        value_loss = 0.5 * (values - returns).pow(2).mean()
        entropy = distribution.entropy().mean()  # type: ignore[no-untyped-call]
        loss = policy_loss + value_loss * 0.5 - entropy * 0.01
        optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(network.parameters(), 0.5)
        optimizer.step()

    def run_episode(self, *, greedy: bool = False) -> tuple[float, bool]:
        observations, _ = self.env.reset(seed=self.config.seed)
        coordinator_transitions: list[_Transition] = []
        specialist_transitions: list[_Transition] = []
        total = 0.0
        coordinator_pending: _Transition | None = None
        while observations:
            if COORDINATOR_ID in observations:
                observation = observations[COORDINATOR_ID]
                if greedy:
                    features = torch.as_tensor(
                        observation["features"], dtype=torch.float32
                    ).unsqueeze(0)
                    mask = torch.as_tensor(
                        observation["action_mask"], dtype=torch.float32
                    ).unsqueeze(0)
                    with torch.no_grad():
                        logits, _ = self.coordinator(features, mask)
                    action = int(torch.argmax(logits, dim=-1).item())
                    log_prob, value = 0.0, 0.0
                else:
                    action, log_prob, value = self._sample(self.coordinator, observation)
                coordinator_pending = _Transition(
                    observation["features"], observation["action_mask"], action, log_prob, value
                )
                observations, rewards, terminated, truncated, _ = self.env.step(
                    {COORDINATOR_ID: action}
                )
                del rewards, terminated, truncated
                coordinator_transitions.append(coordinator_pending)
            else:
                agent = next(iter(observations))
                observation = observations[agent]
                if greedy:
                    role = self._role_from_agent(agent)
                    features = torch.as_tensor(
                        observation["features"], dtype=torch.float32
                    ).unsqueeze(0)
                    mask = torch.as_tensor(
                        observation["action_mask"], dtype=torch.float32
                    ).unsqueeze(0)
                    with torch.no_grad():
                        logits, _ = self.specialists[role](features, mask)
                    action = int(torch.argmax(logits, dim=-1).item())
                    log_prob, value = 0.0, 0.0
                else:
                    role = self._role_from_agent(agent)
                    action, log_prob, value = self._sample(self.specialists[role], observation)
                specialist_transition = _Transition(
                    observation["features"], observation["action_mask"], action, log_prob, value
                )
                observations, rewards, terminated, truncated, _ = self.env.step({agent: action})
                reward = float(rewards.get(agent, 0.0))
                total += reward
                specialist_transition.reward = reward
                specialist_transition.done = bool(
                    terminated.get("__all__", False) or truncated.get("__all__", False)
                )
                specialist_transitions.append(specialist_transition)
                if coordinator_pending is not None:
                    coordinator_pending.reward = reward
                    coordinator_pending.done = specialist_transition.done
        return total, all(self.env.completed)

    def train(
        self, *, iterations: int | None = None, checkpoint: Path | None = None
    ) -> TrainingResult:
        count = iterations if iterations is not None else self.config.max_iterations
        returns: list[float] = []
        for _ in range(count):
            coordinator_batch: list[_Transition] = []
            specialist_batch: dict[AgentRole, list[_Transition]] = {
                role: [] for role in ROLES
            }
            for _episode in range(self.config.episodes_per_iteration):
                self.env.reset(seed=self.config.seed + len(returns))
                observations, _ = self.env.reset(seed=self.config.seed + len(returns))
                del observations
                # Run a stochastic episode while retaining policy transitions.
                observations, _ = self.env.reset(seed=self.config.seed + len(returns))
                coordinator_pending: _Transition | None = None
                while observations:
                    if COORDINATOR_ID in observations:
                        observation = observations[COORDINATOR_ID]
                        action, log_prob, value = self._sample(self.coordinator, observation)
                        coordinator_pending = _Transition(
                            observation["features"],
                            observation["action_mask"],
                            action,
                            log_prob,
                            value,
                        )
                        observations, _, _, _, _ = self.env.step({COORDINATOR_ID: action})
                        coordinator_batch.append(coordinator_pending)
                    else:
                        agent = next(iter(observations))
                        observation = observations[agent]
                        role = self._role_from_agent(agent)
                        action, log_prob, value = self._sample(self.specialists[role], observation)
                        transition = _Transition(
                            observation["features"],
                            observation["action_mask"],
                            action,
                            log_prob,
                            value,
                        )
                        observations, rewards, terminated, truncated, _ = self.env.step(
                            {agent: action}
                        )
                        reward = float(rewards.get(agent, 0.0))
                        transition.reward = reward
                        transition.done = bool(
                            terminated.get("__all__", False) or truncated.get("__all__", False)
                        )
                        specialist_batch[role].append(transition)
                        if coordinator_pending is not None:
                            coordinator_pending.reward = reward
                            coordinator_pending.done = transition.done
                        returns.append(reward)
            self._update(self.coordinator, self.coordinator_optimizer, coordinator_batch)
            for role in ROLES:
                self._update(
                    self.specialists[role],
                    self.specialist_optimizers[role],
                    specialist_batch[role],
                )
            self.coordinator_updates += 1
            self.specialist_updates += 1
        learned = self.evaluate(episodes=max(8, self.config.episodes_per_iteration // 2))
        random_return = self.evaluate_random(
            episodes=max(8, self.config.episodes_per_iteration // 2)
        )
        checkpoint_path: str | None = None
        if checkpoint is not None:
            self.save(checkpoint)
            checkpoint_path = str(checkpoint)
        return TrainingResult(
            iterations=count,
            learned_mean_return=learned,
            random_mean_return=random_return,
            coordinator_updates=self.coordinator_updates,
            specialist_updates=self.specialist_updates,
            checkpoint=checkpoint_path,
        )

    def evaluate(self, *, episodes: int = 16) -> float:
        values = [self.run_episode(greedy=True)[0] for _ in range(episodes)]
        return float(sum(values) / max(len(values), 1))

    def evaluate_random(self, *, episodes: int = 16) -> float:
        policy = RandomLegalPolicy(self.config.seed)
        values: list[float] = []
        for _ in range(episodes):
            observations, _ = self.env.reset(seed=self.config.seed)
            total = 0.0
            while observations:
                agent = next(iter(observations))
                action = policy.action(observations[agent]["action_mask"])
                observations, rewards, _, _, _ = self.env.step({agent: action})
                total += sum(rewards.values())
            values.append(total)
        return float(sum(values) / max(len(values), 1))

    def greedy_actions(self) -> list[int]:
        observations, _ = self.env.reset(seed=self.config.seed)
        actions: list[int] = []
        while observations:
            agent = next(iter(observations))
            observation = observations[agent]
            network = (
                self.coordinator
                if agent == COORDINATOR_ID
                else self.specialists[self._role_from_agent(agent)]
            )
            features = torch.as_tensor(observation["features"], dtype=torch.float32).unsqueeze(0)
            mask = torch.as_tensor(observation["action_mask"], dtype=torch.float32).unsqueeze(0)
            with torch.no_grad():
                logits, _ = network(features, mask)
            action = int(torch.argmax(logits, dim=-1).item())
            actions.append(action)
            observations, _, _, _, _ = self.env.step({agent: action})
        return actions

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(
            {
                "config": self.config.__dict__,
                "coordinator": self.coordinator.state_dict(),
                "specialists": {
                    role.value: network.state_dict()
                    for role, network in self.specialists.items()
                },
                "coordinator_optimizer": self.coordinator_optimizer.state_dict(),
                "specialist_optimizers": {
                    role.value: optimizer.state_dict()
                    for role, optimizer in self.specialist_optimizers.items()
                },
                "coordinator_updates": self.coordinator_updates,
                "specialist_updates": self.specialist_updates,
            },
            path,
        )

    @classmethod
    def load(cls, path: Path) -> HierarchicalPPOTrainer:
        payload = torch.load(path, map_location="cpu", weights_only=False)
        config = TrainingConfig(**payload["config"])
        trainer = cls(config)
        trainer.coordinator.load_state_dict(payload["coordinator"])
        for role, network in trainer.specialists.items():
            network.load_state_dict(payload["specialists"][role.value])
        trainer.coordinator_optimizer.load_state_dict(payload["coordinator_optimizer"])
        for role, optimizer in trainer.specialist_optimizers.items():
            optimizer.load_state_dict(payload["specialist_optimizers"][role.value])
        trainer.coordinator_updates = int(payload["coordinator_updates"])
        trainer.specialist_updates = int(payload["specialist_updates"])
        return trainer


def write_training_result(path: Path, result: TrainingResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.__dict__, indent=2, sort_keys=True) + "\n", encoding="utf-8")
