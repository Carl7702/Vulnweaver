# 02 Hierarchical coordination policy learning

Paper §3.3 and Equations (1)-(10). This stage contains coordinator/specialist action
masking, six role policies, execution-dependency tracing, exploit-progress potentials,
dependency-weighted delayed reward redistribution, assignment-level return propagation,
and masked PPO.

Implementation:

- policies, masks, PPO, and checkpoints: `src/vulnweaver/policy_learning/training.py`;
- specialist coordination: `src/vulnweaver/policy_learning/coordination.py`;
- storage, call-result, and asset-flow edges:
  `src/vulnweaver/policy_learning/dependency_tracing.py`;
- Equations (3)-(8), including reward conservation:
  `src/vulnweaver/policy_learning/rewards.py`.

Current boundary: the equations are executable and tested, while the default trainer is
still a synthetic smoke environment. Paper-scale Qwen/vLLM trajectories and five-seed
training remain to be run after executable case admission.
