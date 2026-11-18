# 03 Policy-guided PoC construction and validation

Paper §3.4 and Algorithm 2. Frozen coordinator/specialist policies construct candidates
inside the vulnerable environment; a separate verifier then replays the same candidate
against Ev, Er, and, when available, Ep.

Implementation:

- model backends and construction coordination: `src/vulnweaver/policy_learning/`;
- fresh isolated execution and Foundry trace parsing: `src/vulnweaver/validation/`;
- setup/trigger/violation/impact predicates, prefix equivalence, and causal decision:
  `src/vulnweaver/validation/verifier.py`;
- RQ3 controls and patch inventory: `data/processed/rq3-dataset/`;
- measured outputs: `results/evaluation/`.

Current boundary: controlled Ev/Er examples pass; paper cases still require reviewed Er
interventions, fixed candidates, replay evidence, and frozen learned checkpoints.
