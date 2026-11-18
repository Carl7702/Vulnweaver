# Paper-to-code map

This map follows the paper's terminology so a reviewer can move from a section or
algorithm to the relevant implementation without knowing the repository's development
history.

| Paper location | Concept | Primary code | Tests / examples | Status |
|---|---|---|---|---|
| §2.1, §3.2 | Setup, trigger, violation, impact obligations | `common/schema.py`, `validation/obligations.py` | `tests/validation/`, `examples/` | Controlled cases implemented |
| Algorithm 1 | Task formulation and admission | `task_construction/`, `experiments/datasets.py` | `tests/task_construction/`, `tests/experiments/` | Admission schema implemented; automatic obligation compilation pending |
| §3.3.1, Fig. 3 | Six specialists and shared construction state | `policy_learning/coordination.py`, `task_construction/isolation.py` | `tests/policy_learning/test_coordination.py` | Deterministic controlled workflow only |
| Eq. (1)-(2) | Hierarchical policies and action masks | `policy_learning/training.py`, `common/protocols.py` | `tests/policy_learning/test_training.py` | Synthetic environment only |
| Eq. (3)-(4) | Verified exploit-progress potential | `policy_learning/rewards.py` | `tests/policy_learning/test_rewards.py` | Normalized q/l potential and first-event gating implemented |
| Eq. (5)-(6) | Storage, call, and asset-flow dependencies | `policy_learning/dependency_tracing.py` | `tests/policy_learning/test_rewards.py` | Edge extraction implemented |
| Eq. (7)-(8) | Dependency-weighted delayed rewards | `policy_learning/rewards.py` | `tests/policy_learning/test_rewards.py` | Primitive implemented with configurable weights, conservation, penalties, and assignment returns; real trajectory integration pending |
| Eq. (9)-(10), Algorithm 3 | Joint masked PPO | `policy_learning/training.py` | `tests/policy_learning/test_training.py` | PPO smoke implementation; not trained on paper tasks |
| Algorithm 2, Eq. (11)-(12) | Vulnerable replay and root-cause intervention | `validation/` | `tests/validation/`, controlled examples | Implemented for controlled cases |
| §4 | Qwen/vLLM and Foundry integration | `policy_learning/models.py`, `containers/` | model and execution tests | Adapters exist; end-to-end paper configuration not run |
| §5, Table 1 | Dataset construction and leakage checks | `experiments/adapters/`, `experiments/datasets.py` | `tests/experiments/` | Metadata only; zero admitted paper cases |
| §5.1-§5.2, Tables 2-4 | Baselines and ablations | `experiments/runner.py` | `tests/experiments/test_runner.py` | Offline profile/replay smoke only |
| §5.3, Table 5 | Verifier reliability controls | `validation/verifier.py`, `data/processed/rq3-dataset/` | `tests/validation/` | 180 source-bound control slots and 72 patch slots present; fixed candidates and measured replays absent |
| §5.4, Table 7 | 18 held-out CVEs | catalog input accepted by `experiments/datasets.py` | none | Missing |
| Appendix B.1 | Bootstrap and paired tests | `experiments/reporting.py` | `tests/experiments/test_reporting.py` | Implemented |
| Appendix C | Prompt templates | no versioned prompt package | none | Missing |

## Runtime flow

```text
finding + pinned project
        |
        v
CaseSpec + four obligations  ->  construction view (Ev only)
        |                              |
        |                              v
        |                    coordinator + specialists
        |                              |
        |                              v
        |                         candidate PoC
        |                              |
        v                              v
verifier-controlled Ev replay -> Er replay -> optional Ep replay -> outcome
```

Construction cannot access `Er`, `Ep`, or sealed reference PoCs;
`task_construction/isolation.py` enforces
that view boundary. For current limitations and paper-result gaps, see
[reproduction-status.md](reproduction-status.md).
