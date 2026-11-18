# Implementation status

This page records implementation status by the paper's three-stage architecture. A
component is marked **implemented** only when its code path is exercised by tests;
**smoke only** means that the interface or algorithm is tested on controlled inputs but
not on the paper dataset; **pending** means the paper experiment cannot yet be run.

| Paper component | Repository status | Evidence | Remaining work |
|---|---|---|---|
| Exploit-oriented PoC task construction (§3.2) | Smoke only | Strict `CaseSpec`, four obligations, adapters, hashes, reset checks | Convert and admit the paper cases with reviewed predicates and executable environments |
| Six specialist agents (§3.3.1) | Smoke only | Deterministic six-role controlled example | Connect specialist model calls, role observations, legal operations, and iterative repair to admitted cases |
| Prerequisite-aware action masking (§3.3.1) | Smoke only | Masked coordinator/specialist actions in the synthetic environment | Build masks from real task prerequisites, artifacts, failures, and budgets |
| Execution dependency tracing (§3.3.2) | Implemented primitive | Storage, call-result, and asset-flow edge extraction with tests | Validate coverage on real Foundry traces and version the dependency weights |
| Progress-guided reward redistribution (§3.3.2) | Implemented primitive | Normalized setup/prefix potential, first-event gating, configurable storage/call/asset weights, per-event normalized delayed attribution, penalties, assignment returns, and conservation tests | Feed real admitted-case trace edges and verified events into the trajectory/training loop |
| Joint hierarchical PPO (§3.3.3) | Smoke only | Separate coordinator and specialist networks, masks, PPO update, checkpoint round-trip | Train on admitted construction tasks; integrate delayed rewards; select checkpoints on the 24-case validation split |
| Policy-guided construction (§3.4) | Smoke only | Controlled heuristic construction and model backend adapters | Load frozen learned policies and run the full iterative construction loop on unseen findings |
| Independent validation (§3.4) | Implemented for controlled cases | Fresh backend per replay, four obligations, `Ev`/`Er`, prefix comparison, optional `Ep` | Curate and validate interventions for all paper cases; harden equivalence rules for case diversity |
| Dataset preparation (§5) | Metadata only | Provenance, leakage grouping, data cards, rejection reasons | Supply pinned source snapshots and admit executable cases |
| Baselines and ablations (§5.1-§5.2) | Protocol smoke only | Shared budgets, complete method-case matrices, manifests | Run actual Direct Prompting, Single-Agent, V2E, PoCShift, Quimera, AdvScanner, coordination, and reward variants |
| Statistics and tables (§5) | Implemented machinery | Project-clustered bootstrap, paired permutation tests, failure summaries | Regenerate from measured construction runs rather than profile-based replay smoke data |
| Held-out CVEs (§5.4) | Pending | Catalog gate exists | Add the 18 pinned cases, `Er`/`Ep` evidence, and case-level measured results |

## Current dataset inventory

The available imports are metadata inventories, not executable evaluation cases.

| Pool | Paper target | Current local inventory | READY cases |
|---|---:|---:|---:|
| `D_tra` | 184 (160 train / 24 validation) | 184 metadata candidates from the pinned DeFiHackLabs snapshot at the paper cutoff (`2022-12` inclusive); execution admission pending | 0 |
| `D_mix` | 121 | 121 FORGE preliminary candidates from 104 repository identities, 61 critical / 60 high; classification and admission pending | 0 |
| `D_log` | 122 | 122 FORGE preliminary candidates from 97 repository identities, all critical; classification and admission pending | 0 |
| `D_inc` | 123 | leakage-filtered metadata candidates rebuilt from the pinned DeFiHackLabs snapshot; execution admission pending | 0 |
| `D_cve` | 18 | all 18 official records plus vulnerable/fixed tags and commits cataloged; manual review and replay admission pending | 0 |

`CANDIDATE` and `METADATA_READY` must never be reported as supported, executable, or
validated. The exact boundary is defined in
[`../reference/data-model.md`](../reference/data-model.md).

The collection snapshot occupies about 916 MiB under `data/raw/`. Its primary pins and
rebuild commands are recorded in [`../../data/README.md`](../../data/README.md).

The canonical case view now contains 568 traceable bundles: Dtra 184, Dmix 121, Dlog
122, Dinc 123, and Dcve 18. Every bundle has collected report metadata, source or
reference material, and a workspace link. The 18 CVE workspaces are snapshot-only Ev/Ep
pairs, not executable admissions. Source completeness does not upgrade any case to
`READY` without the execution and intervention gates above.

## What generated runs currently mean

`vw evaluate` uses fake model plans, placeholder Solidity candidates, and shared replay
evidence for the three controlled examples. Model-call, token, scheduling, and execution
counts come from declared profiles; only local replay latency is measured. Its EPR/VPR/CAR
output checks protocol plumbing and must not be compared with the paper's Tables 2-5.

`vw report` correctly applies project-level resampling to the supplied run, but statistical
correctness cannot turn smoke inputs into paper evidence.

## Reproduction assumptions already pinned

- Python 3.11 for Ray/vLLM compatibility.
- Foundry 1.3.1 and Solidity 0.8.24 for controlled live examples.
- Qwen2.5-Coder-32B-Instruct, temperature 0.2, and top-p 0.95 in default configuration.
- Paper budgets: 20 model calls, 64K input tokens, 24K output tokens, four candidates,
  12 compiler/EVM runs, 24 scheduling decisions, and 900 seconds.
- DeFiHackLabs commit `6bbb7b7893d3ccd2ef3d6018d991dc309ccdc281`.

Undisclosed prompt, filtering, penalty, intervention, and dependency-weight decisions
must be versioned before the paper results can be reproduced.
