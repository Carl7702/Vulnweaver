# Reproduction status and paper gaps

Assessment date: 2026-11-17. The attached 18-page paper was compared against the current
repository at module, dataset, algorithm, and experiment level.

## Dataset continuation (2026-11-17)

- Aligned the CLI training import and evaluation leakage pool with the paper's inclusive
  `2022-12` cutoff. The prior CLI override admitted January 2023 records and produced 196
  candidates; the corrected import produces 184 metadata candidates split 160/24 with no
  project or attack-family overlap.
- Rebuilt the current evaluation card from the pinned sources. `D_inc` has 123
  metadata-ready records and 0 executable `READY` records. `D_cve` has 18 official
  records and 0 executable `READY` records because environment admission, manual review,
  and official-patch replay remain incomplete.
- A deterministic FORGE selection now provides 121 `D_mix` and 122 `D_log` candidates
  with the paper’s stated project and severity counts. CWE/text classification remains
  provisional; 38 inferred repository identities occur in both evaluation pools. The
  original case selection and case-level executable admission remain unverified.
- Materialized a canonical per-case view with report metadata, source/reference material,
  and environment linkage: Dtra 184, Dmix 121, Dlog 122, Dinc 123, and Dcve 18. The
  rejected Dinc inventory remains separate and is not mixed into the 123-case benchmark.

## Bottom line

The repository is a well-tested **artifact scaffold**, not yet the artifact that supports
the paper's quantitative claims. Controlled replay and reporting mechanics work, but the
main empirical chain is incomplete:

```text
paper datasets -> executable admission -> real construction training -> frozen checkpoint
-> real baselines/ablations -> independent validation -> paper tables
```

The repository currently reaches metadata import, controlled examples, synthetic policy
training, replay-profile experiments, and table generation. It does not yet connect those
pieces on the paper cases.

## Blocking gaps

1. **No admitted paper dataset.** Source collection and metadata catalogs now exist, but
   all `D_tra`, `D_mix`, `D_log`, `D_inc`, and `D_cve` pools still have zero `READY`
   cases. The paper requires 184 training cases, 366 main evaluation cases, and 18
   held-out CVEs.
2. **No real construction-policy training.** `policy_learning/training.py` optimizes a synthetic task in
   which each specialist chooses between two toy actions. It does not compile contracts,
   call Qwen/vLLM, consume Foundry feedback, or train on `D_tra`.
3. **Reward algorithm is not end-to-end.** Equations (3)-(8) now have tested primitives,
   including normalized setup/prefix progress, configurable dependency weights, conserved
   delayed attribution, penalties, and assignment returns. Real construction trajectories
   still do not feed those rewards into paper-scale PPO updates.
4. **Policy-guided inference is absent.** The runnable six-agent construction path is a
   fixed heuristic recipe for one controlled case; it does not load learned policies for
   unseen findings as Algorithm 2 requires.
5. **Reported baselines are not executed.** Current method variants are resource profiles
   over identical replay evidence. Direct Prompting, Single-Agent, V2E, PoCShift,
   Quimera, AdvScanner, fixed workflow, heuristic scheduling, and reward ablations need
   actual construction implementations and paired eligible pools.
6. **Paper validation studies are absent.** The 180 labeled verifier controls, 72 official
   patch comparisons, five-seed learning curves, complexity annotations, and 18 case-level
   CVE runs are not present.
7. **Prompts and interventions are not released.** Appendix C contains headings but no
   prompt text, and the repository has no versioned prompt bundle or paper-case `Er`/`Ep`
   intervention catalog.
8. **The repository has no release commit.** The current `main` branch has no commits and
   every reviewer-facing file is untracked. A tagged, immutable commit is required before
   manifests, source hashes, or the paper's artifact URL can identify a reviewable release.

## Important implementation mismatches

- The paper says training uses PyTorch 2.5 and Ray RLlib 2.40. The repository pins both,
  but its current trainer is a custom PyTorch PPO smoke implementation and does not use
  RLlib for the paper training loop.
- The paper's progress potential includes setup fraction `q`, verified transaction-prefix
  length `l`, violation `v`, and impact `i`. The current reward primitive reduces this to
  one first-seen reward per obligation kind and has no normalized prefix-length state.
- Dependency types have no configurable `omega_k` weights in the default configuration.
- Checkpoint selection by best validation CAR (with cost tie-break) is not implemented.
- Environment-failure exclusion, multi-seed training, 10K-interaction checkpointing, and
  frozen-policy evaluation are described in the paper but not wired into a real run.
- The verifier's core state machine exists, but its prefix-equivalence signature is a
  compact controlled-case rule. Paper-scale interventions need case-level review and
  validation against official patches.

## Paper text issues to resolve before release

These are internal paper inconsistencies, not repository defects, but they prevent a
single unambiguous artifact target:

- The abstract/contributions report **92.6% VPR and 90.2% CAR**, while Table 2 and §5.1
  report **92.5% VPR and 90.5% CAR** overall.
- Section 5 contains unresolved references to **“Appendix ??”**.
- The sentence “Eligibility is determined before observing results.” appears twice.
- Appendix C lists prompt-template headings but supplies no templates.
- The repository must not advertise paper-result availability until the generated run
  manifests and case-level evidence match the finalized paper numbers.

## What is already solid

- Strict, versioned case and run schemas with deterministic hashing.
- Separation of construction-visible inputs from `Er`, `Ep`, and reference PoCs.
- Isolated Foundry backend, broadcast/network restrictions, and structured trace parser.
- Four-obligation evaluation and controlled `Ev`/`Er` causal replay.
- Model backend interfaces for fake, replay, OpenAI-compatible, and vLLM endpoints.
- Dataset provenance, rejection reasons, and project-level leakage grouping.
- Project-clustered bootstrap, project-paired permutation tests, and failure summaries.
- Unit suite covering these mechanics; Docker tests remain opt-in.

## Recommended completion order

1. Freeze the final paper numbers, prompt templates, case catalog, and intervention rules.
2. Admit the 184 training cases and 384 evaluation/practicality cases with pinned sources.
3. Connect real construction trajectories to dependency-weighted reward redistribution.
4. Train five seeds, select checkpoints on the 24-case validation split, and freeze them.
5. Run internal baselines and ablations on the 366-case pool.
6. Reproduce external baselines on predeclared eligible subsets.
7. Run the 180-control, 72-patch, and 18-CVE studies.
8. Regenerate every paper table/figure from immutable manifests and publish case-level
   evidence plus a machine-readable discrepancy report.

## Admission audit update (2026-11-17)

The imported inventory now has a reproducible admission audit at
`data/processed/admission/admission-manifest.json`. It generates schema-valid CaseSpec
previews for compile-successful workspaces and records the remaining paper gates:
fixed fork, two reset digests, Ev replay, Er PrefixEq/impact prevention, and optional Ep
replay. `COMPILE_OK` remains a preflight state and is not reported as validated evidence.

RQ3 control slots are materialized at `data/processed/rq3-dataset/`: 180 labeled slots
(90 valid-causal, 30 trigger-only, 30 unrelated-impact, 30 persistent-impact) are now
bound to 180 compile-ready source cases, and 72 official-patch slots are explicit. The 18
pinned CVE vulnerable/fixed pairs are cataloged as auxiliary material, not substituted for
the undisclosed RQ3 selection. All imported controls remain pending until fixed candidates
and independent replay evidence are collected.
