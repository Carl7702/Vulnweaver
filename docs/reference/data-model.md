# Data model and admission boundary

VulnWeaver distinguishes three levels that must not be conflated in paper metrics:

1. An **external project record** is one input JSON document.
2. A **finding candidate** is one finding from that document, with provenance and
   structural rejection reasons. It is not yet an executable case.
3. An **admitted case** is a complete `CaseSpec` whose source, compiler, pinned
   environment, predicates, input hashes, and reset behavior have passed admission.

The ASE26 adapter therefore reports both project and finding counts. A status of
`CANDIDATE` means only that the source metadata passed the adapter's structural checks;
it must not be reported as `SUPPORTED`, executable, or validated. The `vw dataset admit`
command is reserved for complete `CaseSpec` files and optionally verifies every declared
input hash.

Reference PoCs are represented by `SealedReference`. Construction views must never mount
that path. Root-cause-neutralized (`Er`) and officially patched (`Ep`) environments are
also verifier-only inputs; the construction process receives only its filtered view of
the vulnerable environment (`Ev`).

## Evaluation pools

`vw dataset build-evaluation` writes per-finding/incident records, an
`import-manifest.json`, a data card, and a discrepancy report. Records distinguish
`CANDIDATE`, `METADATA_READY`, `READY`, and `REJECTED`; candidate availability is
separate from execution admission. Missing catalogs produce an explicit rejection
sentinel. A sentinel does not represent a discovered vulnerability.

Directory input digests hash relative paths and file contents, excluding volatile
VCS/build state. Hashes remain stable when inputs move and change when contents
change. The DeFiHackLabs manifest additionally pins its commit and source tree.

## Experiment and report artifacts

An `ExperimentCase` carries `case_id`, `project_id`, case/replay paths, and their
content hashes. The runner rejects duplicate IDs and changed inputs before running.
`project_id` groups all findings from the same project for uncertainty estimates.
Older experiment exports without project IDs need to be regenerated.

`vw evaluate` writes `manifest.json`, `experiment.json`, `metrics.json`,
`case-results.jsonl`, `summary.md`, and candidate placeholders. The manifest records
the source code hash even when Git has no commit. `evaluation_mode=offline_replay`
and `resource_accounting=profiled` identify the current smoke protocol: model calls,
token counts, scheduling decisions, and EVM execution counts follow method profiles.
They are not measurements of a live baseline. Latency measures local replay work.

`vw report` writes `report.json`, `report.md`, and `paper-table.csv`. The report
retains the resampling seed, run hash, optional evaluation manifest hash, point
estimates, failure counts, and separate metadata/admission totals. A complete
method-by-case result matrix is required; partial pairs are rejected.

The bootstrap samples projects with replacement and includes every finding in each
drawn project, including repeated draws. Its statistic divides total successes by
the number of sampled findings, so unequal project sizes retain their case weights.
The percentile interval uses the 2.5% and 97.5% quantiles. Permutation tests use one
paired label swap per project, two-sided absolute differences, and add-one Monte
Carlo correction. P-values are unadjusted. By default, each later method is compared
with the first method for EPR, VPR, and CAR.
