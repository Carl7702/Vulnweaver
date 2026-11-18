# Local data workspace

- `raw/` is for pinned external checkouts or source archives.
- `processed/` is for generated metadata, admission records, and data cards.

Dataset contents are ignored by Git; only the directory structure is versioned. Paper
release data should be distributed separately with checksums and provenance manifests.

## Current pinned sources (2026-11-16)

- `raw/FORGE-Artifacts`: `76b75824de4ad6c9a0ba592ee0878587d98cb32b`; the
  sparse checkout contains `dataset/results` and `dataset/contracts`.
- `raw/FORGE-Curated`: `c2829d451d37581dae71aba610506ba3b161e371`; the
  sparse checkout contains findings and the medium/high/critical flattened VFP subset.
- `raw/DeFiHackLabs`: `6bbb7b7893d3ccd2ef3d6018d991dc309ccdc281`; the
  sparse checkout contains `src/test` and the Foundry project metadata.
- `raw/cve/records`: the 18 official CVEProject records named in the paper's RQ4 table.
- `raw/cve/repos`: filtered OpenZeppelin Contracts and risc0-ethereum repositories with
  the vulnerable and fixed tags used by the CVE catalog.

Rebuild the current metadata products with:

```text
uv run vw dataset import-forge data/raw/FORGE-Artifacts
uv run vw dataset import-defihacklabs data/raw/DeFiHackLabs \
  --cutoff-month 2022-12 --validation-count 24
uv run vw dataset import-cve data/raw/cve/records \
  data/raw/cve/rq4_selection.csv data/raw/cve/repos data/raw/cve/snapshots
uv run vw dataset build-evaluation \
  --ase-source PATH_TO_ASE26 \
  --defihacklabs-source data/raw/DeFiHackLabs \
  --cve-catalog data/processed/cve/catalog.json
```

The training cutoff is 2022-12 inclusive. To reconstruct the FORGE selections after
building the evaluation inputs, run `.venv/bin/python scripts/select_forge_evaluation.py`.
The script selects 121 D_mix and 122 D_log findings with the paper's project and severity
counts. It uses recorded CWE labels and text heuristics, so these are preliminary
classifications requiring case-level review. It prevents duplicate findings; 38 repository
identities appear in both evaluation pools, which occupy the same test partition. Project
identity is inferred from repository URLs; cross-source protocol aliases require review.
The 123 D_inc candidates are a reproducible selection from the complete pinned checkout,
not the undisclosed original case list.

Metadata availability is not executable admission. A record remains non-`READY` until
its vulnerable environment, obligations, reset check, replay, and root-cause intervention
have passed the admission workflow.

## Canonical case layout

Run `.venv/bin/python scripts/materialize_case_bundles.py` to build the stable view under
`processed/datasets/`:

| Directory | Role | Cases |
|---|---|---:|
| `01_training_Dtra/cases/` | policy training and checkpoint validation | 184 |
| `02_evaluation_Dmix/cases/` | code-implementation benchmark | 121 |
| `03_evaluation_Dlog/cases/` | business-logic benchmark | 122 |
| `04_evaluation_Dinc/cases/` | incident benchmark | 123 |
| `05_practicality_Dcve/cases/` | held-out CVE practicality study | 18 |

Every case directory contains `case.json`, `bundle.json`, collected vulnerability-report
metadata, relevant source/reference material, and an environment link when an isolated
workspace exists. The three main benchmark datasets therefore contain 366 cases. Rejected
Dinc inventory rows remain auditable under `processed/evaluation/records/` but are not
part of the canonical 123-case view.

`processed/rq3-dataset/` is separate from the construction benchmark. It contains 180
control directories (90 positive valid-causal and 30 in each negative class) bound to
collected source cases, plus 72 official-patch comparison slots. At present, 18 auxiliary
CVE vulnerable/fixed snapshot pairs are pinned; they are not claimed to be the paper's
undisclosed 72-case RQ3 selection. Rows without a fixed candidate and Ev/Er/Ep evidence
remain pending rather than being counted as reproduced measurements.

After importing sources, prepare the local workspaces and case views with:

```text
.venv/bin/python scripts/build_environment_manifest.py
.venv/bin/python scripts/add_training_environments.py
.venv/bin/python scripts/compile_case_workspaces.py
.venv/bin/python scripts/add_cve_environments.py
.venv/bin/python scripts/audit_case_admission.py
.venv/bin/python scripts/materialize_case_bundles.py
.venv/bin/python scripts/prepare_rq3_controls.py
.venv/bin/python scripts/verify_dataset_inventory.py
```

## Inventory consistency

Run `.venv/bin/python scripts/verify_dataset_inventory.py` after rebuilding the current
local snapshot. It checks file counts, split and held-out overlap, catalog identities,
status counts, and the recorded input hashes. Reimports remove stale JSON records from
the generated `candidates/` and `records/` directories. The selected 123 `D_inc`
metadata records are a deterministic reconstruction, not a verified match to the
undisclosed paper case list.
