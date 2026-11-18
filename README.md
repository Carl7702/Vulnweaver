# VulnWeaver

VulnWeaver is a research framework for structuring smart-contract vulnerability cases,
coordinating specialist policies, training a masked hierarchical PPO controller, and
independently validating candidate reproductions against explicit causal obligations.

This public repository contains exactly three project surfaces:

1. the five fixed dataset partitions;
2. the modular implementation of the core method; and
3. the training framework and pinned runtime environments.

Generated PoCs, reference PoCs, replay evidence, raw source collections, temporary
workspaces, checkpoints, and experiment outputs are intentionally not published.

## Repository layout

```text
.
|-- datasets/                         Published dataset partitions
|   |-- 01_training_Dtra/             D_tra: training and validation
|   |-- 02_evaluation_Dmix/           D_mix: implementation vulnerabilities
|   |-- 03_evaluation_Dlog/           D_log: business-logic vulnerabilities
|   |-- 04_evaluation_Dinc/           D_inc: incident vulnerabilities
|   |-- 05_practicality_Dcve/         D_cve: held-out CVE study
|   |-- manifest.json                 Partition and release counts
|   `-- checksums.json                SHA-256 inventory of published payloads
|-- core/vulnweaver/                  Python package
|   |-- common/                       Schemas, hashing, manifests, and protocols
|   |-- task_construction/            Case loading, isolation, and workspaces
|   |-- policy_learning/              Coordination, rewards, models, and PPO
|   |-- validation/                   Execution, obligations, replay, and verification
|   |-- experiments/                  Dataset adapters, runners, and reports
|   `-- cli.py                        `vw` command-line interface
`-- training/
    |-- config/default.toml           Reproducible default configuration
    |-- containers/                   Development, Foundry, and vLLM images
    |-- run.sh                        Training entry point
    `-- verify_release.py             Dataset/publication-boundary verifier
```

Root-level files are limited to packaging, dependency locking, licensing, and repository
configuration.

## What is runnable in this release

The public release supports:

- loading and validating the project schemas;
- inspecting normalized cases and stable case hashes;
- constructing dependency-aware specialist assignment plans;
- running the deterministic masked hierarchical PPO training environment;
- saving policy checkpoints and JSON training summaries;
- importing external dataset snapshots through the supplied adapters;
- independently validating a user-supplied candidate against `Ev`, `Er`, and optionally
  `Ep` environments;
- aggregating user-supplied experiment evidence into metrics and reports; and
- verifying every published dataset file against the release checksum inventory.

The included `vw train` command trains the synthetic coordination environment implemented
in `core/vulnweaver/policy_learning/training.py`. It validates the policy architecture,
legal-action masks, coordinator/specialist hand-off, PPO updates, checkpointing, and
reproducibility. It does not execute the unpublished generated-PoC training corpus.

The current `vw train` and `vw evaluate` commands use deterministic offline model
responses. The package includes OpenAI-compatible and vLLM client classes, but the CLI
does not automatically switch to a live model server. Live model integration must
instantiate those clients explicitly in downstream code.

The published dataset is a static, non-PoC research release. Live verification requires
a candidate directory supplied by the user. Offline evaluation additionally requires
replay bundles; those bundles are not included in this repository.

## Requirements

### Local Python workflow

- Python `3.11` (the package currently requires `>=3.11,<3.13`, while `vw doctor`
  validates the pinned 3.11 runtime)
- [uv](https://docs.astral.sh/uv/)
- Git

### Optional execution services

- Docker for the pinned Foundry execution environment
- an NVIDIA GPU and NVIDIA Container Toolkit for the vLLM image
- an OpenAI-compatible model endpoint when using the model client classes programmatically
- an RPC endpoint supplied through an environment variable for cases that require a
  historical fork

No private key is required. The default execution configuration disables network access
inside the Foundry container and does not allow transaction broadcasting.

## Installation

After cloning the repository, install the locked training environment:

```bash
cd Vulnweaver
uv sync --frozen --extra train
```

For local static analysis tools as well:

```bash
uv sync --frozen --extra train --extra dev
```

Confirm that the package, configuration, Docker CLI, and host Foundry installation are
visible:

```bash
uv run vw doctor --config training/config/default.toml
```

The `docker_cli` and `host_forge` fields are informational unless the corresponding
execution path is used. To test the pinned Foundry container too, build it first and add
`--check-container` as described below.

## Dataset release

### Partitions

| Directory | Symbol | Role | Cases |
| --- | --- | --- | ---: |
| `01_training_Dtra` | `D_tra` | policy training and validation | 184 |
| `02_evaluation_Dmix` | `D_mix` | code/implementation vulnerability evaluation | 121 |
| `03_evaluation_Dlog` | `D_log` | business-logic vulnerability evaluation | 122 |
| `04_evaluation_Dinc` | `D_inc` | post-cutoff incident evaluation | 123 |
| `05_practicality_Dcve` | `D_cve` | held-out CVE practicality study | 18 |
| **Total** |  |  | **568** |

`D_tra` contains 160 training cases and 24 validation cases. The four evaluation and
practicality partitions are kept separate from policy training.

The published preparation states are:

| Symbol | Published state | Count | Interpretation |
| --- | --- | ---: | --- |
| `D_tra` | `METADATA_READY` | 184 | metadata is complete; executable admission is not claimed |
| `D_mix` | `CANDIDATE` | 121 | preliminary implementation-vulnerability candidates |
| `D_log` | `CANDIDATE` | 122 | preliminary business-logic candidates |
| `D_inc` | `METADATA_READY` | 123 | incident metadata is complete; replay is not published |
| `D_cve` | `REJECTED` | 18 | retained for audit; executable admission requirements failed |

The `D_mix` and `D_log` classifications use recorded CWE labels and deterministic text
heuristics. They are published as candidates, not as manually confirmed ground truth.
Every case retains source identifiers, commits, and hashes so these decisions can be
audited without presenting them as reproduced vulnerabilities.

### Case layout

Each partition contains `cases/<case-id>/`. Depending on the source family, a case may
contain:

```text
case.json                    Normalized case or evaluation record
bundle.json                  Publication status and included-asset declaration
vulnerability-report.json    Structured non-PoC vulnerability metadata
source/                      Selected production contract source, when publishable
vulnerable-source/           Vulnerable CVE snapshot, when applicable
patched-source/              Fixed CVE snapshot, when applicable
```

`bundle.json` explicitly records `generated_poc_included: false` and lists excluded
assets. A source directory can be absent when the only available source artifact was a
reference PoC or another excluded executable artifact.

Dataset status values describe preparation state. `CANDIDATE` or `METADATA_READY` does
not imply that a case has an executable environment or a causally validated reproduction.

### Verify the published files

Run the release verifier from the repository root:

```bash
python training/verify_release.py
```

It checks:

- the exact partition counts;
- the 568 case bundles;
- every SHA-256 entry in `datasets/checksums.json`, with no missing or unlisted payloads;
- the absence of symbolic links;
- the absence of generated/reference PoC and replay filenames; and
- the absence of test-, mock-, fuzz-, and exploit-like Solidity sources.

Expected summary:

```text
release verification: 568 cases, 17572 payload files, 0 symlinks, 0 generated/reference PoCs
```

The published `case.json` files are dataset records, not executable `CaseSpec` fixtures.
To inspect a separately prepared, schema-complete case without executing code, run:

```bash
uv run vw case inspect /path/to/schema-complete-case.json
```

The adapters can import separately obtained upstream snapshots into the ignored
`datasets/imported/` workspace. For example:

```bash
uv run vw dataset import-forge /path/to/pinned/FORGE-Artifacts
uv run vw dataset import-defihacklabs /path/to/pinned/DeFiHackLabs \
  --cutoff-month 2022-12 \
  --validation-count 24
```

Raw upstream snapshots are external inputs and remain outside version control.

## Core method

### 1. Case construction and isolation

`core/vulnweaver/task_construction/` loads `CaseSpec` records, validates their task graph
and input hashes, and produces a construction-facing view. The construction view does not
expose root-cause-neutralized environments, patched environments, or sealed reference
artifacts to the construction policy.

### 2. Hierarchical coordination and policy learning

`core/vulnweaver/policy_learning/` contains:

- a dependency-aware coordinator that releases a task only after its prerequisites;
- role/capability allow-list enforcement;
- coordinator and specialist action masks;
- dependency tracing over storage, calls, and asset flow;
- cost- and repetition-aware reward components;
- model backend abstractions; and
- a masked actor-critic PPO implementation with generalized advantage estimation.

The coordinator emits assignments and legal operations. Candidate artifacts are runtime
outputs and are not stored in this public repository.

### 3. Independent validation

`core/vulnweaver/validation/` runs validation separately from construction. A complete
case defines four obligation types:

1. `setup`: the required initial state exists;
2. `trigger`: the vulnerable execution path is reached;
3. `violation`: the intended security property is violated; and
4. `impact`: an observable consequence is demonstrated.

The verifier evaluates the candidate in the vulnerable environment (`Ev`) and compares it
with a root-cause-neutralized environment (`Er`). A case may additionally provide an
official patched environment (`Ep`). This separates factual reproduction from causal
attribution.

### 4. Experiment and reporting support

`core/vulnweaver/experiments/` provides dataset adapters, shared experiment budgets,
method profiles, run manifests, failure accounting, project-clustered bootstrap estimates,
paired permutation tests, and report generation.

## Training

### Configuration

The default configuration is `training/config/default.toml`. Important defaults are:

| Setting | Default |
| --- | ---: |
| random seed | `42` |
| learning rate | `3e-4` |
| discount | `0.99` |
| GAE lambda | `0.95` |
| PPO clip | `0.2` |
| hidden units | `128` |
| episodes per iteration | `32` |
| maximum configured iterations | `100` |

The environment alternates between one coordinator and role-specific specialists. Illegal
coordinator actions are masked before sampling. The trainer maintains independent policy
networks and optimizers for the coordinator and specialists, applies PPO updates, and
compares the learned policy with a random legal-action baseline.

### Run training

The wrapper selects repository-local output paths:

```bash
training/run.sh \
  --iterations 10 \
  --episodes-per-iteration 32 \
  --seed 42
```

Outputs:

```text
training/checkpoints/hierarchical-ppo.pt
training/results/result.json
```

Both directories are ignored by Git. To select explicit locations, invoke the CLI
directly:

```bash
uv run vw train \
  --iterations 10 \
  --episodes-per-iteration 32 \
  --checkpoint /path/to/checkpoint.pt \
  --result-path /path/to/result.json \
  --seed 42
```

The JSON result reports the iteration count, coordinator and specialist update counts,
learned mean return, random-policy mean return, and checkpoint path.

## Runtime environments

### Development image

Build the Python 3.11 environment with the locked training dependencies:

```bash
docker build \
  -f training/containers/development.Dockerfile \
  -t vulnweaver-development:latest \
  .

docker run --rm vulnweaver-development:latest
```

The default container command runs `vw doctor` against the published configuration.

### Foundry execution image

Build the pinned Foundry `1.3.1` and Solidity `0.8.24` environment:

```bash
docker build \
  -f training/containers/foundry.Dockerfile \
  -t vulnweaver-foundry:1.3.1-solc0.8.24 \
  .

uv run vw doctor \
  --config training/config/default.toml \
  --check-container
```

The image is pinned by base-image digest and Solidity binary checksum. On Apple Silicon,
Docker uses `linux/amd64` emulation so the same Solidity binary is used across hosts.

### vLLM model server

Build and start the GPU-only OpenAI-compatible endpoint:

```bash
docker build \
  -f training/containers/vllm.Dockerfile \
  -t vulnweaver-vllm:0.6.6 \
  .

docker run --rm --gpus all \
  -p 8000:8000 \
  vulnweaver-vllm:0.6.6
```

The image defaults to `Qwen/Qwen2.5-Coder-32B-Instruct` with `bfloat16`. Model weights
are downloaded or mounted at runtime and are never committed to this repository.

### Environment variables

Only model-client credentials are read directly from environment variables. Use
`training/.env.example` as a local template when calling the clients programmatically:

```bash
cp training/.env.example .env
set -a
source .env
set +a
```

Supported variables:

| Variable | Purpose |
| --- | --- |
| `VW_MODEL_API_KEY` | optional credential for `OpenAICompatibleBackend` |
| `VW_VLLM_API_KEY` | optional credential for `VLLMBackend` |

The endpoint URL and model name are constructor arguments in the current implementation;
the CLI does not read them from `.env`. RPC resolution is also an external integration
responsibility. `.env`, credentials, RPC URLs, and model weights are excluded from version
control.

## Candidate verification

Live verification requires a schema-complete case, a user-supplied candidate directory,
and the environment repositories referenced by the case:

```bash
uv run vw verify \
  /path/to/case.json \
  /path/to/candidate-directory \
  --repository-root /path/to/environment-root \
  --config training/config/default.toml
```

Offline verification accepts an externally supplied replay bundle:

```bash
uv run vw verify \
  /path/to/case.json \
  /path/to/candidate-directory \
  --replay /path/to/replay.json
```

The verifier rejects replay/case hash mismatches before evaluating obligations. Candidate
directories and replay bundles are runtime inputs and must not be committed to this
public repository.

## Evaluation and reports

`vw evaluate` requires a directory of complete `case.json` and `replay.json` pairs. The
public dataset does not contain replay files, so pass an external evidence directory:

```bash
uv run vw evaluate \
  --cases-root /path/to/private-replay-cases \
  --output results/evaluation \
  --seed 42
```

Select method profiles with a comma-separated list:

```bash
uv run vw evaluate \
  --cases-root /path/to/private-replay-cases \
  --methods direct_prompting,hierarchical_coordination \
  --output results/evaluation
```

Generate aggregate JSON, Markdown, and CSV reports:

```bash
uv run vw report \
  results/evaluation/experiment.json \
  --output results/report \
  --bootstrap-samples 10000 \
  --seed 42
```

`results/` is ignored by Git.

This command is an offline protocol simulator. It uses deterministic model responses,
non-executable marker candidates, prescribed resource profiles, and supplied replay
evidence. Its output validates accounting, replay, aggregation, and reporting paths; it
must not be reported as live model performance, measured token usage, or reward efficacy.

## Development checks

After installing the `dev` extra:

```bash
uv run ruff check core training
uv run mypy core
uv lock --check
uv build
```

The repository intentionally does not publish the internal test fixtures because they
contain controlled example artifacts outside the release boundary. Use
`training/verify_release.py` for the public dataset integrity check.

## Troubleshooting

- **`vw doctor` reports an unsupported Python version:** run through the Python 3.11
  environment created by `uv sync`.
- **Docker daemon connection failure:** start Docker Desktop or the system Docker service
  before using `--check-container` or live verification.
- **vLLM cannot see a GPU:** verify the NVIDIA driver, Container Toolkit, and
  `docker run --gpus all` support on the host.
- **A case has no source directory:** inspect `bundle.json`; the source may have been
  excluded because it was a PoC, replay, test fixture, or temporary workspace.
- **`vw evaluate` finds no cases:** point `--cases-root` to complete external
  `case.json`/`replay.json` pairs rather than the static public dataset.

## Release boundary

The public repository contains no generated or reference PoC files. It also excludes
replay evidence, raw upstream repositories, test/mock/fuzz sources, temporary build
workspaces, secrets, local absolute paths, checkpoints, and generated results. The
published checksums make the released data independently auditable without exposing
those excluded artifacts.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
