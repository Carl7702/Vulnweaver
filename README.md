# VulnWeaver

Artifact repository for **“VulnWeaver: Hierarchical Multi-Agent Reinforcement
Learning for Smart Contract Vulnerability Validation.”**

VulnWeaver studies how a learned coordinator and six specialist agents construct
smart-contract proofs of concept (PoCs), and how an independent verifier checks factual
reproduction and causal relevance through vulnerable (`Ev`) and root-cause-neutralized
(`Er`) replays.

> **Artifact status.** This repository currently implements and tests the schemas,
> controlled examples, isolated Foundry execution, four validation obligations,
> dependency extraction, reward primitives, a synthetic hierarchical-PPO smoke task,
> dataset adapters, and statistical reporting. It does **not yet reproduce the paper's
> main experimental results**. The paper's admitted datasets, real Qwen/vLLM training,
> external baselines, five-seed ablations, and 18-CVE study are still missing. See
> [Reproduction status](docs/reviewer/reproduction-status.md) for the exact gap list.

## Reviewer path

1. Read the [paper-to-code map](docs/reviewer/paper-to-code.md).
2. Run the unit and offline replay suite below.
3. Inspect one self-contained case under [`examples/authorization`](examples/authorization).
4. Consult [implementation status](docs/reviewer/implementation-status.md) before interpreting
   any generated metrics.

The controlled examples validate the artifact mechanics; they are not members of the
paper's training or evaluation datasets.

## Quick start

Requirements: Python 3.11 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --extra dev
uv run vw doctor
uv run pytest
```

Replay a complete `Ev`/`Er` validation without Docker or model access:

```bash
uv run vw verify \
  examples/authorization/case.json \
  examples/authorization \
  --replay examples/authorization/replay.json
```

For live Foundry replay, first build the pinned container and use the supplied candidate:

```bash
docker build -f containers/foundry.Dockerfile \
  -t vulnweaver-foundry:1.3.1-solc0.8.24 .
uv run vw verify \
  examples/authorization/case.json \
  examples/authorization/candidate
```

Training dependencies are optional because PyTorch and Ray are large:

```bash
uv sync --extra dev --extra train
uv run vw train --iterations 10
```

At present, `vw train` is a policy/plumbing smoke test over a synthetic environment; it
is not the paper's 184-case construction training run.

## Repository layout

```text
.
├── src/vulnweaver/
│   ├── task_construction/ Paper §3.2
│   ├── policy_learning/   Paper §3.3
│   ├── validation/        Paper §3.4
│   ├── experiments/       Paper §5
│   └── common/            Shared schemas and protocols
├── tests/                 Mirrors the source hierarchy
├── examples/              One self-contained directory per controlled case
├── method/
│   ├── 01_exploit_oriented_task_construction/
│   ├── 02_hierarchical_coordination_policy_learning/
│   └── 03_policy_guided_poc_construction_validation/
├── docs/
│   ├── reviewer/          Paper mapping, status, and gap audit
│   └── reference/         Technical reference documentation
├── config/                Paper-aligned defaults
├── containers/            Foundry, vLLM, and development images
├── data/                  Pinned sources, canonical per-case bundles, RQ3 controls
└── results/
    ├── training/          Checkpoints, validation curves, reward ablations
    └── evaluation/        RQ1-RQ4, baselines, reports, and tables
```

The canonical local dataset view is generated under `data/processed/datasets/` with
Dtra (184), Dmix (121), Dlog (122), Dinc (123), and Dcve (18) stored one directory per
case. RQ3 controls and patch-pair inputs live separately under
`data/processed/rq3-dataset/` so verifier-reliability data cannot be confused with the
construction benchmark.

The main paper concepts map directly to modules:

- task/case representation: `task_construction/` and `common/schema.py`;
- hierarchical coordination and rewards: `policy_learning/`;
- independent replay and intervention: `validation/`;
- datasets, baselines, and reports: `experiments/`.

## Safety boundary

VulnWeaver executes only in local containers or pinned, read-only historical forks. It
does not broadcast transactions, manage private keys, or access real assets. API keys
and RPC URLs are read from environment variables only; copy `.env.example` for local
development and never commit `.env`.

## Development checks

```bash
uv run ruff check .
uv run mypy src
uv run pytest --cov=vulnweaver
```

Docker integration tests are opt-in:

```bash
VW_RUN_DOCKER_TESTS=1 uv run pytest -m integration
```

## License

Apache-2.0. See [LICENSE](LICENSE).
