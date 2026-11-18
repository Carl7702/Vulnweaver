# VulnWeaver

This repository contains the published datasets, modular core implementation, and
reproducible training environment for VulnWeaver.

## Layout

```text
datasets/                       Five fixed dataset partitions (568 cases)
core/vulnweaver/
  task_construction/            Exploit-oriented task construction
  policy_learning/              Hierarchical coordination and policy learning
  validation/                   Independent execution and causal validation
  experiments/                  Dataset and experiment support
  common/                       Shared schemas, configuration, and protocols
training/
  config/                       Reproducible runtime and PPO configuration
  containers/                   Development, Foundry, and vLLM images
  run.sh                        Training entry point
  verify_release.py             Dataset and publication-boundary verification
```

The repository does not contain raw source collections, generated PoCs, reference PoCs,
replay evidence, temporary workspaces, checkpoints, or generated experiment results.

## Setup

Requirements: Python 3.11 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --frozen --extra train
uv run vw doctor --config training/config/default.toml
python training/verify_release.py
```

Run hierarchical PPO training with:

```bash
training/run.sh --iterations 10
```

The default checkpoint and result paths are local outputs excluded from version control.

## Dataset partitions

| Partition | Purpose | Cases |
| --- | --- | ---: |
| `D_tra` | training and validation | 184 |
| `D_mix` | implementation-vulnerability evaluation | 121 |
| `D_log` | business-logic evaluation | 122 |
| `D_inc` | incident evaluation | 123 |
| `D_cve` | held-out CVE practicality study | 18 |

See [`datasets/README.md`](datasets/README.md) and
[`datasets/manifest.json`](datasets/manifest.json) for the published inventory.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
