# Generated results

Paper experiment outputs are separated from inputs and from each other:

- `training/`: policy checkpoints, validation curves, and reward-ablation trajectories;
- `evaluation/`: frozen-policy benchmark runs, RQ2/RQ3/RQ4 evidence, baselines, and
  generated tables.

Only directory READMEs are versioned. Run artifacts remain ignored because they can be
large; every real run must carry its own manifest, seed, code/data hashes, tool versions,
resource usage, and output paths. Smoke outputs must include `smoke` in their filename
and must not be used as paper measurements.
