# Training

Install the pinned training environment and start a run from the repository root:

```bash
uv sync --frozen --extra train
training/run.sh --iterations 10 --episodes-per-iteration 32 --seed 42
```

The runtime configuration is stored in `config/default.toml`. The development image
contains Python 3.11 and the locked training dependencies; the Foundry image pins the
execution toolchain; the vLLM image pins the model-serving runtime.

Checkpoints and run results are written below `training/` and ignored by Git.
