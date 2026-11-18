#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
exec uv run vw train \
  --checkpoint training/checkpoints/hierarchical-ppo.pt \
  --result-path training/results/result.json \
  "$@"
