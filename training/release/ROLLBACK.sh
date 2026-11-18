#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: ROLLBACK.sh PATH_TO_MODIFIED_COPY}"
patch --batch --silent -R "$target" < "$(dirname "$0")/DIFF_FILE"
