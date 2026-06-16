#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
GEM5_BIN="${GEM5_BIN:-$("${SCRIPT_DIR}/build_gem5.sh" | tail -n 1)}"

python3 "${SCRIPT_DIR}/run_write_model.py" \
    --gem5 "${GEM5_BIN}" \
    --out-root "${PROJECT_DIR}/results/write-path/runs" \
    --force
