#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
GEM5_BIN="${GEM5_BIN:-$("${SCRIPT_DIR}/build_gem5.sh" | tail -n 1)}"

python3 "${SCRIPT_DIR}/run_matrix.py" \
    --gem5 "${GEM5_BIN}" \
    --out-root "${PROJECT_DIR}/results/quick/runs" \
    --seeds 1 \
    --working-sets-kib 256,4096 \
    --periods-ns 20,100 \
    --warmup-us 20 \
    --duration-us 100 \
    --force
