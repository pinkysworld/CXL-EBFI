#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
GEM5_BIN="${GEM5_BIN:-$("${SCRIPT_DIR}/build_gem5.sh" | tail -n 1)}"
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3.11 || command -v python3)}"

"${PYTHON_BIN}" "${SCRIPT_DIR}/run_matrix.py" \
  --gem5 "${GEM5_BIN}" \
  --out-root "${PROJECT_DIR}/results/workloads/runs" \
  --working-sets-kib 65536 \
  --periods-ns 20 \
  --traffic-patterns uniform,linear,stride4k,hotcold \
  --force

"${PYTHON_BIN}" "${SCRIPT_DIR}/plot_workloads.py"
