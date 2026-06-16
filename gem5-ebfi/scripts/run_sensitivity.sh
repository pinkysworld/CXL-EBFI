#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
GEM5_BIN="${GEM5_BIN:-$("${SCRIPT_DIR}/build_gem5.sh" | tail -n 1)}"

for aead_ns in 10 25 50; do
    python3 "${SCRIPT_DIR}/run_matrix.py" \
        --gem5 "${GEM5_BIN}" \
        --out-root \
        "${PROJECT_DIR}/results/sensitivity/aead-${aead_ns}ns/runs" \
        --seeds 1,2,3 \
        --working-sets-kib 4096 \
        --periods-ns 20,100 \
        --aead-latency-ns "${aead_ns}" \
        --force
done

for miss_ns in 40 80 160 320; do
    python3 "${SCRIPT_DIR}/run_matrix.py" \
        --gem5 "${GEM5_BIN}" \
        --out-root \
        "${PROJECT_DIR}/results/sensitivity/metadata-${miss_ns}ns/runs" \
        --seeds 1,2,3 \
        --working-sets-kib 4096 \
        --periods-ns 20,100 \
        --metadata-miss-ns "${miss_ns}" \
        --force
done
