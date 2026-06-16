#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSION="$(sed -n '1p' "${PROJECT_DIR}/gem5-version.txt")"
COMMIT="$(sed -n '2p' "${PROJECT_DIR}/gem5-version.txt")"
CACHE_ROOT="${GEM5_CACHE_ROOT:-${HOME}/.cache/cxl-ebfi}"
GEM5_DIR="${GEM5_DIR:-${CACHE_ROOT}/gem5-${VERSION}}"
VENV_DIR="${GEM5_VENV_DIR:-${CACHE_ROOT}/venv}"
EXTRAS_LINK="${CACHE_ROOT}/gem5-ebfi-extras"
JOBS="${JOBS:-4}"
PYTHON_CONFIG="${PYTHON_CONFIG:-}"

mkdir -p "${CACHE_ROOT}"

if [[ ! -d "${GEM5_DIR}/.git" ]]; then
    git clone --depth 1 --branch "${VERSION}" \
        https://github.com/gem5/gem5.git "${GEM5_DIR}"
fi

ACTUAL_COMMIT="$(git -C "${GEM5_DIR}" rev-parse HEAD)"
if [[ "${ACTUAL_COMMIT}" != "${COMMIT}" ]]; then
    echo "gem5 checkout mismatch: expected ${COMMIT}, found ${ACTUAL_COMMIT}" >&2
    exit 1
fi

if [[ -z "${PYTHON_BIN:-}" ]]; then
    if command -v python3.11 >/dev/null 2>&1; then
        PYTHON_BIN="python3.11"
    else
        PYTHON_BIN="python3"
    fi
fi

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    "${PYTHON_BIN}" -m venv "${VENV_DIR}"
fi
"${VENV_DIR}/bin/pip" install --disable-pip-version-check "scons==4.8.1"

if [[ -z "${PYTHON_CONFIG}" ]]; then
    VENV_PYTHON="$("${VENV_DIR}/bin/python" -c \
        'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}-config")')"
    PYTHON_CONFIG="$(command -v "${VENV_PYTHON}" || true)"
fi
if [[ -z "${PYTHON_CONFIG}" ]]; then
    echo "Could not locate a pythonX.Y-config matching the build venv." >&2
    echo "Set PYTHON_CONFIG explicitly, for example python3.11-config." >&2
    exit 1
fi

ln -sfn "${PROJECT_DIR}/src" "${EXTRAS_LINK}"

cd "${GEM5_DIR}"
PYTHON_CONFIG="${PYTHON_CONFIG}" \
"${VENV_DIR}/bin/scons" build/NULL/gem5.opt \
    -j"${JOBS}" \
    EXTRAS="${EXTRAS_LINK}"

echo "${GEM5_DIR}/build/NULL/gem5.opt"
