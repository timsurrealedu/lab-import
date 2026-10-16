#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
VENV_DIR="${PROJECT_DIR}/.venv"

echo "==> Uninstalling VM Lab Importer CLI links from ${BIN_DIR}"

COMMANDS=(
    "lab"
    "lab-import"
    "lab-list"
    "lab-start"
    "lab-stop"
    "lab-info"
    "lab-remove"
    "lab-network"
)

for cmd in "${COMMANDS[@]}"; do
    if [ -L "${BIN_DIR}/${cmd}" ] || [ -f "${BIN_DIR}/${cmd}" ]; then
        rm -f "${BIN_DIR}/${cmd}"
        echo "  ✓ Removed ${BIN_DIR}/${cmd}"
    fi
done

if [ "${1:-}" = "--purge" ]; then
    rm -rf "${VENV_DIR}"
    rm -rf "${HOME}/.cache/lab-import"
    echo "  ✓ Removed virtualenv and staging cache."
fi

echo "==> Uninstallation complete. Existing libvirt VMs and networks were left untouched."
