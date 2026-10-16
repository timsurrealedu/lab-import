#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
VENV_DIR="${PROJECT_DIR}/.venv"

echo "==> Installing VM Lab Importer (lab-import) from ${PROJECT_DIR}"

# 1. Check required Arch Linux system tools
MISSING=()
for cmd in python3 virsh qemu-img qemu-system-x86_64; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        MISSING+=("$cmd")
    fi
done

if ! python3 -c "import libvirt" >/dev/null 2>&1; then
    MISSING+=("python-libvirt")
fi

if [ "${#MISSING[@]}" -gt 0 ]; then
    echo "Error: Missing required system packages: ${MISSING[*]}" >&2
    echo "Install them on Arch Linux with:" >&2
    echo "  sudo pacman -S libvirt python-libvirt qemu-base qemu-system-x86 python-click python-rich 7zip" >&2
    exit 1
fi

# 2. Create virtual environment inheriting system-site-packages (for C python-libvirt bindings)
python3 -m venv --system-site-packages "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --no-build-isolation --no-deps -e "${PROJECT_DIR}" >/dev/null

# 3. Symlink CLI entrypoints into ~/.local/bin
mkdir -p "${BIN_DIR}"
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
    ln -sf "${VENV_DIR}/bin/${cmd}" "${BIN_DIR}/${cmd}"
    echo "  ✓ Installed ${BIN_DIR}/${cmd}"
done

echo ""
echo "==> Running environment check (lab doctor):"
"${BIN_DIR}/lab" doctor
echo ""
echo "==> Installation complete!"
