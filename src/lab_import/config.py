"""Configuration constants, paths, and dependency checks for lab-import."""

from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_LIBVIRT_URI = "qemu:///system"
DEFAULT_STORAGE_POOL = "default"
DEFAULT_STORAGE_PATH = Path("/var/lib/libvirt/images")
DEFAULT_LAB_NETWORK = "pentest-lab"
DEFAULT_LAB_BRIDGE = "virbr-lab"
DEFAULT_KALI_NAMES = ("kalilinux", "kaliLinux", "kali-linux", "kali")

# Metadata namespace stored inside libvirt domain XML
METADATA_NS_URI = "https://timsurreal.local/xmlns/lab-import/1.0"
METADATA_NS_PREFIX = "labimport"
LIBOSINFO_NS_URI = "http://libosinfo.org/xmlns/libvirt/domain/1.0"

# Archive extraction security defaults
DEFAULT_MAX_EXTRACT_BYTES = 120 * 1024 * 1024 * 1024  # 120 GiB
DEFAULT_MAX_ARCHIVE_FILES = 5000
DEFAULT_MAX_COMPRESSION_RATIO = 250.0  # Max ratio for sizable non-sparse files
MIN_SIZE_FOR_RATIO_CHECK = 10 * 1024 * 1024  # 10 MiB

# Transient VMware files that should not be extracted from archives by default
# (their presence is still recorded in ExtractionReport for lock/suspend warnings)
TRANSIENT_VMWARE_EXTENSIONS = {
    ".vmem",
    ".vmss",
    ".vmsn",
    ".dmp",
    ".log",
    ".scoreboard",
}


def get_cache_dir() -> Path:
    """Return the XDG cache directory for lab-import (on main NVMe, not /tmp tmpfs)."""
    xdg_cache = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg_cache) if xdg_cache else Path.home() / ".cache"
    path = base / "lab-import"
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def get_staging_base_dir() -> Path:
    """Return the staging root directory for archive extractions."""
    staging = get_cache_dir() / "staging"
    staging.mkdir(parents=True, exist_ok=True, mode=0o700)
    return staging


def get_state_dir() -> Path:
    """Return the XDG state directory for backups, logs, and transaction journals."""
    xdg_state = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg_state) if xdg_state else Path.home() / ".local" / "state"
    path = base / "lab-import"
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def get_backups_dir() -> Path:
    """Return the directory where domain/network XML backups are stored."""
    backups = get_state_dir() / "backups"
    backups.mkdir(parents=True, exist_ok=True, mode=0o700)
    return backups


@dataclass
class SystemDependencies:
    """Status of required and optional external tools/libraries."""

    qemu_img: str | None = None
    virsh: str | None = None
    qemu_system_x86_64: str | None = None
    virt_xml_validate: str | None = None
    virt_viewer: str | None = None
    virt_manager: str | None = None
    seven_zip: str | None = None
    bsdtar: str | None = None
    python_libvirt: bool = False
    ovmf_code_path: Path | None = None
    ovmf_vars_path: Path | None = None
    missing_required: list[str] = field(default_factory=list)
    missing_optional: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return len(self.missing_required) == 0


def detect_dependencies() -> SystemDependencies:
    """Inspect installed virtualization and archive tools on the host."""
    deps = SystemDependencies(
        qemu_img=shutil.which("qemu-img"),
        virsh=shutil.which("virsh"),
        qemu_system_x86_64=shutil.which("qemu-system-x86_64"),
        virt_xml_validate=shutil.which("virt-xml-validate"),
        virt_viewer=shutil.which("virt-viewer"),
        virt_manager=shutil.which("virt-manager"),
        seven_zip=shutil.which("7z") or shutil.which("7za"),
        bsdtar=shutil.which("bsdtar"),
    )

    try:
        import libvirt  # noqa: F401

        deps.python_libvirt = True
    except ImportError:
        deps.python_libvirt = False

    ovmf_candidates = [
        (
            Path("/usr/share/edk2/x64/OVMF_CODE.4m.fd"),
            Path("/usr/share/edk2/x64/OVMF_VARS.4m.fd"),
        ),
        (
            Path("/usr/share/edk2-ovmf/x64/OVMF_CODE.4m.fd"),
            Path("/usr/share/edk2-ovmf/x64/OVMF_VARS.4m.fd"),
        ),
        (
            Path("/usr/share/edk2/x64/OVMF_CODE.fd"),
            Path("/usr/share/edk2/x64/OVMF_VARS.fd"),
        ),
        (
            Path("/usr/share/ovmf/x64/OVMF_CODE.fd"),
            Path("/usr/share/ovmf/x64/OVMF_VARS.fd"),
        ),
    ]
    for code_path, vars_path in ovmf_candidates:
        if code_path.is_file():
            deps.ovmf_code_path = code_path
            if vars_path.is_file():
                deps.ovmf_vars_path = vars_path
            break

    if not deps.qemu_img:
        deps.missing_required.append("qemu-img (pacman -S qemu-img)")
    if not deps.virsh:
        deps.missing_required.append("virsh (pacman -S libvirt)")
    if not deps.qemu_system_x86_64:
        deps.missing_required.append("qemu-system-x86_64 (pacman -S qemu-system-x86)")
    if not deps.python_libvirt:
        deps.missing_required.append("python-libvirt (pacman -S python-libvirt)")

    if not deps.seven_zip:
        deps.missing_optional.append("7z (pacman -S 7zip) — needed only for .7z archives")
    if not deps.virt_manager:
        deps.missing_optional.append("virt-manager (pacman -S virt-manager)")
    if not deps.virt_viewer:
        deps.missing_optional.append("virt-viewer (pacman -S virt-viewer)")
    if not deps.ovmf_code_path:
        deps.missing_optional.append("edk2-ovmf (pacman -S edk2-ovmf) — needed only for UEFI guests")

    return deps


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure file and console logging for troubleshooting."""
    logger = logging.getLogger("lab_import")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    try:
        log_file = get_state_dir() / "lab-import.log"
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        logger.addHandler(fh)
    except OSError:
        pass

    if verbose:
        sh = logging.StreamHandler()
        sh.setLevel(logging.DEBUG)
        sh.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(sh)

    return logger
