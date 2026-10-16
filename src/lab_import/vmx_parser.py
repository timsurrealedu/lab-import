"""Parser for VMware .vmx and .vmsd configuration files and active lock/suspend state checks."""

from __future__ import annotations

import logging
import os
import re
import subprocess
from pathlib import Path, PureWindowsPath
from typing import Any

from .errors import ArchiveSecurityError, VMStateConflictError, VMXParseError
from .models import (
    VMXConfig,
    VMXControllerSpec,
    VMXDiskSpec,
    VMXNicSpec,
)

logger = logging.getLogger("lab_import.vmx_parser")

CONTROLLER_BUS_TYPES = ("scsi", "sata", "ide", "nvme")
NON_HARDDISK_DEVICE_TYPES = {
    "cdrom-image",
    "cdrom-raw",
    "atapi-cdrom",
    "rawdisk",
    "floppy",
}


def decode_vmware_text(raw_bytes: bytes) -> str:
    """Decode a .vmx or .vmsd file honoring its .encoding header or common encodings."""
    # Peek first 256 bytes for .encoding = "..."
    header = raw_bytes[:256].decode("ascii", errors="ignore")
    m = re.search(r'\.encoding\s*=\s*"([^"]+)"', header, re.IGNORECASE)
    encodings = []
    if m:
        encodings.append(m.group(1).strip())
    encodings.extend(["utf-8-sig", "utf-8", "windows-1252", "latin-1"])
    for enc in encodings:
        try:
            return raw_bytes.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def parse_vmx_kv_lines(text: str) -> dict[str, str]:
    """Parse key = "value" lines from a .vmx or .vmsd file (storing lowercase keys)."""
    entries: dict[str, str] = {}
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//") or line.startswith("!"):
            continue
        if "=" not in line:
            raise VMXParseError(
                f"Malformed line {line_no} in VMware configuration: {raw_line!r}",
                hint="Every non-comment line in a .vmx file must be in 'key = \"value\"' format.",
            )
        key_part, val_part = line.split("=", 1)
        key = key_part.strip()
        if not key:
            raise VMXParseError(f"Empty key on line {line_no} in VMware configuration.")
        val = val_part.strip()
        if len(val) >= 2 and val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        entries[key.lower()] = val
    return entries


def parse_vmx_file(vmx_path: Path) -> VMXConfig:
    """Parse a .vmx file into a structured VMXConfig dataclass."""
    if not vmx_path.is_file():
        raise VMXParseError(f"VMX configuration file not found: {vmx_path}")

    raw_bytes = vmx_path.read_bytes()
    if not raw_bytes.strip():
        raise VMXParseError(f"VMX configuration file is empty: {vmx_path}")

    text = decode_vmware_text(raw_bytes)
    entries = parse_vmx_kv_lines(text)

    if not entries:
        raise VMXParseError(f"VMX file contains no valid configuration entries: {vmx_path}")

    display_name = entries.get("displayname", "").strip() or vmx_path.stem
    guest_os = entries.get("guestos", "other-64").strip()
    guest_os_detailed = (
        entries.get("guestos.detailed.data", "").strip()
        or entries.get("guestinfo.detailed.data", "").strip()
    )

    num_vcpus = _parse_positive_int(entries.get("numvcpus"), default=1, field_name="numvcpus")
    cores_per_socket = _parse_positive_int(
        entries.get("cpuid.corespersocket"), default=1, field_name="cpuid.coresPerSocket"
    )
    memory_mb = _parse_positive_int(entries.get("memsize"), default=2048, field_name="memsize")

    firmware_raw = entries.get("firmware", "bios").strip().lower()
    firmware = "efi" if firmware_raw == "efi" else "bios"
    secure_boot = _parse_bool(entries.get("uefi.secureboot.enabled"), default=False)
    hw_version = _parse_positive_int(
        entries.get("virtualhw.version"), default=18, field_name="virtualHW.version"
    )

    uuid_bios = entries.get("uuid.bios", "").strip()
    clean_shutdown = _parse_bool(entries.get("cleanshutdown"), default=True)
    soft_power_off = _parse_bool(entries.get("softpoweroff"), default=True)
    checkpoint_vmstate = entries.get("checkpoint.vmstate", "").strip()

    pci_bridge0_present = _parse_bool(entries.get("pcibridge0.present"), default=False)
    pci_bridge0_slot = _parse_optional_slot(entries.get("pcibridge0.pcislotnumber"))

    controllers = _extract_controllers(entries)
    disks, disk_warnings = _extract_disks(entries, vmx_path.parent)
    nics = _extract_nics(entries)

    cfg = VMXConfig(
        vmx_path=vmx_path.resolve(),
        display_name=display_name,
        guest_os=guest_os,
        guest_os_detailed=guest_os_detailed,
        num_vcpus=num_vcpus,
        cores_per_socket=cores_per_socket,
        memory_mb=memory_mb,
        firmware=firmware,
        secure_boot=secure_boot,
        virtual_hw_version=hw_version,
        uuid_bios=uuid_bios,
        clean_shutdown=clean_shutdown,
        soft_power_off=soft_power_off,
        checkpoint_vmstate=checkpoint_vmstate,
        pci_bridge0_present=pci_bridge0_present,
        pci_bridge0_slot=pci_bridge0_slot,
        controllers=controllers,
        disks=disks,
        nics=nics,
        raw_entries=entries,
        warnings=disk_warnings,
    )
    return cfg


def build_synthetic_vmx_from_vmdk(
    vmdk_path: Path,
    *,
    extra_vmdks: list[Path] | None = None,
    name: str | None = None,
    vcpus: int = 2,
    memory_mb: int = 2048,
    firmware: str = "bios",
    guest_os: str = "other-64",
) -> VMXConfig:
    """Create a synthetic VMXConfig when importing a standalone VMDK without a .vmx."""
    all_vmdks = [vmdk_path.resolve()] + [p.resolve() for p in (extra_vmdks or [])]
    disks = [
        VMXDiskSpec(
            bus_type="scsi",
            controller_index=0,
            unit_index=idx,
            file_name=p.name,
            resolved_path=p,
            device_type="disk",
            present=True,
        )
        for idx, p in enumerate(all_vmdks)
    ]
    return VMXConfig(
        vmx_path=None,
        display_name=name or vmdk_path.stem,
        guest_os=guest_os,
        num_vcpus=vcpus,
        memory_mb=memory_mb,
        firmware=firmware,
        pci_bridge0_present=True,
        pci_bridge0_slot=17,
        controllers=[
            VMXControllerSpec(bus_type="scsi", index=0, virtual_dev="lsilogic", present=True)
        ],
        disks=disks,
        nics=[
            VMXNicSpec(
                index=0,
                virtual_dev="e1000",
                connection_type="nat",
                pci_slot=33,
                present=True,
            )
        ],
        warnings=[
            "No .vmx configuration file provided; using safe default hardware settings for standalone VMDK."
        ],
    )


def _extract_controllers(entries: dict[str, str]) -> list[VMXControllerSpec]:
    controllers: list[VMXControllerSpec] = []
    for bus in CONTROLLER_BUS_TYPES:
        for idx in range(4):
            prefix = f"{bus}{idx}"
            present_str = entries.get(f"{prefix}.present")
            vdev = entries.get(f"{prefix}.virtualdev", "")
            if present_str is None and not vdev:
                continue
            present = _parse_bool(present_str, default=True)
            if not present:
                continue
            default_dev = {
                "scsi": "lsilogic",
                "sata": "ahci",
                "ide": "piix4",
                "nvme": "nvme",
            }[bus]
            controllers.append(
                VMXControllerSpec(
                    bus_type=bus,
                    index=idx,
                    virtual_dev=(vdev or default_dev).lower(),
                    present=True,
                    pci_slot=_parse_optional_slot(entries.get(f"{prefix}.pcislotnumber")),
                )
            )
    return controllers


def _extract_disks(
    entries: dict[str, str], base_dir: Path
) -> tuple[list[VMXDiskSpec], list[str]]:
    disks: list[VMXDiskSpec] = []
    warnings: list[str] = []

    # Match keys like scsi0:0.filename, sata0:1.filename, ide0:0.filename, nvme0:0.filename
    disk_key_re = re.compile(r"^(scsi|sata|ide|nvme)(\d+):(\d+)\.filename$")
    for key, file_name in sorted(entries.items()):
        m = disk_key_re.match(key)
        if not m:
            continue
        bus_type, ctrl_str, unit_str = m.group(1), m.group(2), m.group(3)
        ctrl_idx, unit_idx = int(ctrl_str), int(unit_str)
        prefix = f"{bus_type}{ctrl_idx}:{unit_idx}"

        present = _parse_bool(entries.get(f"{prefix}.present"), default=True)
        if not present:
            continue

        dev_type = entries.get(f"{prefix}.devicetype", "disk").strip().lower()
        file_lower = file_name.strip().lower()

        # Skip CD-ROM drives, ISO images, floppy images, or host physical drives
        if (
            dev_type in NON_HARDDISK_DEVICE_TYPES
            or file_lower.endswith((".iso", ".flp", ".img"))
            or file_lower in ("auto detect", "nul", "")
        ):
            if file_lower.endswith(".iso"):
                warnings.append(
                    f"Ignoring optical/ISO drive attachment {prefix} ({file_name!r})."
                )
            continue

        redo_file = entries.get(f"{prefix}.redo", "").strip()
        resolved = resolve_vm_Subpath(base_dir, file_name)

        disks.append(
            VMXDiskSpec(
                bus_type=bus_type,
                controller_index=ctrl_idx,
                unit_index=unit_idx,
                file_name=file_name,
                resolved_path=resolved,
                device_type=dev_type,
                present=True,
                redo_file=redo_file,
            )
        )

    return disks, warnings


def resolve_vm_Subpath(base_dir: Path, raw_file_name: str) -> Path:
    """Safely resolve a disk or NVRAM filename referenced inside a .vmx or .vmdk."""
    cleaned = raw_file_name.strip().strip('"')
    # Reject absolute Unix paths or path traversal
    if cleaned.startswith("/"):
        raise ArchiveSecurityError(
            f"VM configuration references an absolute host path: {raw_file_name!r}",
            hint="External absolute file references in untrusted VM configs are blocked.",
        )
    # If a Windows path was saved (e.g., D:\folder\disk.vmdk), check if the basename exists locally
    if re.match(r"^[a-zA-Z]:[\\/]", cleaned):
        win_name = PureWindowsPath(cleaned).name
        candidate = (base_dir / win_name).resolve()
        if candidate.is_relative_to(base_dir.resolve()):
            return candidate
        raise ArchiveSecurityError(
            f"VM configuration references external Windows path: {raw_file_name!r}"
        )

    normalized = cleaned.replace("\\", "/")
    parts = [p for p in normalized.split("/") if p and p != "."]
    if ".." in parts:
        raise ArchiveSecurityError(
            f"VM configuration references parent directory traversal ('..'): {raw_file_name!r}"
        )
    resolved = base_dir.resolve().joinpath(*parts).resolve(strict=False)
    if not resolved.is_relative_to(base_dir.resolve()):
        raise ArchiveSecurityError(
            f"VM configuration file path escapes VM directory: {raw_file_name!r}"
        )
    return resolved


def _extract_nics(entries: dict[str, str]) -> list[VMXNicSpec]:
    nics: list[VMXNicSpec] = []
    for idx in range(10):
        prefix = f"ethernet{idx}"
        present_str = entries.get(f"{prefix}.present")
        if present_str is None and f"{prefix}.virtualdev" not in entries:
            continue
        present = _parse_bool(present_str, default=True)
        if not present:
            continue
        vdev = entries.get(f"{prefix}.virtualdev", "e1000").strip().lower()
        conn_type = entries.get(f"{prefix}.connectiontype", "nat").strip().lower()
        addr_type = entries.get(f"{prefix}.addresstype", "generated").strip().lower()
        mac = (
            entries.get(f"{prefix}.address", "").strip()
            or entries.get(f"{prefix}.generatedaddress", "").strip()
            or None
        )
        pci_slot = _parse_optional_slot(entries.get(f"{prefix}.pcislotnumber"))
        nics.append(
            VMXNicSpec(
                index=idx,
                virtual_dev=vdev,
                connection_type=conn_type,
                address_type=addr_type,
                mac_address=mac,
                pci_slot=pci_slot,
                present=True,
            )
        )
    if not nics:
        # Provide one default e1000 NIC if none declared
        nics.append(
            VMXNicSpec(
                index=0,
                virtual_dev="e1000",
                connection_type="nat",
                pci_slot=33,
                present=True,
            )
        )
    return nics


def parse_vmsd_file(vmsd_path: Path) -> dict[str, Any]:
    """Parse a VMware .vmsd snapshot descriptor file."""
    result: dict[str, Any] = {
        "num_snapshots": 0,
        "current_uid": "",
        "snapshots": [],
        "raw": {},
    }
    if not vmsd_path.is_file() or vmsd_path.stat().st_size == 0:
        return result

    text = decode_vmware_text(vmsd_path.read_bytes())
    entries = parse_vmx_kv_lines(text)
    result["raw"] = entries
    num_snaps = _parse_positive_int(
        entries.get("snapshot.numsnapshots"), default=0, allow_zero=True
    )
    result["num_snapshots"] = num_snaps
    result["current_uid"] = entries.get("snapshot.current", "")

    for i in range(num_snaps):
        prefix = f"snapshot{i}"
        snap_info = {
            "index": i,
            "uid": entries.get(f"{prefix}.uid", ""),
            "parent": entries.get(f"{prefix}.parent", ""),
            "display_name": entries.get(f"{prefix}.displayname", f"Snapshot {i}"),
            "filename": entries.get(f"{prefix}.filename", ""),
            "disks": [],
        }
        for d_idx in range(10):
            d_file = entries.get(f"{prefix}.disk{d_idx}.filename")
            if d_file:
                snap_info["disks"].append(
                    {
                        "node": entries.get(f"{prefix}.disk{d_idx}.node", ""),
                        "filename": d_file,
                    }
                )
        result["snapshots"].append(snap_info)

    return result


def check_source_vm_runtime_state(
    vm_dir: Path,
    vmx_config: VMXConfig,
    *,
    allow_suspended: bool = False,
    force: bool = False,
) -> list[str]:
    """Check whether the VMware VM is actively running on this host or suspended.

    Distinguishes between:
    1. Actively running local `vmware-vmx` processes holding this VM open -> error.
    2. Suspended `.vmss` checkpoint state (`checkpoint.vmState`) -> error unless allow_suspended/force.
    3. Stale `.lck` / `.vmem` files packaged inside an archive from another machine -> warning only.
    """
    warnings: list[str] = []
    vm_dir_resolved = str(vm_dir.resolve())

    # 1. Check active local vmware-vmx processes
    if _is_vmware_vmx_running_for_dir(vm_dir_resolved) and not force:
        raise VMStateConflictError(
            f"Source VM {vmx_config.display_name!r} is currently running in VMware on this host.",
            hint="Shut down the VM cleanly in VMware Workstation/Player before importing.",
        )

    # 2. Check suspended state (.vmss)
    if vmx_config.checkpoint_vmstate:
        vmss_path = vm_dir / vmx_config.checkpoint_vmstate
        if not (allow_suspended or force):
            raise VMStateConflictError(
                f"Source VM {vmx_config.display_name!r} is in a suspended state "
                f"(checkpoint.vmState = {vmx_config.checkpoint_vmstate!r}).",
                hint=(
                    "Resume and cleanly shut down the VM in VMware first, or pass "
                    "--allow-suspended to import the disk state (discarding unsaved RAM state)."
                ),
            )
        warnings.append(
            f"Source VM had suspended state ({vmss_path.name}); RAM state is discarded during KVM conversion."
        )

    # 3. Check for stale .lck / .vmem / unclean shutdown indicators
    lck_paths = list(vm_dir.glob("*.lck"))
    vmem_paths = list(vm_dir.glob("*.vmem"))
    if lck_paths or vmem_paths or not vmx_config.clean_shutdown:
        warnings.append(
            "Source VM had stale lock/paging files or cleanShutdown=FALSE from a prior VMware session; "
            "the guest OS will automatically replay its filesystem journal on first boot."
        )

    return warnings


def _is_vmware_vmx_running_for_dir(vm_dir_resolved: str) -> bool:
    """Return True if a local vmware-vmx process on this host is running a VM from vm_dir."""
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return False
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline_bytes = (entry / "cmdline").read_bytes()
            if not cmdline_bytes:
                continue
            cmdline = cmdline_bytes.decode("utf-8", errors="ignore").replace("\x00", " ")
            if "vmware-vmx" in cmdline and vm_dir_resolved in cmdline:
                return True
        except OSError:
            continue
    return False


def _parse_positive_int(
    raw: str | None,
    *,
    default: int,
    field_name: str = "value",
    allow_zero: bool = False,
) -> int:
    if raw is None or raw.strip() == "":
        return default
    try:
        val = int(raw.strip())
    except ValueError as exc:
        raise VMXParseError(
            f"Invalid integer for {field_name} in .vmx: {raw!r}"
        ) from exc
    if (allow_zero and val < 0) or (not allow_zero and val <= 0):
        raise VMXParseError(
            f"Invalid non-positive value for {field_name} in .vmx: {val}"
        )
    return val


def _parse_optional_slot(raw: str | None) -> int | None:
    if raw is None or raw.strip() == "":
        return None
    try:
        val = int(raw.strip())
        return val if val >= 0 else None
    except ValueError:
        return None


def _parse_bool(raw: str | None, *, default: bool) -> bool:
    if raw is None:
        return default
    norm = raw.strip().lower()
    if norm in ("true", "yes", "1"):
        return True
    if norm in ("false", "no", "0"):
        return False
    return default
