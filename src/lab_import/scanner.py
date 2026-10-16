"""Flexible input detection and multi-VM discovery across archives, folders, and disks."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from .errors import AmbiguousVMSelectionError, SourceDiscoveryError
from .models import DiscoveredVM

EXTENT_SEGMENT_RE = re.compile(
    r".*-(?:[sf]\d{3,4}|flat|delta|ctk|rdm|rdmp)\.vmdk$",
    re.IGNORECASE,
)


def is_extent_segment_filename(filename: str) -> bool:
    """Return True if a .vmdk filename looks like a data extent rather than a descriptor."""
    if EXTENT_SEGMENT_RE.match(filename):
        return True
    return False


def find_parent_descriptor_for_extent(extent_path: Path) -> Path | None:
    """If the user pointed directly to LinkedBase-s001.vmdk, locate LinkedBase.vmdk."""
    m = re.match(
        r"^(?P<stem>.+)-(?:[sf]\d{3,4}|flat|delta|ctk|rdm|rdmp)\.vmdk$",
        extent_path.name,
        re.IGNORECASE,
    )
    if not m:
        return None
    stem = m.group("stem")
    candidate = extent_path.parent / f"{stem}.vmdk"
    if candidate.is_file():
        return candidate
    return None


def discover_vms_in_path(root_path: Path) -> list[DiscoveredVM]:
    """Inspect a file or directory and return all discovered VM candidates."""
    if not root_path.exists():
        raise SourceDiscoveryError(f"Input path does not exist: {root_path}")

    if root_path.is_file():
        suffix = root_path.suffix.lower()
        if suffix == ".vmx":
            return [
                DiscoveredVM(
                    name=root_path.stem,
                    vmx_path=root_path.resolve(),
                    primary_vmdk=None,
                    base_dir=root_path.parent.resolve(),
                    source_type="vmx",
                )
            ]
        if suffix == ".ovf":
            return [_discover_from_ovf(root_path.resolve())]
        if suffix == ".vmdk":
            target_vmdk = root_path.resolve()
            if is_extent_segment_filename(target_vmdk.name):
                parent_desc = find_parent_descriptor_for_extent(target_vmdk)
                if parent_desc:
                    target_vmdk = parent_desc
                else:
                    raise SourceDiscoveryError(
                        f"{target_vmdk.name!r} is a split VMDK extent segment, and its main descriptor "
                        "could not be found in the same directory.",
                        hint="Provide the main descriptor .vmdk file, the .vmx file, or the VM directory.",
                    )
            return [
                DiscoveredVM(
                    name=target_vmdk.stem,
                    vmx_path=None,
                    primary_vmdk=target_vmdk,
                    base_dir=target_vmdk.parent.resolve(),
                    source_type="standalone_vmdk",
                )
            ]
        raise SourceDiscoveryError(
            f"Unsupported input file: {root_path.name}",
            hint="Expected an archive (.zip, .tar.*, .7z, .ova), directory, .vmx, or .vmdk file.",
        )

    # Directory scan (bounded depth up to 5 levels)
    vmx_files: list[Path] = []
    ovf_files: list[Path] = []
    vmdk_files: list[Path] = []

    for p in sorted(root_path.rglob("*")):
        try:
            rel_parts = p.relative_to(root_path).parts
        except ValueError:
            continue
        if len(rel_parts) > 6:
            continue
        if any(part.lower().endswith(".lck") for part in rel_parts):
            continue
        if not p.is_file():
            continue
        name_lower = p.name.lower()
        if name_lower.endswith(".vmx") and not name_lower.endswith((".vmx.bak", ".vmx~")):
            vmx_files.append(p.resolve())
        elif name_lower.endswith(".ovf"):
            ovf_files.append(p.resolve())
        elif name_lower.endswith(".vmdk") and not is_extent_segment_filename(p.name):
            vmdk_files.append(p.resolve())

    if vmx_files:
        discovered: list[DiscoveredVM] = []
        for vmx in vmx_files:
            display = _peek_vmx_display_name(vmx) or vmx.stem
            discovered.append(
                DiscoveredVM(
                    name=display,
                    vmx_path=vmx,
                    primary_vmdk=None,
                    base_dir=vmx.parent,
                    source_type="vmx",
                )
            )
        return discovered

    if ovf_files:
        return [_discover_from_ovf(ovf) for ovf in ovf_files]

    if vmdk_files:
        # Filter out delta snapshots (-000001.vmdk) if base descriptors exist in same dir
        non_delta = [
            v for v in vmdk_files if not re.search(r"-\d{6}\.vmdk$", v.name, re.IGNORECASE)
        ]
        candidates = non_delta if non_delta else vmdk_files
        # Group VMDKs by directory or return each primary VMDK
        by_dir: dict[Path, list[Path]] = {}
        for v in candidates:
            by_dir.setdefault(v.parent, []).append(v)
        discovered_vmdks: list[DiscoveredVM] = []
        for folder, disks in by_dir.items():
            primary = disks[0]
            discovered_vmdks.append(
                DiscoveredVM(
                    name=primary.stem,
                    vmx_path=None,
                    primary_vmdk=primary,
                    base_dir=folder,
                    source_type="standalone_vmdk",
                    extra_vmdks=disks[1:],
                )
            )
        return discovered_vmdks

    raise SourceDiscoveryError(
        f"No VMware configuration (.vmx), OVF (.ovf), or virtual disk (.vmdk) found in {root_path}",
        hint="Check that the archive or directory contains a valid VMware VM.",
    )


def select_discovered_vm(
    candidates: list[DiscoveredVM],
    *,
    selector: str | None = None,
    interactive: bool = True,
    prompt_fn: callable | None = None,
) -> DiscoveredVM:
    """Select one VM from discovered candidates via selector flag or interactive prompt."""
    if not candidates:
        raise SourceDiscoveryError("No virtual machines discovered in source.")

    if len(candidates) == 1 and selector is None:
        return candidates[0]

    if selector is not None:
        # Try 1-based numeric index first
        if selector.isdigit():
            idx = int(selector)
            if 1 <= idx <= len(candidates):
                return candidates[idx - 1]
        # Try exact or case-insensitive match on VM name or filename
        sel_lower = selector.lower().strip()
        for c in candidates:
            if c.name.lower() == sel_lower:
                return c
            if c.vmx_path and (
                c.vmx_path.name.lower() == sel_lower
                or c.vmx_path.stem.lower() == sel_lower
            ):
                return c
            if c.primary_vmdk and (
                c.primary_vmdk.name.lower() == sel_lower
                or c.primary_vmdk.stem.lower() == sel_lower
            ):
                return c
        available = ", ".join(f"{i+1}:{c.name}" for i, c in enumerate(candidates))
        raise SourceDiscoveryError(
            f"No VM matching selector {selector!r} found among discovered VMs ({available}).",
            hint="Use --vm <name> or --vm <number> to choose one of the listed VMs.",
        )

    if not interactive:
        available = ", ".join(f"{i+1}: {c.name}" for i, c in enumerate(candidates))
        raise AmbiguousVMSelectionError(
            f"Multiple virtual machines found in source ({available}).",
            hint="Pass --vm <name_or_index> to select which VM to import in non-interactive mode.",
        )

    if prompt_fn is not None:
        return prompt_fn(candidates)

    raise AmbiguousVMSelectionError(
        "Multiple VMs found and no interactive prompt handler provided.",
        hint="Pass --vm <name_or_index>.",
    )


def _peek_vmx_display_name(vmx_path: Path) -> str | None:
    try:
        raw = vmx_path.read_bytes().decode("utf-8", errors="replace")
        for line in raw.splitlines():
            line = line.strip()
            if line.lower().startswith("displayname") and "=" in line:
                _, val = line.split("=", 1)
                return val.strip().strip('"')
    except OSError:
        pass
    return None


def _discover_from_ovf(ovf_path: Path) -> DiscoveredVM:
    folder = ovf_path.parent
    vmdks = sorted(
        p.resolve()
        for p in folder.glob("*.vmdk")
        if p.is_file() and not is_extent_segment_filename(p.name)
    )
    name = ovf_path.stem
    try:
        tree = ET.parse(ovf_path)
        for elem in tree.iter():
            if elem.tag.endswith("VirtualSystem"):
                id_attr = elem.attrib.get("id") or elem.attrib.get(
                    "{http://schemas.dmtf.org/ovf/envelope/1}id"
                )
                if id_attr:
                    name = id_attr
                for child in elem:
                    if child.tag.endswith("Name") and child.text:
                        name = child.text.strip()
                        break
                break
    except Exception:
        pass
    primary = vmdks[0] if vmdks else None
    extra = vmdks[1:] if len(vmdks) > 1 else []
    return DiscoveredVM(
        name=name,
        vmx_path=ovf_path,
        primary_vmdk=primary,
        base_dir=folder,
        source_type="ovf",
        extra_vmdks=extra,
    )
