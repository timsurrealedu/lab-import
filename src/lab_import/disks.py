"""VMDK disk inspection, snapshot/delta chain verification, and QCOW2 conversion."""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .errors import (
    ArchiveSecurityError,
    DiskValidationError,
    InsufficientSpaceError,
    SnapshotDependencyError,
)
from .models import VMDKAnalysis, VMDKExtentInfo
from .vmx_parser import decode_vmware_text, parse_vmsd_file, resolve_vm_Subpath

logger = logging.getLogger("lab_import.disks")

EXTENT_LINE_RE = re.compile(
    r'^(RW|RDONLY|NOACCESS)\s+(\d+)\s+(SPARSE|FLAT|VMFS|VMFSSPARSE|VMFSRAW|ZERO|SESPARSE)\s+"([^"]+)"(?:\s+(\d+))?$',
    re.IGNORECASE,
)

EFI_GPT_GUID_BYTES = bytes.fromhex("28732ac11ff8d211ba4b00a0c93ec93b")


def is_text_vmdk_descriptor(vmdk_path: Path) -> bool:
    """Return True if vmdk_path is a plain-text VMDK descriptor file."""
    try:
        with vmdk_path.open("rb") as fh:
            head = fh.read(512)
        if not head:
            return False
        # Binary VMDK magic is 'KDMV' or 'COWD'
        if head.startswith((b"KDMV", b"COWD")):
            return False
        text = head.decode("latin-1", errors="ignore")
        return "# Disk DescriptorFile" in text or "createType=" in text
    except OSError:
        return False


def parse_vmdk_descriptor_text(
    descriptor_path: Path, base_dir: Path | None = None
) -> dict[str, Any]:
    """Parse a text VMDK descriptor (or embedded descriptor) for CID, parentCID, extents, and DDB."""
    allowed_root = (base_dir or descriptor_path.parent).resolve()
    raw = descriptor_path.read_bytes()
    text = decode_vmware_text(raw)

    info: dict[str, Any] = {
        "cid": "ffffffff",
        "parent_cid": "ffffffff",
        "create_type": "monolithicSparse",
        "parent_filename_hint": None,
        "adapter_type": "lsilogic",
        "extents": [],
    }

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        m_ext = EXTENT_LINE_RE.match(line)
        if m_ext:
            access, sectors_str, ext_type, fname, _offset = m_ext.groups()
            ext_type_up = ext_type.upper()
            resolved_ext: Path | None = None
            exists = True
            actual_sz = 0
            if ext_type_up != "ZERO":
                # Resolve relative to descriptor_path.parent, but enforce within allowed_root
                resolved_ext = resolve_vm_Subpath(descriptor_path.parent, fname)
                if not resolved_ext.is_relative_to(allowed_root):
                    raise ArchiveSecurityError(
                        f"VMDK extent {fname!r} escapes VM directory {allowed_root}"
                    )
                exists = resolved_ext.is_file()
                if exists:
                    actual_sz = resolved_ext.stat().st_size

            info["extents"].append(
                VMDKExtentInfo(
                    access=access.upper(),
                    sectors=int(sectors_str),
                    extent_type=ext_type_up,
                    filename=fname,
                    resolved_path=resolved_ext,
                    exists=exists,
                    actual_size_bytes=actual_sz,
                )
            )
            continue

        if "=" in line:
            k, v = line.split("=", 1)
            k_low = k.strip().lower()
            v_clean = v.strip().strip('"')
            if k_low == "cid":
                info["cid"] = v_clean.lower()
            elif k_low == "parentcid":
                info["parent_cid"] = v_clean.lower()
            elif k_low == "createtype":
                info["create_type"] = v_clean
            elif k_low == "parentfilenamehint":
                info["parent_filename_hint"] = v_clean
            elif k_low == "ddb.adaptertype":
                info["adapter_type"] = v_clean.lower()

    return info


def analyze_vmdk_disk(
    vmdk_path: Path,
    *,
    base_dir: Path | None = None,
    vmsd_path: Path | None = None,
    ignore_unreferenced_snapshots: bool = False,
) -> VMDKAnalysis:
    """Perform comprehensive inspection of a VMDK disk, its extents, and snapshot chains."""
    if not vmdk_path.is_file():
        raise DiskValidationError(
            f"Virtual disk file not found: {vmdk_path}",
            hint="Verify that all VMDK files specified in the .vmx configuration exist.",
        )

    allowed_root = (base_dir or vmdk_path.parent).resolve()
    if not vmdk_path.resolve().is_relative_to(allowed_root):
        raise ArchiveSecurityError(
            f"VMDK path {vmdk_path} resolves outside allowed directory {allowed_root}"
        )

    analysis = VMDKAnalysis(descriptor_path=vmdk_path.resolve())

    # 1. If text descriptor, parse and validate all extents BEFORE calling qemu-img
    #    so malicious extent path traversal is caught before qemu-img opens any file!
    if is_text_vmdk_descriptor(vmdk_path):
        desc = parse_vmdk_descriptor_text(vmdk_path, allowed_root)
        analysis.cid = desc["cid"]
        analysis.parent_cid = desc["parent_cid"]
        analysis.create_type = desc["create_type"]
        analysis.parent_filename_hint = desc["parent_filename_hint"]
        analysis.adapter_type = desc["adapter_type"]
        analysis.extents = desc["extents"]

        if not analysis.extents:
            raise DiskValidationError(
                f"VMDK descriptor {vmdk_path.name} contains no extent definitions."
            )

        missing_extents = [
            e.filename for e in analysis.extents if e.extent_type != "ZERO" and not e.exists
        ]
        if missing_extents:
            raise DiskValidationError(
                f"VMDK {vmdk_path.name} is missing {len(missing_extents)} segment file(s): "
                + ", ".join(missing_extents),
                hint="Ensure the archive or folder was completely downloaded/extracted.",
            )

    # 2. Verify snapshot/backing chain if parentCID != ffffffff or parentFileNameHint is set
    chain = _verify_and_walk_snapshot_chain(vmdk_path, analysis, allowed_root)
    analysis.backing_chain = chain
    if len(chain) > 1:
        analysis.has_snapshots = True
        analysis.snapshot_details.append(
            " -> ".join(p.name for p in chain)
        )

    # 3. Inspect .vmsd and check for unreferenced delta disks (-000001.vmdk) in the folder
    _check_vmsd_and_unreferenced_deltas(
        vmdk_path,
        analysis,
        allowed_root,
        vmsd_path=vmsd_path,
        ignore_unreferenced_snapshots=ignore_unreferenced_snapshots,
    )

    # 4. Run qemu-img info --output=json to validate readability & compute exact sizes
    qinfo = run_qemu_img_info(vmdk_path)
    analysis.format = qinfo.get("format", "vmdk")
    analysis.virtual_size_bytes = int(qinfo.get("virtual-size", 0))
    if analysis.virtual_size_bytes <= 0:
        raise DiskValidationError(
            f"VMDK {vmdk_path.name} reported invalid virtual size: {analysis.virtual_size_bytes}"
        )

    fmt_data = qinfo.get("format-specific", {}).get("data", {})
    if fmt_data.get("create-type"):
        analysis.create_type = fmt_data["create-type"]
    if fmt_data.get("cid") is not None and analysis.cid == "ffffffff":
        analysis.cid = f"{int(fmt_data['cid']):08x}"
    if fmt_data.get("parent-cid") is not None and analysis.parent_cid == "ffffffff":
        analysis.parent_cid = f"{int(fmt_data['parent-cid']):08x}"

    # Calculate total actual size across all extents and backing files
    if analysis.extents:
        total_actual = vmdk_path.stat().st_size + sum(
            e.actual_size_bytes for e in analysis.extents
        )
        # Also include backing chain files if snapshots exist
        for parent_p in analysis.backing_chain[1:]:
            if is_text_vmdk_descriptor(parent_p):
                p_desc = parse_vmdk_descriptor_text(parent_p, allowed_root)
                total_actual += parent_p.stat().st_size + sum(
                    e.actual_size_bytes for e in p_desc["extents"]
                )
            elif parent_p.is_file():
                total_actual += parent_p.stat().st_size
        analysis.actual_size_bytes = total_actual
    else:
        analysis.actual_size_bytes = int(
            qinfo.get("actual-size") or vmdk_path.stat().st_size
        )

    # 5. Best-effort check for GPT EFI System Partition (helpful for standalone VMDKs)
    analysis.has_efi_partition = _detect_efi_partition(vmdk_path, analysis)

    return analysis


def _verify_and_walk_snapshot_chain(
    leaf_vmdk: Path, analysis: VMDKAnalysis, allowed_root: Path
) -> list[Path]:
    """Walk parentFileNameHint links and ensure every backing VMDK & extent is valid and safe."""
    chain: list[Path] = [leaf_vmdk.resolve()]
    visited: set[Path] = {leaf_vmdk.resolve()}

    curr_path = leaf_vmdk.resolve()
    curr_parent_cid = analysis.parent_cid
    curr_parent_hint = analysis.parent_filename_hint

    # If binary monolithic delta VMDK, inspect header or qemu-img for backing-filename
    if not is_text_vmdk_descriptor(curr_path):
        header_info = _peek_binary_vmdk_descriptor(curr_path)
        if header_info:
            curr_parent_cid = header_info.get("parent_cid", "ffffffff")
            curr_parent_hint = header_info.get("parent_filename_hint")
            analysis.cid = header_info.get("cid", analysis.cid)
            analysis.parent_cid = curr_parent_cid
            analysis.parent_filename_hint = curr_parent_hint

    while curr_parent_cid != "ffffffff" or curr_parent_hint:
        if curr_parent_cid != "ffffffff" and not curr_parent_hint:
            raise SnapshotDependencyError(
                f"Delta VMDK {curr_path.name} has parentCID={curr_parent_cid} "
                "but no parentFileNameHint.",
                hint="Snapshot chain is incomplete; cannot safely reconstruct disk state.",
            )
        assert curr_parent_hint is not None
        parent_path = resolve_vm_Subpath(curr_path.parent, curr_parent_hint)
        if not parent_path.is_relative_to(allowed_root):
            raise ArchiveSecurityError(
                f"Snapshot parent {curr_parent_hint!r} resolves outside VM directory {allowed_root}"
            )
        if not parent_path.is_file():
            raise SnapshotDependencyError(
                f"Snapshot delta disk {curr_path.name} depends on missing parent disk "
                f"{curr_parent_hint!r} (expected at {parent_path}).",
                hint=(
                    "Do not import an incomplete snapshot chain. Consolidate snapshots in "
                    "VMware or provide all parent VMDK files."
                ),
            )
        if parent_path in visited:
            raise SnapshotDependencyError(
                f"Circular snapshot backing chain detected involving {parent_path.name}."
            )
        visited.add(parent_path)
        chain.append(parent_path)

        if is_text_vmdk_descriptor(parent_path):
            p_desc = parse_vmdk_descriptor_text(parent_path, allowed_root)
            missing = [
                e.filename for e in p_desc["extents"] if e.extent_type != "ZERO" and not e.exists
            ]
            if missing:
                raise SnapshotDependencyError(
                    f"Parent snapshot disk {parent_path.name} is missing extent(s): {', '.join(missing)}"
                )
            if curr_parent_cid != "ffffffff" and p_desc["cid"] != curr_parent_cid:
                raise SnapshotDependencyError(
                    f"Snapshot CID mismatch: {curr_path.name} expects parentCID={curr_parent_cid}, "
                    f"but {parent_path.name} has CID={p_desc['cid']}.",
                    hint="The parent disk was modified independently of the child snapshot.",
                )
            curr_parent_cid = p_desc["parent_cid"]
            curr_parent_hint = p_desc["parent_filename_hint"]
            curr_path = parent_path
        else:
            p_hdr = _peek_binary_vmdk_descriptor(parent_path)
            if p_hdr:
                if (
                    curr_parent_cid != "ffffffff"
                    and p_hdr.get("cid", "ffffffff") != curr_parent_cid
                ):
                    raise SnapshotDependencyError(
                        f"Snapshot CID mismatch: {curr_path.name} expects parentCID={curr_parent_cid}, "
                        f"but {parent_path.name} has CID={p_hdr.get('cid')}."
                    )
                curr_parent_cid = p_hdr.get("parent_cid", "ffffffff")
                curr_parent_hint = p_hdr.get("parent_filename_hint")
                curr_path = parent_path
            else:
                break

    return chain


def _peek_binary_vmdk_descriptor(vmdk_path: Path) -> dict[str, Any] | None:
    """Extract embedded ASCII descriptor from a monolithicSparse binary VMDK header."""
    try:
        with vmdk_path.open("rb") as fh:
            head = fh.read(32768)
        if not head.startswith(b"KDMV"):
            return None
        # Embedded descriptor usually starts at sector 1 (offset 512)
        desc_chunk = head[512:].split(b"\x00", 1)[0]
        text = desc_chunk.decode("latin-1", errors="ignore")
        if "# Disk DescriptorFile" not in text and "createType=" not in text:
            return None
        info: dict[str, Any] = {
            "cid": "ffffffff",
            "parent_cid": "ffffffff",
            "parent_filename_hint": None,
        }
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                k_low = k.strip().lower()
                v_clean = v.strip().strip('"')
                if k_low == "cid":
                    info["cid"] = v_clean.lower()
                elif k_low == "parentcid":
                    info["parent_cid"] = v_clean.lower()
                elif k_low == "parentfilenamehint":
                    info["parent_filename_hint"] = v_clean
        return info
    except OSError:
        return None


def _check_vmsd_and_unreferenced_deltas(
    vmdk_path: Path,
    analysis: VMDKAnalysis,
    allowed_root: Path,
    *,
    vmsd_path: Path | None = None,
    ignore_unreferenced_snapshots: bool = False,
) -> None:
    """Detect ambiguous snapshot states or unreferenced delta disks (-000001.vmdk)."""
    folder = vmdk_path.parent
    stem = re.sub(r"-\d{6}$", "", vmdk_path.stem)
    delta_pattern = re.compile(
        rf"^{re.escape(stem)}-\d{{6}}\.vmdk$", re.IGNORECASE
    )
    chain_set = {p.resolve() for p in analysis.backing_chain}

    unreferenced: list[Path] = []
    for p in sorted(folder.glob("*.vmdk")):
        if delta_pattern.match(p.name) and p.resolve() not in chain_set:
            unreferenced.append(p.resolve())

    analysis.unreferenced_deltas = unreferenced

    if vmsd_path and vmsd_path.is_file() and vmsd_path.stat().st_size > 0:
        vmsd_data = parse_vmsd_file(vmsd_path)
        num_snaps = vmsd_data.get("num_snapshots", 0)
        if num_snaps > 0:
            analysis.has_snapshots = True
            for s in vmsd_data.get("snapshots", []):
                analysis.snapshot_details.append(
                    f"Snapshot {s['index']} (uid={s['uid']}): {s['display_name']!r}"
                )

    if unreferenced and not ignore_unreferenced_snapshots:
        names = ", ".join(p.name for p in unreferenced)
        raise SnapshotDependencyError(
            f"Ambiguous snapshot state for {vmdk_path.name}: found delta snapshot disk(s) "
            f"({names}) that are not referenced by the active disk configuration.",
            hint=(
                "The VM directory contains snapshot delta disks outside the active disk chain. "
                "To import a specific snapshot leaf disk directly, pass its .vmdk path, or pass "
                "--ignore-unreferenced-snapshots to import only the currently referenced disk chain."
            ),
        )


def _detect_efi_partition(vmdk_path: Path, analysis: VMDKAnalysis) -> bool:
    """Check the first extent or monolithic file for a GPT EFI System Partition GUID."""
    target_file = vmdk_path
    if analysis.extents and analysis.extents[0].resolved_path:
        target_file = analysis.extents[0].resolved_path
    try:
        with target_file.open("rb") as fh:
            chunk = fh.read(2 * 1024 * 1024)
        return EFI_GPT_GUID_BYTES in chunk
    except OSError:
        return False


def run_qemu_img_info(image_path: Path) -> dict[str, Any]:
    """Run `qemu-img info --output=json` and return parsed JSON."""
    proc = subprocess.run(
        ["qemu-img", "info", "--output=json", str(image_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise DiskValidationError(
            f"qemu-img info failed on {image_path.name}: {proc.stderr.strip()}",
            hint="The virtual disk descriptor or one of its extents may be corrupted.",
        )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise DiskValidationError(
            f"Failed to parse qemu-img info JSON output for {image_path.name}"
        ) from exc


def validate_qcow2_image(qcow2_path: Path, expected_virtual_size: int | None = None) -> dict[str, Any]:
    """Validate a converted QCOW2 image using `qemu-img check` and `qemu-img info`."""
    if not qcow2_path.is_file():
        raise DiskValidationError(f"Converted QCOW2 image does not exist: {qcow2_path}")

    info = run_qemu_img_info(qcow2_path)
    if info.get("format") != "qcow2":
        raise DiskValidationError(
            f"Expected format 'qcow2' for {qcow2_path.name}, got {info.get('format')!r}"
        )

    vsize = int(info.get("virtual-size", 0))
    if expected_virtual_size is not None and vsize != expected_virtual_size:
        raise DiskValidationError(
            f"Converted QCOW2 virtual size mismatch: expected {expected_virtual_size} bytes, got {vsize} bytes"
        )

    proc = subprocess.run(
        ["qemu-img", "check", "--output=json", str(qcow2_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    # Exit code 0 = no errors; exit code 3 = leaks found but no corruption
    if proc.returncode not in (0, 3):
        raise DiskValidationError(
            f"QCOW2 integrity check failed on {qcow2_path.name}: "
            f"{proc.stderr.strip() or proc.stdout.strip()}"
        )
    return info


def check_storage_space_for_conversion(
    target_dir: Path, required_bytes: int, safety_margin_bytes: int = 1024 * 1024 * 1024
) -> None:
    """Verify target_dir has enough free space for disk conversion."""
    check_dir = target_dir if target_dir.exists() else target_dir.parent
    usage = shutil.disk_usage(check_dir)
    needed = required_bytes + safety_margin_bytes
    if usage.free < needed:
        raise InsufficientSpaceError(
            f"Insufficient free disk space in {check_dir}: "
            f"requires at least {needed / (1024**3):.2f} GiB, "
            f"only {usage.free / (1024**3):.2f} GiB available."
        )


def convert_vmdk_to_qcow2(
    source_vmdk: Path,
    target_qcow2: Path,
    *,
    skip_create: bool = False,
    expected_virtual_size: int | None = None,
    progress_callback: Callable[[float], None] | None = None,
) -> dict[str, Any]:
    """Convert a VMDK (monolithic, split, or snapshot chain) to a standalone QCOW2 image.

    If `skip_create=True`, passes `-n` to `qemu-img convert` so it writes into a
    pre-created libvirt storage pool volume without requiring root directory write access.
    """
    if source_vmdk.resolve() == target_qcow2.resolve():
        raise DiskValidationError("Source VMDK and target QCOW2 paths must be distinct.")

    cmd = ["qemu-img", "convert", "-p", "-f", "vmdk", "-O", "qcow2"]
    if skip_create:
        cmd.append("-n")
    cmd.extend([str(source_vmdk), str(target_qcow2)])

    logger.debug("Running disk conversion: %s", " ".join(cmd))
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )

    progress_re = re.compile(rb"\((\d+(?:\.\d+)?)/100%\)")
    try:
        assert proc.stdout is not None
        buf = b""
        while True:
            ch = proc.stdout.read(64)
            if not ch:
                break
            buf += ch
            matches = progress_re.findall(buf)
            if matches and progress_callback:
                pct = float(matches[-1].decode("ascii"))
                progress_callback(pct)
            if len(buf) > 256:
                buf = buf[-128:]
        _, stderr_bytes = proc.communicate()
    except BaseException:
        proc.kill()
        proc.wait()
        raise

    if proc.returncode != 0:
        err_msg = stderr_bytes.decode("utf-8", errors="replace").strip()
        raise DiskValidationError(
            f"qemu-img convert failed for {source_vmdk.name}: {err_msg}",
            hint="Check disk space, permissions, and VMDK segment integrity.",
        )

    if progress_callback:
        progress_callback(100.0)

    return validate_qcow2_image(target_qcow2, expected_virtual_size=expected_virtual_size)
