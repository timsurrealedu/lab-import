"""Unit and integration tests for VMDK disk analysis, snapshot chains, and QCOW2 conversion."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from lab_import.disks import (
    analyze_vmdk_disk,
    convert_vmdk_to_qcow2,
    validate_qcow2_image,
)
from lab_import.errors import (
    ArchiveSecurityError,
    DiskValidationError,
    SnapshotDependencyError,
)


def test_monolithic_and_split_vmdk_analysis_and_conversion(tmp_path: Path) -> None:
    # 1. Create a real synthetic split sparse VMDK (twoGbMaxExtentSparse) using qemu-img
    split_vmdk = tmp_path / "synth_split.vmdk"
    subprocess.run(
        [
            "qemu-img",
            "create",
            "-f",
            "vmdk",
            "-o",
            "subformat=twoGbMaxExtentSparse",
            str(split_vmdk),
            "16M",
        ],
        check=True,
        capture_output=True,
    )

    analysis = analyze_vmdk_disk(split_vmdk, base_dir=tmp_path)
    assert analysis.format == "vmdk"
    assert analysis.create_type == "twoGbMaxExtentSparse"
    assert analysis.virtual_size_bytes == 16 * 1024 * 1024
    assert len(analysis.extents) >= 1
    assert all(e.exists for e in analysis.extents)
    assert analysis.has_snapshots is False

    # 2. Convert to QCOW2 and validate
    out_qcow2 = tmp_path / "synth_out.qcow2"
    progress_calls: list[float] = []
    info = convert_vmdk_to_qcow2(
        split_vmdk,
        out_qcow2,
        expected_virtual_size=analysis.virtual_size_bytes,
        progress_callback=progress_calls.append,
    )
    assert out_qcow2.is_file()
    assert int(info["virtual-size"]) == 16 * 1024 * 1024
    assert progress_calls and progress_calls[-1] == 100.0
    validate_qcow2_image(out_qcow2, expected_virtual_size=16 * 1024 * 1024)


def test_missing_vmdk_segment_detected(tmp_path: Path) -> None:
    split_vmdk = tmp_path / "broken_split.vmdk"
    subprocess.run(
        [
            "qemu-img",
            "create",
            "-f",
            "vmdk",
            "-o",
            "subformat=twoGbMaxExtentSparse",
            str(split_vmdk),
            "16M",
        ],
        check=True,
        capture_output=True,
    )
    # Delete the segment file
    seg = tmp_path / "broken_split-s001.vmdk"
    assert seg.is_file()
    seg.unlink()

    with pytest.raises(DiskValidationError, match="missing 1 segment"):
        analyze_vmdk_disk(split_vmdk, base_dir=tmp_path)


def test_malicious_vmdk_extent_path_traversal_blocked(tmp_path: Path) -> None:
    evil_vmdk = tmp_path / "evil.vmdk"
    evil_vmdk.write_text(
        '# Disk DescriptorFile\n'
        'version=1\n'
        'CID=12345678\n'
        'parentCID=ffffffff\n'
        'createType="twoGbMaxExtentSparse"\n'
        'RW 2048 FLAT "../../etc/passwd" 0\n',
        encoding="utf-8",
    )
    with pytest.raises(ArchiveSecurityError):
        analyze_vmdk_disk(evil_vmdk, base_dir=tmp_path)


def test_snapshot_chain_missing_parent_and_unreferenced_delta(tmp_path: Path) -> None:
    # 1. Missing parent in snapshot chain
    delta_vmdk = tmp_path / "vm-000001.vmdk"
    delta_vmdk.write_text(
        '# Disk DescriptorFile\n'
        'version=1\n'
        'CID=abcdef01\n'
        'parentCID=11223344\n'
        'createType="twoGbMaxExtentSparse"\n'
        'parentFileNameHint="missing_base.vmdk"\n'
        'RW 2048 SPARSE "vm-000001-s001.vmdk"\n',
        encoding="utf-8",
    )
    (tmp_path / "vm-000001-s001.vmdk").write_bytes(b"\x00" * 512)

    with pytest.raises(SnapshotDependencyError, match="missing parent disk"):
        analyze_vmdk_disk(delta_vmdk, base_dir=tmp_path)

    # 2. Unreferenced delta snapshot alongside base disk
    base_vmdk = tmp_path / "clean.vmdk"
    subprocess.run(
        ["qemu-img", "create", "-f", "vmdk", str(base_vmdk), "8M"],
        check=True,
        capture_output=True,
    )
    unref_delta = tmp_path / "clean-000001.vmdk"
    unref_delta.write_text("# dummy delta", encoding="utf-8")

    with pytest.raises(SnapshotDependencyError, match="Ambiguous snapshot state"):
        analyze_vmdk_disk(base_vmdk, base_dir=tmp_path)

    # Allowed when ignore_unreferenced_snapshots=True
    res = analyze_vmdk_disk(
        base_vmdk, base_dir=tmp_path, ignore_unreferenced_snapshots=True
    )
    assert res.virtual_size_bytes == 8 * 1024 * 1024
