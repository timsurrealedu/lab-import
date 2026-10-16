"""Unit and security tests for archive inspection and extraction."""

from __future__ import annotations

import io
import os
import shutil
import stat
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

from lab_import.errors import ArchiveSecurityError, ExtractionError, InsufficientSpaceError
from lab_import.extractor import (
    StagingWorkspace,
    extract_archive_safely,
    inspect_archive_members,
    validate_safe_relative_path,
)


def test_validate_safe_relative_path_blocks_traversal(tmp_path: Path) -> None:
    with pytest.raises(ArchiveSecurityError):
        validate_safe_relative_path("../../etc/passwd", tmp_path)
    with pytest.raises(ArchiveSecurityError):
        validate_safe_relative_path("vm/../../../etc/shadow", tmp_path)
    with pytest.raises(ArchiveSecurityError):
        validate_safe_relative_path("/etc/passwd", tmp_path)
    with pytest.raises(ArchiveSecurityError):
        validate_safe_relative_path("C:\\Windows\\System32\\cmd.exe", tmp_path)
    with pytest.raises(ArchiveSecurityError):
        validate_safe_relative_path("vm\\..\\..\\secret.txt", tmp_path)
    with pytest.raises(ArchiveSecurityError):
        validate_safe_relative_path("bad\x00file.vmx", tmp_path)


def test_zip_slip_rejected(tmp_path: Path) -> None:
    zip_path = tmp_path / "malicious.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../escaped.txt", "pwned")

    with pytest.raises(ArchiveSecurityError):
        inspect_archive_members(zip_path)


def test_zip_symlink_rejected(tmp_path: Path) -> None:
    zip_path = tmp_path / "symlink.zip"
    info = zipfile.ZipInfo("vm/evil_link")
    info.create_system = 3  # Unix
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(info, "/etc/passwd")

    with pytest.raises(ArchiveSecurityError, match="symbolic or hard link"):
        inspect_archive_members(zip_path)


def test_tar_symlink_and_device_rejected(tmp_path: Path) -> None:
    tar_path = tmp_path / "symlink.tar"
    with tarfile.open(tar_path, "w") as tf:
        ti = tarfile.TarInfo("vm/link_to_etc")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "/etc/shadow"
        tf.addfile(ti)

    with pytest.raises(ArchiveSecurityError, match="symbolic or hard link"):
        inspect_archive_members(tar_path)

    fifo_tar = tmp_path / "fifo.tar"
    with tarfile.open(fifo_tar, "w") as tf:
        ti = tarfile.TarInfo("vm/named_pipe")
        ti.type = tarfile.FIFOTYPE
        tf.addfile(ti)

    with pytest.raises(ArchiveSecurityError, match="special device"):
        inspect_archive_members(fifo_tar)


def test_archive_bomb_file_count_and_size_limits(tmp_path: Path) -> None:
    zip_path = tmp_path / "many.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        for i in range(15):
            zf.writestr(f"vm/file_{i}.txt", "hello")

    with pytest.raises(ArchiveSecurityError, match="exceeding safety limit"):
        inspect_archive_members(zip_path, max_files=10)

    with pytest.raises(ArchiveSecurityError, match="uncompressed size"):
        inspect_archive_members(zip_path, max_bytes=20)


def test_safe_zip_extraction_strips_exec_bits_and_skips_transient(tmp_path: Path) -> None:
    zip_path = tmp_path / "valid_vm.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        info = zipfile.ZipInfo("TestVM/TestVM.vmx")
        info.create_system = 3
        # Attempt to set setuid + rwxrwxrwx inside archive
        info.external_attr = (stat.S_IFREG | stat.S_ISUID | 0o777) << 16
        zf.writestr(info, '.encoding = "UTF-8"\ndisplayName = "TestVM"\n')
        zf.writestr("TestVM/TestVM.vmdk", "# Disk DescriptorFile\n")
        zf.writestr("TestVM/TestVM.vmem", "paging_data")
        zf.writestr("TestVM/TestVM.vmdk.lck/M123.lck", "lock_data")
        zf.writestr("TestVM/vmware.log", "log_data")

    staging = tmp_path / "staging"
    report = extract_archive_safely(zip_path, staging, skip_transient=True)

    assert report.had_lock_files is True
    assert report.had_vmem_files is True
    assert not (staging / "TestVM" / "TestVM.vmem").exists()
    assert not (staging / "TestVM" / "TestVM.vmdk.lck").exists()

    vmx_extracted = staging / "TestVM" / "TestVM.vmx"
    assert vmx_extracted.is_file()
    mode = stat.S_IMODE(vmx_extracted.stat().st_mode)
    # Must be 0600, no executable or setuid bits!
    assert mode == 0o600


def test_tar_gz_and_7z_extraction(tmp_path: Path) -> None:
    tgz_path = tmp_path / "sample.tar.gz"
    with tarfile.open(tgz_path, "w:gz") as tf:
        data = b'displayName = "TarVM"\n'
        ti = tarfile.TarInfo("TarVM/TarVM.vmx")
        ti.size = len(data)
        ti.mode = 0o755
        tf.addfile(ti, io.BytesIO(data))

    staging_tar = tmp_path / "staging_tar"
    rep_tar = extract_archive_safely(tgz_path, staging_tar)
    assert (staging_tar / "TarVM" / "TarVM.vmx").is_file()
    assert rep_tar.total_extracted_bytes > 0

    if shutil.which("7z"):
        src_dir = tmp_path / "src7z" / "SevenVM"
        src_dir.mkdir(parents=True)
        (src_dir / "SevenVM.vmx").write_text('displayName = "SevenVM"\n', encoding="utf-8")
        archive_7z = tmp_path / "sample.7z"
        subprocess.run(
            ["7z", "a", str(archive_7z), str(src_dir)],
            check=True,
            capture_output=True,
        )
        staging_7z = tmp_path / "staging_7z"
        rep_7z = extract_archive_safely(archive_7z, staging_7z)
        assert (staging_7z / "SevenVM" / "SevenVM.vmx").is_file()
        assert rep_7z.total_extracted_bytes > 0


def test_staging_workspace_cleans_up() -> None:
    captured_path: Path | None = None
    with StagingWorkspace(prefix="unit-test-") as sdir:
        captured_path = sdir
        assert sdir.is_dir()
        (sdir / "temp.txt").write_text("temp", encoding="utf-8")
    assert captured_path is not None
    assert not captured_path.exists()
