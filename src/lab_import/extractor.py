"""Secure archive inspection and extraction for untrusted VM packages."""

from __future__ import annotations

import logging
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

from .config import (
    DEFAULT_MAX_ARCHIVE_FILES,
    DEFAULT_MAX_COMPRESSION_RATIO,
    DEFAULT_MAX_EXTRACT_BYTES,
    MIN_SIZE_FOR_RATIO_CHECK,
    TRANSIENT_VMWARE_EXTENSIONS,
    get_staging_base_dir,
)
from .errors import ArchiveSecurityError, ExtractionError, InsufficientSpaceError
from .models import ArchiveMemberInfo, ExtractionReport

logger = logging.getLogger("lab_import.extractor")

CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB streaming chunks
SAFETY_MARGIN_BYTES = 512 * 1024 * 1024  # 512 MiB free space reserve


def is_archive_path(path: Path) -> bool:
    """Return True if path looks like a supported archive file."""
    if not path.is_file():
        return False
    name_lower = path.name.lower()
    if name_lower.endswith(
        (
            ".zip",
            ".7z",
            ".tar",
            ".tar.gz",
            ".tgz",
            ".tar.bz2",
            ".tbz2",
            ".tar.xz",
            ".txz",
            ".tar.zst",
            ".ova",
        )
    ):
        return True
    return zipfile.is_zipfile(path) or tarfile.is_tarfile(path)


def detect_archive_format(path: Path) -> str:
    """Detect whether an archive is 'zip', 'tar', or '7z'."""
    name_lower = path.name.lower()
    if name_lower.endswith(".7z"):
        return "7z"
    if name_lower.endswith(
        (
            ".tar",
            ".tar.gz",
            ".tgz",
            ".tar.bz2",
            ".tbz2",
            ".tar.xz",
            ".txz",
            ".tar.zst",
            ".ova",
        )
    ):
        return "tar"
    if name_lower.endswith(".zip"):
        return "zip"
    if zipfile.is_zipfile(path):
        return "zip"
    if tarfile.is_tarfile(path):
        return "tar"
    # Check 7z magic bytes: '7z\xbc\xaf\x27\x1c'
    try:
        with path.open("rb") as fh:
            magic = fh.read(6)
        if magic == b"7z\xbc\xaf\x27\x1c":
            return "7z"
    except OSError:
        pass
    raise ExtractionError(
        f"Unsupported archive format: {path.name}",
        hint="Supported formats: .zip, .tar/.tar.gz/.tar.xz/.ova, .7z, extracted directory, .vmx, or .vmdk",
    )


def validate_safe_relative_path(raw_name: str, staging_root: Path) -> Path:
    """Validate that an archive member path cannot escape staging_root."""
    if not raw_name or "\x00" in raw_name:
        raise ArchiveSecurityError(
            f"Archive contains an empty or NUL-byte filename: {raw_name!r}"
        )

    # Reject backslashes used as path traversal or Windows drive prefixes
    normalized = raw_name.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[a-zA-Z]:", normalized):
        raise ArchiveSecurityError(
            f"Archive contains an absolute or drive-prefixed path: {raw_name!r}",
            hint="Untrusted archive rejected due to path traversal attempt.",
        )

    posix_path = PurePosixPath(normalized)
    for part in posix_path.parts:
        if part in ("..", ""):
            if part == "..":
                raise ArchiveSecurityError(
                    f"Archive contains path traversal component ('..'): {raw_name!r}",
                    hint="Untrusted archive rejected due to Zip-Slip/Tar-Slip attempt.",
                )

    rel_parts = [p for p in posix_path.parts if p not in (".", "")]
    if not rel_parts:
        return staging_root.resolve()

    candidate = staging_root.resolve().joinpath(*rel_parts)
    resolved = candidate.resolve(strict=False)
    staging_resolved = staging_root.resolve()
    if resolved != staging_resolved and not resolved.is_relative_to(staging_resolved):
        raise ArchiveSecurityError(
            f"Archive member resolves outside staging directory: {raw_name!r}"
        )
    return resolved


def is_transient_vmware_member(rel_path_str: str) -> tuple[bool, str]:
    """Check if an archive member is a transient VMware lock/memory/log artifact.

    Returns (is_transient, category) where category is 'lock', 'vmem', 'vmss', or 'log'.
    """
    normalized = rel_path_str.replace("\\", "/").rstrip("/")
    parts = PurePosixPath(normalized).parts
    for part in parts:
        if part.lower().endswith(".lck"):
            return True, "lock"
    ext = PurePosixPath(normalized).suffix.lower()
    if ext == ".vmem":
        return True, "vmem"
    if ext in (".vmss", ".vmsn"):
        return True, "vmss"
    if ext in TRANSIENT_VMWARE_EXTENSIONS:
        return True, "log"
    return False, ""


def inspect_archive_members(
    archive_path: Path,
    *,
    max_files: int = DEFAULT_MAX_ARCHIVE_FILES,
    max_bytes: int = DEFAULT_MAX_EXTRACT_BYTES,
    max_ratio: float = DEFAULT_MAX_COMPRESSION_RATIO,
) -> list[ArchiveMemberInfo]:
    """Inspect all archive entries and enforce security invariants before extraction."""
    fmt = detect_archive_format(archive_path)
    if fmt == "zip":
        members = _inspect_zip(archive_path)
    elif fmt == "tar":
        members = _inspect_tar(archive_path)
    elif fmt == "7z":
        members = _inspect_7z(archive_path)
    else:
        raise ExtractionError(f"Unsupported archive format: {fmt}")

    if len(members) > max_files:
        raise ArchiveSecurityError(
            f"Archive contains {len(members)} entries, exceeding safety limit of {max_files}.",
            hint="Use --max-files to increase limit if this is a legitimate archive.",
        )

    dummy_root = Path("/tmp/lab-import-validation-root")
    seen_targets: set[Path] = set()
    total_uncompressed = 0

    for m in members:
        target = validate_safe_relative_path(m.name, dummy_root)
        if m.is_symlink:
            raise ArchiveSecurityError(
                f"Archive contains symbolic or hard link: {m.name!r}",
                hint="Symbolic and hard links inside VM archives are blocked for security.",
            )
        if m.is_special:
            raise ArchiveSecurityError(
                f"Archive contains special device/FIFO/socket node: {m.name!r}",
                hint="Special filesystem nodes inside archives are blocked for security.",
            )
        if not m.is_dir:
            if target in seen_targets:
                raise ArchiveSecurityError(
                    f"Archive contains duplicate/colliding file path: {m.name!r}"
                )
            seen_targets.add(target)

        if m.size < 0:
            raise ArchiveSecurityError(f"Archive member has negative size: {m.name!r}")

        total_uncompressed += m.size
        if total_uncompressed > max_bytes:
            raise ArchiveSecurityError(
                f"Archive uncompressed size ({total_uncompressed / (1024**3):.2f} GiB) "
                f"exceeds safety limit ({max_bytes / (1024**3):.2f} GiB).",
                hint="Potential archive bomb detected.",
            )

        # Check suspicious compression ratio on non-VMDK entries
        ext = PurePosixPath(m.name.replace("\\", "/")).suffix.lower()
        if (
            ext not in (".vmdk", ".nvram", ".vmsd", ".vmx", ".vmxf")
            and m.size >= MIN_SIZE_FOR_RATIO_CHECK
            and m.compressed_size > 0
        ):
            ratio = m.size / m.compressed_size
            if ratio > max_ratio:
                raise ArchiveSecurityError(
                    f"Archive member {m.name!r} has suspicious compression ratio "
                    f"({ratio:.1f}x > {max_ratio:.1f}x limit).",
                    hint="Potential decompression bomb rejected.",
                )

    return members


def _inspect_zip(archive_path: Path) -> list[ArchiveMemberInfo]:
    members: list[ArchiveMemberInfo] = []
    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            for info in zf.infolist():
                mode = (info.external_attr >> 16) & 0xFFFF
                is_symlink = stat.S_ISLNK(mode)
                is_special = (
                    stat.S_ISCHR(mode)
                    or stat.S_ISBLK(mode)
                    or stat.S_ISFIFO(mode)
                    or stat.S_ISSOCK(mode)
                )
                members.append(
                    ArchiveMemberInfo(
                        name=info.filename,
                        size=info.file_size,
                        compressed_size=info.compress_size,
                        is_dir=info.is_dir(),
                        is_symlink=is_symlink,
                        is_special=is_special,
                        mode=mode,
                    )
                )
    except zipfile.BadZipFile as exc:
        raise ExtractionError(f"Corrupt or invalid ZIP archive: {archive_path}") from exc
    return members


def _inspect_tar(archive_path: Path) -> list[ArchiveMemberInfo]:
    members: list[ArchiveMemberInfo] = []
    try:
        with tarfile.open(archive_path, "r:*") as tf:
            for info in tf.getmembers():
                is_symlink = info.issym() or info.islnk()
                is_special = (
                    info.isdev()
                    or info.ischr()
                    or info.isblk()
                    or info.isfifo()
                )
                members.append(
                    ArchiveMemberInfo(
                        name=info.name,
                        size=info.size,
                        compressed_size=info.size,
                        is_dir=info.isdir(),
                        is_symlink=is_symlink,
                        is_special=is_special,
                        mode=info.mode,
                    )
                )
    except (tarfile.TarError, OSError) as exc:
        raise ExtractionError(f"Corrupt or invalid TAR archive: {archive_path}") from exc
    return members


def _inspect_7z(archive_path: Path) -> list[ArchiveMemberInfo]:
    seven_zip = shutil.which("7z") or shutil.which("7za")
    if not seven_zip:
        raise ExtractionError(
            "7z tool is not installed; cannot inspect .7z archive.",
            hint="Install 7zip on Arch Linux with: sudo pacman -S 7zip",
        )
    proc = subprocess.run(
        [seven_zip, "l", "-slt", "-ba", str(archive_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise ExtractionError(
            f"Failed to list 7z archive {archive_path.name}: {proc.stderr.strip()}"
        )

    members: list[ArchiveMemberInfo] = []
    blocks = proc.stdout.strip().split("\n\n")
    for block in blocks:
        if not block.strip():
            continue
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if " = " in line:
                k, v = line.split(" = ", 1)
                fields[k.strip()] = v.strip()
        path_val = fields.get("Path")
        if not path_val:
            continue
        size = int(fields.get("Size") or "0")
        packed_size = int(fields.get("Packed Size") or str(size))
        folder_flag = fields.get("Folder", "-") == "+"
        attrs = fields.get("Attributes", "")
        sym_link = fields.get("Symbolic Link", "")
        mode_str = fields.get("Mode", "")
        if "D" in attrs.split(".")[0] if "." in attrs else "D" in attrs:
            folder_flag = True
        is_symlink = bool(sym_link) or mode_str.startswith("l") or "l" in attrs.lower()
        is_special = mode_str.startswith(("c", "b", "p", "s"))
        members.append(
            ArchiveMemberInfo(
                name=path_val,
                size=size,
                compressed_size=packed_size,
                is_dir=folder_flag,
                is_symlink=is_symlink,
                is_special=is_special,
            )
        )
    return members


def extract_archive_safely(
    archive_path: Path,
    staging_dir: Path,
    *,
    skip_transient: bool = True,
    max_files: int = DEFAULT_MAX_ARCHIVE_FILES,
    max_bytes: int = DEFAULT_MAX_EXTRACT_BYTES,
    max_ratio: float = DEFAULT_MAX_COMPRESSION_RATIO,
    progress_callback: Callable[[int, int, str], None] | None = None,
) -> ExtractionReport:
    """Validate and safely extract an archive into staging_dir."""
    staging_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(staging_dir, 0o700)

    members = inspect_archive_members(
        archive_path,
        max_files=max_files,
        max_bytes=max_bytes,
        max_ratio=max_ratio,
    )

    report = ExtractionReport(archive_path=archive_path, staging_dir=staging_dir)

    # Calculate actual bytes we plan to extract
    planned_bytes = 0
    for m in members:
        if m.is_dir:
            continue
        is_trans, category = is_transient_vmware_member(m.name)
        if is_trans:
            if category == "lock":
                report.had_lock_files = True
            elif category == "vmem":
                report.had_vmem_files = True
            elif category == "vmss":
                report.had_vmss_files = True
            if skip_transient:
                report.skipped_transient_files.append(m.name)
                continue
        planned_bytes += m.size

    if planned_bytes > max_bytes:
        raise ArchiveSecurityError(
            f"Planned extraction size ({planned_bytes} bytes) exceeds limit ({max_bytes} bytes)."
        )

    usage = shutil.disk_usage(staging_dir)
    if usage.free < planned_bytes + SAFETY_MARGIN_BYTES:
        raise InsufficientSpaceError(
            f"Insufficient free space in staging directory {staging_dir}: "
            f"need {(planned_bytes + SAFETY_MARGIN_BYTES) / (1024**3):.2f} GiB, "
            f"have {usage.free / (1024**3):.2f} GiB available.",
            hint="Free up disk space or set XDG_CACHE_HOME to a larger partition.",
        )

    fmt = detect_archive_format(archive_path)
    if fmt == "zip":
        _extract_zip_members(
            archive_path,
            staging_dir,
            report,
            skip_transient=skip_transient,
            max_bytes=max_bytes,
            total_planned=planned_bytes,
            progress_callback=progress_callback,
        )
    elif fmt == "tar":
        _extract_tar_members(
            archive_path,
            staging_dir,
            report,
            skip_transient=skip_transient,
            max_bytes=max_bytes,
            total_planned=planned_bytes,
            progress_callback=progress_callback,
        )
    elif fmt == "7z":
        _extract_7z_members(
            archive_path,
            staging_dir,
            report,
            members,
            skip_transient=skip_transient,
            max_bytes=max_bytes,
            total_planned=planned_bytes,
            progress_callback=progress_callback,
        )

    return report


def _extract_zip_members(
    archive_path: Path,
    staging_dir: Path,
    report: ExtractionReport,
    *,
    skip_transient: bool,
    max_bytes: int,
    total_planned: int,
    progress_callback: Callable[[int, int, str], None] | None,
) -> None:
    written_total = 0
    with zipfile.ZipFile(archive_path, "r") as zf:
        for info in zf.infolist():
            is_trans, _ = is_transient_vmware_member(info.filename)
            if skip_transient and is_trans:
                continue

            target = validate_safe_relative_path(info.filename, staging_dir)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.chmod(target, 0o700)
                continue

            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if target.exists() or target.is_symlink():
                raise ArchiveSecurityError(
                    f"Refusing to overwrite existing file during extraction: {info.filename!r}"
                )

            fd = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            file_written = 0
            try:
                with os.fdopen(fd, "wb") as out_fh, zf.open(info, "r") as in_fh:
                    while True:
                        chunk = in_fh.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        file_written += len(chunk)
                        written_total += len(chunk)
                        if file_written > info.file_size + 1024 or written_total > max_bytes:
                            raise ArchiveSecurityError(
                                f"Archive member {info.filename!r} exceeded declared size or extraction limit."
                            )
                        out_fh.write(chunk)
                        if progress_callback:
                            progress_callback(written_total, max(total_planned, 1), Path(info.filename).name)
            except Exception:
                target.unlink(missing_ok=True)
                raise

            os.chmod(target, 0o600)
            report.extracted_files.append(target)
    report.total_extracted_bytes = written_total


def _extract_tar_members(
    archive_path: Path,
    staging_dir: Path,
    report: ExtractionReport,
    *,
    skip_transient: bool,
    max_bytes: int,
    total_planned: int,
    progress_callback: Callable[[int, int, str], None] | None,
) -> None:
    written_total = 0
    with tarfile.open(archive_path, "r:*") as tf:
        for member in tf.getmembers():
            is_trans, _ = is_transient_vmware_member(member.name)
            if skip_transient and is_trans:
                continue

            target = validate_safe_relative_path(member.name, staging_dir)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.chmod(target, 0o700)
                continue

            if not member.isfile():
                raise ArchiveSecurityError(
                    f"Unsupported non-regular TAR entry: {member.name!r}"
                )

            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if target.exists() or target.is_symlink():
                raise ArchiveSecurityError(
                    f"Refusing to overwrite existing file during extraction: {member.name!r}"
                )

            in_fh = tf.extractfile(member)
            if in_fh is None:
                continue

            fd = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            file_written = 0
            try:
                with os.fdopen(fd, "wb") as out_fh, in_fh:
                    while True:
                        chunk = in_fh.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        file_written += len(chunk)
                        written_total += len(chunk)
                        if file_written > member.size + 1024 or written_total > max_bytes:
                            raise ArchiveSecurityError(
                                f"TAR member {member.name!r} exceeded declared size or extraction limit."
                            )
                        out_fh.write(chunk)
                        if progress_callback:
                            progress_callback(written_total, max(total_planned, 1), Path(member.name).name)
            except Exception:
                target.unlink(missing_ok=True)
                raise

            os.chmod(target, 0o600)
            report.extracted_files.append(target)
    report.total_extracted_bytes = written_total


def _extract_7z_members(
    archive_path: Path,
    staging_dir: Path,
    report: ExtractionReport,
    members: list[ArchiveMemberInfo],
    *,
    skip_transient: bool,
    max_bytes: int,
    total_planned: int,
    progress_callback: Callable[[int, int, str], None] | None,
) -> None:
    seven_zip = shutil.which("7z") or shutil.which("7za")
    if not seven_zip:
        raise ExtractionError("7z binary not available.")

    written_total = 0
    for m in members:
        is_trans, _ = is_transient_vmware_member(m.name)
        if skip_transient and is_trans:
            continue

        target = validate_safe_relative_path(m.name, staging_dir)
        if m.is_dir:
            target.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(target, 0o700)
            continue

        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if target.exists() or target.is_symlink():
            raise ArchiveSecurityError(
                f"Refusing to overwrite existing file during extraction: {m.name!r}"
            )

        proc = subprocess.Popen(
            [seven_zip, "x", "-so", "-y", str(archive_path), m.name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        fd = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        file_written = 0
        try:
            assert proc.stdout is not None
            with os.fdopen(fd, "wb") as out_fh:
                while True:
                    chunk = proc.stdout.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    file_written += len(chunk)
                    written_total += len(chunk)
                    if file_written > m.size + 1024 or written_total > max_bytes:
                        proc.kill()
                        raise ArchiveSecurityError(
                            f"7z member {m.name!r} exceeded declared size or extraction limit."
                        )
                    out_fh.write(chunk)
                    if progress_callback:
                        progress_callback(written_total, max(total_planned, 1), Path(m.name).name)
            _, stderr_bytes = proc.communicate()
            if proc.returncode != 0:
                raise ExtractionError(
                    f"7z failed extracting {m.name!r}: {stderr_bytes.decode(errors='replace').strip()}"
                )
        except Exception:
            proc.kill()
            proc.wait()
            target.unlink(missing_ok=True)
            raise

        os.chmod(target, 0o600)
        report.extracted_files.append(target)

    # Verify post-extraction that no symlinks exist anywhere in staging_dir
    for root, dirs, files in os.walk(staging_dir, followlinks=False):
        root_p = Path(root)
        for name in dirs + files:
            p = root_p / name
            if p.is_symlink():
                p.unlink(missing_ok=True)
                raise ArchiveSecurityError(f"Symlink detected post-extraction: {p}")

    report.total_extracted_bytes = written_total


class StagingWorkspace:
    """Context manager that creates and cleans up a 0700 staging directory."""

    def __init__(self, prefix: str = "import-") -> None:
        self.prefix = prefix
        self.path: Path | None = None

    def __enter__(self) -> Path:
        base = get_staging_base_dir()
        raw = tempfile.mkdtemp(prefix=self.prefix, dir=str(base))
        self.path = Path(raw)
        os.chmod(self.path, 0o700)
        return self.path

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        if self.path and self.path.exists():
            shutil.rmtree(self.path, ignore_errors=True)
            self.path = None
