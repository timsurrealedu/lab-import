"""Structured exception hierarchy for lab-import with actionable hints."""

from __future__ import annotations


class LabImportError(Exception):
    """Base error for all expected lab-import failures."""

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint


class ArchiveSecurityError(LabImportError):
    """Raised when an archive violates extraction safety rules (path traversal, symlink, bomb)."""


class ExtractionError(LabImportError):
    """Raised when an archive cannot be extracted or exceeds disk limits."""


class SourceDiscoveryError(LabImportError):
    """Raised when no valid VM configuration or disk can be found in the input."""


class AmbiguousVMSelectionError(LabImportError):
    """Raised when multiple VMs exist and non-interactive mode cannot choose automatically."""


class VMXParseError(LabImportError):
    """Raised when a .vmx configuration is malformed or missing essential parameters."""


class VMStateConflictError(LabImportError):
    """Raised when a source VMware VM is actively running or suspended."""


class SnapshotDependencyError(LabImportError):
    """Raised when a VMDK has unsupported, broken, or ambiguous snapshot/delta chains."""


class DiskValidationError(LabImportError):
    """Raised when VMDK extents are missing, corrupt, unsafe, or QCOW2 check fails."""


class InsufficientSpaceError(LabImportError):
    """Raised when staging or target storage pool lacks sufficient free space."""


class NetworkConfigError(LabImportError):
    """Raised when isolated lab network setup or subnet allocation fails."""


class LibvirtOperationError(LabImportError):
    """Raised when a libvirt domain/pool/network operation fails."""


class ValidationFailedError(LabImportError):
    """Raised when post-import validation fails."""
