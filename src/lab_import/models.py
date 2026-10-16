"""Data models for VMware configurations, disk inspection, import planning, and validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ArchiveMemberInfo:
    """Metadata about a single member inside an archive prior to extraction."""

    name: str
    size: int
    compressed_size: int
    is_dir: bool = False
    is_symlink: bool = False
    is_special: bool = False
    mode: int = 0


@dataclass
class ExtractionReport:
    """Summary of secure archive extraction into a staging directory."""

    archive_path: Path
    staging_dir: Path
    extracted_files: list[Path] = field(default_factory=list)
    skipped_transient_files: list[str] = field(default_factory=list)
    total_extracted_bytes: int = 0
    had_lock_files: bool = False
    had_vmem_files: bool = False
    had_vmss_files: bool = False


@dataclass
class DiscoveredVM:
    """A candidate virtual machine discovered inside an archive, directory, or file."""

    name: str
    vmx_path: Path | None
    primary_vmdk: Path | None
    base_dir: Path
    source_type: str  # "vmx" | "ovf" | "standalone_vmdk"
    extra_vmdks: list[Path] = field(default_factory=list)


@dataclass
class VMXControllerSpec:
    """VMware storage controller parsed from .vmx."""

    bus_type: str  # "scsi" | "sata" | "ide" | "nvme"
    index: int
    virtual_dev: str  # e.g. "lsilogic", "lsisas1068", "pvscsi", "ahci"
    present: bool = True
    pci_slot: int | None = None


@dataclass
class VMXDiskSpec:
    """VMware disk attachment parsed from .vmx."""

    bus_type: str  # "scsi" | "sata" | "ide" | "nvme"
    controller_index: int
    unit_index: int
    file_name: str
    resolved_path: Path | None = None
    device_type: str = "disk"  # "disk", "cdrom-image", "atapi-cdrom", etc.
    present: bool = True
    redo_file: str = ""


@dataclass
class VMXNicSpec:
    """VMware network adapter parsed from .vmx."""

    index: int
    virtual_dev: str = "e1000"  # "e1000", "e1000e", "vmxnet3", "vlance"
    connection_type: str = "nat"  # "nat", "hostonly", "bridged", "custom"
    address_type: str = "generated"
    mac_address: str | None = None
    pci_slot: int | None = None
    present: bool = True


@dataclass
class VMXConfig:
    """Parsed representation of a VMware .vmx configuration file."""

    vmx_path: Path | None
    display_name: str
    guest_os: str = "other-64"
    guest_os_detailed: str = ""
    num_vcpus: int = 2
    cores_per_socket: int = 1
    memory_mb: int = 2048
    firmware: str = "bios"  # "bios" | "efi"
    secure_boot: bool = False
    virtual_hw_version: int = 18
    uuid_bios: str = ""
    clean_shutdown: bool = True
    soft_power_off: bool = True
    checkpoint_vmstate: str = ""
    pci_bridge0_present: bool = False
    pci_bridge0_slot: int | None = None
    controllers: list[VMXControllerSpec] = field(default_factory=list)
    disks: list[VMXDiskSpec] = field(default_factory=list)
    nics: list[VMXNicSpec] = field(default_factory=list)
    raw_entries: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


@dataclass
class VMDKExtentInfo:
    """Single extent entry in a VMDK descriptor."""

    access: str  # "RW", "RDONLY", "NOACCESS"
    sectors: int
    extent_type: str  # "SPARSE", "FLAT", "VMFS", "ZERO", etc.
    filename: str
    resolved_path: Path | None = None
    exists: bool = False
    actual_size_bytes: int = 0


@dataclass
class VMDKAnalysis:
    """Detailed inspection result for a VMDK disk and its extents/backing chain."""

    descriptor_path: Path
    format: str = "vmdk"
    create_type: str = "monolithicSparse"
    virtual_size_bytes: int = 0
    actual_size_bytes: int = 0
    cid: str = "ffffffff"
    parent_cid: str = "ffffffff"
    parent_filename_hint: str | None = None
    adapter_type: str = "lsilogic"
    extents: list[VMDKExtentInfo] = field(default_factory=list)
    backing_chain: list[Path] = field(default_factory=list)
    has_snapshots: bool = False
    snapshot_details: list[str] = field(default_factory=list)
    unreferenced_deltas: list[Path] = field(default_factory=list)
    has_efi_partition: bool = False
    warnings: list[str] = field(default_factory=list)


@dataclass
class TargetDiskPlan:
    """Planned conversion and attachment for a single virtual disk."""

    source_vmdk: VMDKAnalysis
    target_vol_name: str
    target_path: Path
    bus: str  # "sata" | "scsi" | "virtio" | "ide" | "nvme"
    target_dev: str  # e.g. "sda", "sdb", "vda", "hda"
    controller_model: str | None = None  # e.g. "virtio-scsi", "lsilogic"
    unit_index: int = 0


@dataclass
class TargetNicPlan:
    """Planned network interface configuration for QEMU/KVM."""

    index: int
    network_name: str
    model: str  # "e1000", "e1000e", "virtio", "vmxnet3"
    mac_address: str
    preserved_mac: bool = False
    vmware_pci_slot: int | None = None
    pci_bus: int | None = None
    pci_slot: int | None = None
    expected_guest_ifname: str | None = None


@dataclass
class LabNetworkSpec:
    """Configuration of the reusable isolated penetration-testing network."""

    name: str
    bridge_name: str
    subnet_cidr: str
    gateway_ip: str
    netmask: str
    dhcp_start: str
    dhcp_end: str
    kali_reserved_ip: str | None = None
    kali_mac: str | None = None
    already_exists: bool = False
    is_active: bool = False
    is_isolated: bool = True


@dataclass
class ImportPlan:
    """Complete hardware translation, storage, and networking plan for an import."""

    source_path: Path
    vm_name: str
    original_vm_name: str
    os_family: str  # "linux" | "windows" | "bsd" | "other"
    os_distro: str
    libosinfo_id: str | None
    arch: str
    machine_type: str  # "pc" | "q35"
    firmware: str  # "bios" | "efi"
    ovmf_code_path: Path | None
    vcpus: int
    memory_mb: int
    use_pci_bridge_for_slot_naming: bool
    disks: list[TargetDiskPlan] = field(default_factory=list)
    nics: list[TargetNicPlan] = field(default_factory=list)
    video_model: str = "vga"
    lab_network: LabNetworkSpec | None = None
    kali_domain_name: str | None = None
    kali_needs_lab_nic: bool = False
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class ValidationCheck:
    """Single non-destructive post-import validation check result."""

    name: str
    passed: bool
    detail: str


@dataclass
class ImportResult:
    """Final result of executing an ImportPlan."""

    plan: ImportPlan
    domain_uuid: str
    domain_xml: str
    converted_disks: list[Path] = field(default_factory=list)
    validation_checks: list[ValidationCheck] = field(default_factory=list)
    boot_validated: bool = False
    discovered_ip: str | None = None
    kali_attached: bool = False
    kali_backup_path: Path | None = None
