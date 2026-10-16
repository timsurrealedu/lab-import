"""Unit tests for VMware .vmx/.vmsd parsing and source discovery."""

from __future__ import annotations

from pathlib import Path

import pytest

from lab_import.errors import (
    AmbiguousVMSelectionError,
    ArchiveSecurityError,
    VMStateConflictError,
    VMXParseError,
)
from lab_import.scanner import discover_vms_in_path, select_discovered_vm
from lab_import.vmx_parser import (
    check_source_vm_runtime_state,
    parse_vmsd_file,
    parse_vmx_file,
)

LINKEDBASE_VMX_SAMPLE = """#!/usr/bin/vmware
.encoding = "windows-1252"
config.version = "8"
virtualHW.version = "18"
pciBridge0.present = "TRUE"
pciBridge0.pciSlotNumber = "17"
displayName = "LinkedBase"
guestOS = "ubuntu-64"
numvcpus = "2"
memsize = "2048"
scsi0.virtualDev = "lsilogic"
scsi0.present = "TRUE"
sata0.present = "TRUE"
scsi0:0.fileName = "LinkedBase.vmdk"
scsi0:0.present = "TRUE"
sata0:1.deviceType = "cdrom-image"
sata0:1.fileName = "D:\\ubuntu-20.04.6-live-server-amd64.iso"
sata0:1.present = "TRUE"
sata0:0.deviceType = "cdrom-image"
sata0:0.fileName = "autoinst.iso"
sata0:0.present = "TRUE"
floppy0.fileType = "file"
floppy0.fileName = "autoinst.flp"
ethernet0.connectionType = "nat"
ethernet0.addressType = "generated"
ethernet0.virtualDev = "e1000"
ethernet0.present = "TRUE"
ethernet0.pciSlotNumber = "33"
ethernet0.generatedAddress = "00:0c:29:54:7f:31"
cleanShutdown = "FALSE"
guestOS.detailed.data = "architecture='X86' bitness='64' distroName='Ubuntu' distroVersion='20.04' familyName='Linux' kernelVersion='5.4.0-216-generic' prettyName='Ubuntu 20.04.6 LTS'"
"""


def test_parse_linkedbase_vmx_filters_isos_and_floppies(tmp_path: Path) -> None:
    vmx_path = tmp_path / "LinkedBase.vmx"
    vmx_path.write_text(LINKEDBASE_VMX_SAMPLE, encoding="utf-8")

    cfg = parse_vmx_file(vmx_path)
    assert cfg.display_name == "LinkedBase"
    assert cfg.guest_os == "ubuntu-64"
    assert cfg.num_vcpus == 2
    assert cfg.memory_mb == 2048
    assert cfg.firmware == "bios"
    assert cfg.clean_shutdown is False
    assert cfg.pci_bridge0_present is True
    assert cfg.pci_bridge0_slot == 17

    # Only scsi0:0 LinkedBase.vmdk should be included; both ISOs and floppy must be filtered out!
    assert len(cfg.disks) == 1
    assert cfg.disks[0].file_name == "LinkedBase.vmdk"
    assert cfg.disks[0].bus_type == "scsi"

    assert len(cfg.nics) == 1
    assert cfg.nics[0].virtual_dev == "e1000"
    assert cfg.nics[0].pci_slot == 33
    assert cfg.nics[0].mac_address == "00:0c:29:54:7f:31"


def test_parse_uefi_and_malformed_vmx(tmp_path: Path) -> None:
    uefi_vmx = tmp_path / "efi.vmx"
    uefi_vmx.write_text(
        'displayName = "UEFIVM"\nfirmware = "efi"\nmemsize = "4096"\nnumvcpus = "4"\n'
        'nvme0:0.fileName = "disk.vmdk"\nnvme0:0.present = "TRUE"\n',
        encoding="utf-8",
    )
    cfg = parse_vmx_file(uefi_vmx)
    assert cfg.firmware == "efi"
    assert cfg.memory_mb == 4096
    assert cfg.num_vcpus == 4
    assert len(cfg.disks) == 1
    assert cfg.disks[0].bus_type == "nvme"

    bad_vmx = tmp_path / "bad.vmx"
    bad_vmx.write_text("this line has no equals sign\n", encoding="utf-8")
    with pytest.raises(VMXParseError):
        parse_vmx_file(bad_vmx)


def test_vmx_blocks_external_disk_path_traversal(tmp_path: Path) -> None:
    evil_vmx = tmp_path / "evil.vmx"
    evil_vmx.write_text(
        'displayName = "Evil"\nscsi0:0.fileName = "../../etc/shadow"\nscsi0:0.present = "TRUE"\n',
        encoding="utf-8",
    )
    with pytest.raises(ArchiveSecurityError):
        parse_vmx_file(evil_vmx)


def test_suspended_vm_blocked_while_stale_locks_only_warn(tmp_path: Path) -> None:
    vmx_path = tmp_path / "Susp.vmx"
    vmx_path.write_text(
        'displayName = "Susp"\ncheckpoint.vmState = "Susp-1234.vmss"\n',
        encoding="utf-8",
    )
    cfg = parse_vmx_file(vmx_path)
    with pytest.raises(VMStateConflictError, match="suspended state"):
        check_source_vm_runtime_state(tmp_path, cfg, allow_suspended=False)

    # With allow_suspended=True, returns warning instead of raising
    warns = check_source_vm_runtime_state(tmp_path, cfg, allow_suspended=True)
    assert any("suspended" in w.lower() for w in warns)


def test_multi_vm_discovery_and_selection(tmp_path: Path) -> None:
    vm1 = tmp_path / "VM1"
    vm2 = tmp_path / "VM2"
    vm1.mkdir()
    vm2.mkdir()
    (vm1 / "alpha.vmx").write_text('displayName = "AlphaVM"\n', encoding="utf-8")
    (vm2 / "beta.vmx").write_text('displayName = "BetaVM"\n', encoding="utf-8")

    discovered = discover_vms_in_path(tmp_path)
    assert len(discovered) == 2

    with pytest.raises(AmbiguousVMSelectionError):
        select_discovered_vm(discovered, selector=None, interactive=False)

    chosen = select_discovered_vm(discovered, selector="BetaVM", interactive=False)
    assert chosen.name == "BetaVM"

    chosen_idx = select_discovered_vm(discovered, selector="1", interactive=False)
    assert chosen_idx.name == "AlphaVM"


def test_parse_vmsd_snapshots(tmp_path: Path) -> None:
    vmsd = tmp_path / "test.vmsd"
    vmsd.write_text(
        '.encoding = "UTF-8"\n'
        'snapshot.lastUID = "2"\n'
        'snapshot.current = "2"\n'
        'snapshot.numSnapshots = "1"\n'
        'snapshot0.uid = "2"\n'
        'snapshot0.displayName = "Before Exploit"\n'
        'snapshot0.disk0.fileName = "base.vmdk"\n'
        'snapshot0.disk0.node = "scsi0:0"\n',
        encoding="utf-8",
    )
    parsed = parse_vmsd_file(vmsd)
    assert parsed["num_snapshots"] == 1
    assert parsed["current_uid"] == "2"
    assert parsed["snapshots"][0]["display_name"] == "Before Exploit"
