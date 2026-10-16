"""Hardware translation and import planning from VMware to QEMU/KVM."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from .config import (
    DEFAULT_LAB_NETWORK,
    DEFAULT_STORAGE_PATH,
    detect_dependencies,
)
from .errors import LabImportError, LibvirtOperationError
from .models import (
    ImportPlan,
    LabNetworkSpec,
    TargetDiskPlan,
    TargetNicPlan,
    VMDKAnalysis,
    VMXConfig,
)
from .network import (
    find_kali_domain,
    generate_kvm_mac,
    get_all_domain_macs,
    inspect_kali_lab_attachment,
    inspect_or_plan_lab_network,
)

UNICAST_MAC_RE = re.compile(
    r"^[0-9a-fA-F][02468aAcCeE](?::[0-9a-fA-F]{2}){5}$"
)


def sanitize_domain_name(raw_name: str) -> str:
    """Convert a display name into a clean, safe libvirt domain name."""
    cleaned = raw_name.strip()
    cleaned = re.sub(r"\s+", "-", cleaned)
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]", "", cleaned)
    cleaned = cleaned.strip("-.")
    return cleaned or "imported-vm"


def detect_os_profile(vmx: VMXConfig) -> tuple[str, str, str | None]:
    """Infer (os_family, os_distro_label, libosinfo_id) from VMware guestOS fields."""
    guest_os = vmx.guest_os.lower()
    detailed = vmx.guest_os_detailed

    distro_name = _extract_detailed_field(detailed, "distroName")
    distro_ver = _extract_detailed_field(detailed, "distroVersion")
    pretty_name = _extract_detailed_field(detailed, "prettyName")

    if "ubuntu" in guest_os or distro_name.lower() == "ubuntu":
        ver = distro_ver or "20.04"
        label = pretty_name or f"Ubuntu {ver}"
        return "linux", label, f"http://ubuntu.com/ubuntu/{ver}"

    if "debian" in guest_os or distro_name.lower() == "debian":
        ver = distro_ver or "12"
        label = pretty_name or f"Debian {ver}"
        return "linux", label, f"http://debian.org/debian/{ver}"

    if "kali" in guest_os or distro_name.lower() == "kali":
        return "linux", pretty_name or "Kali Linux", "http://debian.org/debian/12"

    if any(k in guest_os for k in ("centos", "rhel", "redhat", "fedora", "rocky", "alma")):
        return "linux", pretty_name or vmx.guest_os, "http://redhat.com/rhel/8.0"

    if any(k in guest_os for k in ("linux", "other26x", "other3x", "other4x", "other5x", "arch", "suse")):
        return "linux", pretty_name or vmx.guest_os, None

    if "win" in guest_os:
        return "windows", pretty_name or vmx.guest_os, "http://microsoft.com/win/10"

    if "freebsd" in guest_os or "openbsd" in guest_os:
        return "bsd", pretty_name or vmx.guest_os, None

    if "familyName='Linux'" in detailed:
        return "linux", pretty_name or vmx.guest_os, None

    return "other", pretty_name or vmx.guest_os, None


def _extract_detailed_field(detailed: str, key: str) -> str:
    m = re.search(rf"{re.escape(key)}='([^']*)'", detailed)
    return m.group(1).strip() if m else ""


def resolve_domain_name_collision(
    desired_name: str,
    conn: Any,
    storage_dir: Path = DEFAULT_STORAGE_PATH,
    *,
    policy: str = "rename",  # "rename" | "fail" | "replace"
) -> tuple[str, bool]:
    """Check if desired_name collides with an existing libvirt domain or disk volume.

    Returns (resolved_name, will_replace_existing).
    """
    existing_domains: set[str] = set()
    existing_volumes: set[str] = set()

    if conn is not None:
        try:
            for d in conn.listAllDomains(0):
                existing_domains.add(d.name())
        except Exception:
            pass
        try:
            pool = conn.storagePoolLookupByName("default")
            for v in pool.listAllVolumes(0):
                existing_volumes.add(v.name())
        except Exception:
            pass

    if storage_dir.is_dir():
        try:
            for p in storage_dir.iterdir():
                existing_volumes.add(p.name)
        except OSError:
            pass

    def _conflicts(candidate: str) -> bool:
        if candidate in existing_domains or candidate.lower() in {
            d.lower() for d in existing_domains
        }:
            return True
        if f"{candidate}.qcow2" in existing_volumes:
            return True
        return False

    if not _conflicts(desired_name):
        return desired_name, False

    if policy == "fail":
        raise LibvirtOperationError(
            f"A virtual machine or disk named {desired_name!r} already exists in libvirt.",
            hint="Use --name <new_name>, --collision rename, or lab-remove <vm> first.",
        )

    if policy == "replace":
        if desired_name.lower() in ("kalilinux", "kali-linux", "kali"):
            raise LibvirtOperationError(
                f"Refusing to replace protected Kali Linux VM ({desired_name!r})."
            )
        return desired_name, True

    # Default policy == "rename"
    for suffix in range(2, 1000):
        cand = f"{desired_name}-{suffix}"
        if not _conflicts(cand):
            return cand, False

    raise LibvirtOperationError(f"Could not find an available name for {desired_name!r}.")


def build_import_plan(
    source_path: Path,
    vmx: VMXConfig,
    disk_analyses: list[VMDKAnalysis],
    *,
    conn: Any = None,
    name_override: str | None = None,
    memory_override_mb: int | None = None,
    vcpus_override: int | None = None,
    firmware_override: str = "auto",
    disk_bus_override: str = "auto",
    nic_model_override: str = "auto",
    network_name: str = DEFAULT_LAB_NETWORK,
    preserve_mac: bool = True,
    collision_policy: str = "rename",
    storage_dir: Path = DEFAULT_STORAGE_PATH,
    skip_kali_check: bool = False,
) -> ImportPlan:
    """Translate VMware configuration and analyzed disks into a complete QEMU/KVM ImportPlan."""
    deps = detect_dependencies()
    warnings: list[str] = list(vmx.warnings)
    notes: list[str] = []

    for d_analysis in disk_analyses:
        warnings.extend(d_analysis.warnings)
        if d_analysis.has_snapshots:
            notes.append(
                f"Disk {d_analysis.descriptor_path.name} uses snapshot chain "
                f"({'; '.join(d_analysis.snapshot_details)}); conversion will flatten active state into standalone QCOW2."
            )

    raw_name = name_override or vmx.display_name
    base_name = sanitize_domain_name(raw_name)
    resolved_name, replaced = resolve_domain_name_collision(
        base_name, conn, storage_dir=storage_dir, policy=collision_policy
    )
    if resolved_name != base_name:
        notes.append(
            f"Domain name {base_name!r} already exists; using collision-safe name {resolved_name!r}."
        )
    elif replaced:
        warnings.append(f"Existing domain {resolved_name!r} will be replaced.")

    os_family, os_distro, libosinfo_id = detect_os_profile(vmx)

    # Firmware selection
    if firmware_override in ("bios", "efi"):
        firmware = firmware_override
    else:
        if vmx.firmware == "efi":
            firmware = "efi"
        elif vmx.vmx_path is None and any(d.has_efi_partition for d in disk_analyses):
            firmware = "efi"
            notes.append(
                "Detected GPT EFI System Partition on standalone VMDK; selecting UEFI firmware."
            )
        else:
            firmware = "bios"

    ovmf_code: Path | None = None
    if firmware == "efi":
        if not deps.ovmf_code_path:
            raise LabImportError(
                "VM requires UEFI firmware, but OVMF/EDK2 firmware files were not found on this host.",
                hint="Install UEFI firmware on Arch Linux with: sudo pacman -S edk2-ovmf",
            )
        ovmf_code = deps.ovmf_code_path

    # CPU & Memory sanity bounds
    host_cpus = os.cpu_count() or 4
    vcpus = vcpus_override or vmx.num_vcpus or 2
    if vcpus > host_cpus:
        warnings.append(
            f"VM requested {vcpus} vCPUs, capping to host CPU count ({host_cpus})."
        )
        vcpus = host_cpus

    memory_mb = memory_override_mb or vmx.memory_mb or 2048
    if memory_mb < 256:
        warnings.append(f"VM memory ({memory_mb} MiB) is very low; raising to 512 MiB.")
        memory_mb = 512

    # Disk bus selection (Compatibility prioritized for first boot)
    target_disks: list[TargetDiskPlan] = []
    for idx, d_analysis in enumerate(disk_analyses):
        vmx_disk = vmx.disks[idx] if idx < len(vmx.disks) else None
        orig_bus = vmx_disk.bus_type if vmx_disk else "scsi"

        if disk_bus_override != "auto":
            chosen_bus = disk_bus_override
        else:
            if orig_bus == "ide" and idx < 4:
                chosen_bus = "ide"
            else:
                # Default to SATA (AHCI) for SCSI/SATA/NVMe VMware disks:
                # - Built into all Linux & Windows kernels/initramfs without needing VirtIO drivers
                # - Presents disks in Linux as /dev/sda, /dev/sdb (identical to VMware lsilogic SCSI!)
                chosen_bus = "sata"

        dev_prefix = {
            "sata": "sd",
            "scsi": "sd",
            "virtio": "vd",
            "ide": "hd",
            "nvme": "nvme0n",
        }.get(chosen_bus, "sd")

        if chosen_bus == "nvme":
            target_dev = f"nvme0n{idx + 1}"
        else:
            target_dev = f"{dev_prefix}{chr(ord('a') + idx)}"

        ctrl_model = "virtio-scsi" if chosen_bus == "scsi" else None
        vol_name = (
            f"{resolved_name}.qcow2"
            if len(disk_analyses) == 1
            else f"{resolved_name}-disk{idx + 1}.qcow2"
        )
        target_path = storage_dir / vol_name

        target_disks.append(
            TargetDiskPlan(
                source_vmdk=d_analysis,
                target_vol_name=vol_name,
                target_path=target_path,
                bus=chosen_bus,
                target_dev=target_dev,
                controller_model=ctrl_model,
                unit_index=idx,
            )
        )

    if any(d.bus == "sata" for d in target_disks):
        notes.append(
            "Using SATA (AHCI) disk controller (/dev/sdX) for maximum first-boot compatibility "
            "across guests without requiring VirtIO block drivers."
        )

    # Network interface planning
    existing_macs = get_all_domain_macs(conn)
    target_nics: list[TargetNicPlan] = []
    use_pci_bridge = False

    for nic_idx, vmx_nic in enumerate(vmx.nics):
        has_vmware_slot = vmx_nic.pci_slot is not None and 1 <= vmx_nic.pci_slot <= 255
        if has_vmware_slot:
            use_pci_bridge = True

        if nic_model_override != "auto":
            model = nic_model_override
        else:
            if has_vmware_slot:
                # e1000e is a native PCIe endpoint that attaches directly to a pcie-root-port
                # with PCIe Physical Slot Number = vmware_pci_slot (e.g. 33 -> ens33).
                model = "e1000e"
            elif vmx_nic.virtual_dev in ("e1000", "e1000e"):
                model = vmx_nic.virtual_dev
            elif vmx_nic.virtual_dev == "vmxnet3":
                model = "e1000"
            else:
                model = "e1000"

        candidate_mac = (vmx_nic.mac_address or "").lower()
        preserved = False
        if (
            preserve_mac
            and candidate_mac
            and UNICAST_MAC_RE.match(candidate_mac)
            and candidate_mac not in existing_macs
        ):
            chosen_mac = candidate_mac
            preserved = True
            existing_macs.add(chosen_mac)
        else:
            chosen_mac = generate_kvm_mac(existing_macs)
            existing_macs.add(chosen_mac)

        pci_bus: int | None = None
        pci_slot: int | None = None
        expected_ifname: str | None = None

        # Map VMware pciSlotNumber (e.g. 33 -> pcie-root-port slot=33 -> ens33 in Linux)
        if has_vmware_slot and vmx_nic.pci_slot is not None:
            pci_bus = nic_idx + 1
            pci_slot = 0
            expected_ifname = f"ens{vmx_nic.pci_slot}"
            notes.append(
                f"Mapped VMware ethernet{nic_idx}.pciSlotNumber={vmx_nic.pci_slot} to "
                f"PCIe root port bus {pci_bus} (slot={vmx_nic.pci_slot}) so Linux guests retain interface name {expected_ifname!r}."
            )

        target_nics.append(
            TargetNicPlan(
                index=nic_idx,
                network_name=network_name,
                model=model,
                mac_address=chosen_mac,
                preserved_mac=preserved,
                vmware_pci_slot=vmx_nic.pci_slot,
                pci_bus=pci_bus,
                pci_slot=pci_slot,
                expected_guest_ifname=expected_ifname,
            )
        )

    # Inspect Kali VM and isolated lab network state
    kali_name: str | None = None
    kali_needs_nic = False
    kali_mac: str | None = None

    if not skip_kali_check and conn is not None:
        kali_dom = find_kali_domain(conn)
        if kali_dom is not None:
            kali_name = kali_dom.name()
            try:
                k_info = inspect_kali_lab_attachment(kali_dom.XMLDesc(0), network_name)
                kali_needs_nic = not k_info["has_lab_nic"]
                kali_mac = k_info.get("lab_mac")
            except Exception:
                pass

    if not kali_mac:
        kali_mac = generate_kvm_mac(existing_macs, seed_str=f"kali-{network_name}")

    lab_net_spec: LabNetworkSpec | None = inspect_or_plan_lab_network(
        conn, network_name=network_name, kali_mac=kali_mac
    )

    return ImportPlan(
        source_path=source_path.resolve(),
        vm_name=resolved_name,
        original_vm_name=vmx.display_name,
        os_family=os_family,
        os_distro=os_distro,
        libosinfo_id=libosinfo_id,
        arch="x86_64",
        machine_type="q35" if use_pci_bridge else "pc",
        firmware=firmware,
        ovmf_code_path=ovmf_code,
        vcpus=vcpus,
        memory_mb=memory_mb,
        use_pci_bridge_for_slot_naming=use_pci_bridge,
        disks=target_disks,
        nics=target_nics,
        video_model="vga",
        lab_network=lab_net_spec,
        kali_domain_name=kali_name,
        kali_needs_lab_nic=kali_needs_nic,
        warnings=warnings,
        notes=notes,
    )
