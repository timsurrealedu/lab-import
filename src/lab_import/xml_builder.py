"""Libvirt domain XML generation and schema validation."""

from __future__ import annotations

import datetime
import shutil
import subprocess
import tempfile
import uuid
import xml.etree.ElementTree as ET
from typing import Any

from .config import LIBOSINFO_NS_URI, METADATA_NS_PREFIX, METADATA_NS_URI
from .errors import ValidationFailedError
from .models import ImportPlan


QEMU_NS_URI = "http://libvirt.org/schemas/domain/qemu/1.0"


def build_domain_xml(plan: ImportPlan, domain_uuid: str | None = None) -> str:
    """Generate a complete, valid libvirt QEMU/KVM domain XML from an ImportPlan."""
    ET.register_namespace("libosinfo", LIBOSINFO_NS_URI)
    ET.register_namespace(METADATA_NS_PREFIX, METADATA_NS_URI)
    ET.register_namespace("qemu", QEMU_NS_URI)

    dom_uuid = domain_uuid or str(uuid.uuid4())
    dom = ET.Element("domain", {"type": "kvm"})

    name_el = ET.SubElement(dom, "name")
    name_el.text = plan.vm_name

    uuid_el = ET.SubElement(dom, "uuid")
    uuid_el.text = dom_uuid

    title_el = ET.SubElement(dom, "title")
    title_el.text = f"{plan.vm_name} ({plan.os_distro})"

    desc_el = ET.SubElement(dom, "description")
    desc_el.text = (
        f"Imported by lab-import from {plan.source_path.name} "
        f"(original VMware name: {plan.original_vm_name})"
    )

    # Metadata block for Virt-Manager (libosinfo) + lab-import provenance tracking
    meta_el = ET.SubElement(dom, "metadata")
    if plan.libosinfo_id:
        osinfo_el = ET.SubElement(meta_el, f"{{{LIBOSINFO_NS_URI}}}libosinfo")
        ET.SubElement(osinfo_el, f"{{{LIBOSINFO_NS_URI}}}os", {"id": plan.libosinfo_id})

    lab_meta = ET.SubElement(
        meta_el,
        f"{{{METADATA_NS_URI}}}vm",
        {
            "version": "1.0",
            "imported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "source_path": str(plan.source_path),
            "original_name": plan.original_vm_name,
            "os_distro": plan.os_distro,
            "network": plan.nics[0].network_name if plan.nics else "pentest-lab",
        },
    )
    for d in plan.disks:
        ET.SubElement(
            lab_meta,
            f"{{{METADATA_NS_URI}}}disk",
            {
                "path": str(d.target_path),
                "source_vmdk": d.source_vmdk.descriptor_path.name,
                "virtual_size": str(d.source_vmdk.virtual_size_bytes),
            },
        )

    mem_kib = str(plan.memory_mb * 1024)
    mem_el = ET.SubElement(dom, "memory", {"unit": "KiB"})
    mem_el.text = mem_kib
    cur_mem_el = ET.SubElement(dom, "currentMemory", {"unit": "KiB"})
    cur_mem_el.text = mem_kib

    vcpu_el = ET.SubElement(dom, "vcpu", {"placement": "static"})
    vcpu_el.text = str(plan.vcpus)

    os_attrs = {"firmware": "efi"} if plan.firmware == "efi" else {}
    os_el = ET.SubElement(dom, "os", os_attrs)
    type_el = ET.SubElement(
        os_el, "type", {"arch": plan.arch, "machine": plan.machine_type}
    )
    type_el.text = "hvm"
    if plan.firmware == "efi":
        fw_el = ET.SubElement(os_el, "firmware")
        ET.SubElement(fw_el, "feature", {"enabled": "no", "name": "secure-boot"})
        ET.SubElement(fw_el, "feature", {"enabled": "no", "name": "enrolled-keys"})
    ET.SubElement(os_el, "boot", {"dev": "hd"})

    features_el = ET.SubElement(dom, "features")
    ET.SubElement(features_el, "acpi")
    ET.SubElement(features_el, "apic")
    ET.SubElement(features_el, "vmport", {"state": "off"})

    ET.SubElement(
        dom,
        "cpu",
        {"mode": "host-passthrough", "check": "none", "migratable": "on"},
    )

    clock_el = ET.SubElement(
        dom,
        "clock",
        {"offset": "localtime" if plan.os_family == "windows" else "utc"},
    )
    ET.SubElement(clock_el, "timer", {"name": "rtc", "tickpolicy": "catchup"})
    ET.SubElement(clock_el, "timer", {"name": "pit", "tickpolicy": "delay"})
    ET.SubElement(clock_el, "timer", {"name": "hpet", "present": "no"})

    on_po = ET.SubElement(dom, "on_poweroff")
    on_po.text = "destroy"
    on_rb = ET.SubElement(dom, "on_reboot")
    on_rb.text = "restart"
    on_cr = ET.SubElement(dom, "on_crash")
    on_cr.text = "destroy"

    pm_el = ET.SubElement(dom, "pm")
    ET.SubElement(pm_el, "suspend-to-mem", {"enabled": "no"})
    ET.SubElement(pm_el, "suspend-to-disk", {"enabled": "no"})

    devices_el = ET.SubElement(dom, "devices")
    emu_el = ET.SubElement(devices_el, "emulator")
    emu_el.text = "/usr/bin/qemu-system-x86_64"

    # Disks
    needs_scsi_ctrl = False
    for d in plan.disks:
        if d.bus == "scsi":
            needs_scsi_ctrl = True
        disk_el = ET.SubElement(devices_el, "disk", {"type": "file", "device": "disk"})
        ET.SubElement(
            disk_el,
            "driver",
            {"name": "qemu", "type": "qcow2", "discard": "unmap"},
        )
        ET.SubElement(disk_el, "source", {"file": str(d.target_path)})
        ET.SubElement(disk_el, "target", {"dev": d.target_dev, "bus": d.bus})

    # Controllers
    ET.SubElement(
        devices_el,
        "controller",
        {"type": "usb", "index": "0", "model": "qemu-xhci"},
    )
    if needs_scsi_ctrl:
        ET.SubElement(
            devices_el,
            "controller",
            {"type": "scsi", "index": "0", "model": "virtio-scsi"},
        )
    if any(d.bus == "sata" for d in plan.disks):
        ET.SubElement(
            devices_el,
            "controller",
            {"type": "sata", "index": "0"},
        )

    slotted_nics = [
        nic
        for nic in plan.nics
        if nic.vmware_pci_slot is not None and nic.pci_bus is not None
    ]

    if plan.machine_type == "q35" and plan.use_pci_bridge_for_slot_naming and slotted_nics:
        ET.SubElement(
            devices_el,
            "controller",
            {"type": "pci", "index": "0", "model": "pcie-root"},
        )
        total_root_ports = len(slotted_nics) + 6
        for rp_idx in range(1, total_root_ports + 1):
            rp_el = ET.SubElement(
                devices_el,
                "controller",
                {"type": "pci", "index": str(rp_idx), "model": "pcie-root-port"},
            )
            ET.SubElement(rp_el, "model", {"name": "pcie-root-port"})
            if rp_idx <= len(slotted_nics):
                nic_obj = slotted_nics[rp_idx - 1]
                chassis_val = str(nic_obj.vmware_pci_slot or rp_idx)
                ET.SubElement(
                    rp_el,
                    "target",
                    {"chassis": chassis_val, "port": f"0x{15 + rp_idx:02x}"},
                )
                ET.SubElement(rp_el, "alias", {"name": f"ua-net-slot{nic_obj.index}"})
            else:
                ET.SubElement(
                    rp_el,
                    "target",
                    {"chassis": str(100 + rp_idx), "port": f"0x{15 + rp_idx:02x}"},
                )
        dmi_idx = total_root_ports + 1
        dmi_el = ET.SubElement(
            devices_el,
            "controller",
            {"type": "pci", "index": str(dmi_idx), "model": "pcie-to-pci-bridge"},
        )
        ET.SubElement(dmi_el, "model", {"name": "pcie-pci-bridge"})
    elif plan.machine_type == "pc" and plan.use_pci_bridge_for_slot_naming:
        ET.SubElement(
            devices_el,
            "controller",
            {"type": "pci", "index": "0", "model": "pci-root"},
        )
        bridge_el = ET.SubElement(
            devices_el,
            "controller",
            {"type": "pci", "index": "1", "model": "pci-bridge"},
        )
        ET.SubElement(bridge_el, "model", {"name": "pci-bridge"})
        ET.SubElement(bridge_el, "target", {"chassisNr": "1"})

    ET.SubElement(
        devices_el,
        "controller",
        {"type": "virtio-serial", "index": "0"},
    )

    # Network interfaces
    for nic in plan.nics:
        iface_el = ET.SubElement(devices_el, "interface", {"type": "network"})
        ET.SubElement(iface_el, "mac", {"address": nic.mac_address})
        ET.SubElement(iface_el, "source", {"network": nic.network_name})
        ET.SubElement(iface_el, "model", {"type": nic.model})
        if (
            plan.use_pci_bridge_for_slot_naming
            and nic.pci_bus is not None
            and nic.pci_slot is not None
        ):
            ET.SubElement(
                iface_el,
                "address",
                {
                    "type": "pci",
                    "domain": "0x0000",
                    "bus": f"0x{nic.pci_bus:02x}",
                    "slot": f"0x{nic.pci_slot:02x}",
                    "function": "0x0",
                },
            )

    # Serial & Console
    serial_el = ET.SubElement(devices_el, "serial", {"type": "pty"})
    ET.SubElement(serial_el, "target", {"type": "isa-serial", "port": "0"})
    console_el = ET.SubElement(devices_el, "console", {"type": "pty"})
    ET.SubElement(console_el, "target", {"type": "serial", "port": "0"})

    # Guest Agent & SPICE channels
    ga_chan = ET.SubElement(devices_el, "channel", {"type": "unix"})
    ET.SubElement(
        ga_chan,
        "target",
        {"type": "virtio", "name": "org.qemu.guest_agent.0"},
    )
    spice_chan = ET.SubElement(devices_el, "channel", {"type": "spicevmc"})
    ET.SubElement(
        spice_chan,
        "target",
        {"type": "virtio", "name": "com.redhat.spice.0"},
    )

    # Input devices (USB tablet for seamless cursor in Virt-Manager/Virt-Viewer)
    ET.SubElement(devices_el, "input", {"type": "tablet", "bus": "usb"})
    ET.SubElement(devices_el, "input", {"type": "mouse", "bus": "ps2"})
    ET.SubElement(devices_el, "input", {"type": "keyboard", "bus": "ps2"})

    # SPICE graphics + VGA video
    gfx_el = ET.SubElement(devices_el, "graphics", {"type": "spice", "autoport": "yes"})
    ET.SubElement(gfx_el, "listen", {"type": "address"})
    ET.SubElement(gfx_el, "image", {"compression": "off"})

    ET.SubElement(devices_el, "audio", {"id": "1", "type": "spice"})

    video_el = ET.SubElement(devices_el, "video")
    ET.SubElement(
        video_el,
        "model",
        {"type": plan.video_model, "vram": "16384", "heads": "1", "primary": "yes"},
    )

    ET.SubElement(devices_el, "memballoon", {"model": "virtio"})
    rng_el = ET.SubElement(devices_el, "rng", {"model": "virtio"})
    rng_back = ET.SubElement(rng_el, "backend", {"model": "random"})
    rng_back.text = "/dev/urandom"

    if plan.machine_type == "q35" and plan.use_pci_bridge_for_slot_naming and slotted_nics:
        cmd_el = ET.SubElement(dom, f"{{{QEMU_NS_URI}}}commandline")
        ET.SubElement(cmd_el, f"{{{QEMU_NS_URI}}}arg", {"value": "-global"})
        ET.SubElement(
            cmd_el,
            f"{{{QEMU_NS_URI}}}arg",
            {"value": "ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off"},
        )
        ovr_el = ET.SubElement(dom, f"{{{QEMU_NS_URI}}}override")
        for nic_obj in slotted_nics:
            dev_el = ET.SubElement(
                ovr_el,
                f"{{{QEMU_NS_URI}}}device",
                {"alias": f"ua-net-slot{nic_obj.index}"},
            )
            fe_el = ET.SubElement(dev_el, f"{{{QEMU_NS_URI}}}frontend")
            ET.SubElement(
                fe_el,
                f"{{{QEMU_NS_URI}}}property",
                {
                    "name": "slot",
                    "type": "unsigned",
                    "value": str(nic_obj.vmware_pci_slot),
                },
            )

    ET.indent(dom, space="  ")
    return ET.tostring(dom, encoding="unicode") + "\n"


def validate_xml_with_libvirt_schema(xml_str: str, schema_name: str = "domain") -> None:
    """Validate generated XML using `virt-xml-validate` if installed."""
    validator = shutil.which("virt-xml-validate")
    if not validator:
        # Parse check at minimum
        ET.fromstring(xml_str)
        return

    with tempfile.NamedTemporaryFile("w", suffix=".xml", encoding="utf-8") as tmp:
        tmp.write(xml_str)
        tmp.flush()
        proc = subprocess.run(
            [validator, tmp.name, schema_name],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise ValidationFailedError(
                f"Libvirt {schema_name} XML schema validation failed: "
                f"{proc.stderr.strip() or proc.stdout.strip()}"
            )


def extract_lab_metadata_from_xml(domain_xml: str) -> dict[str, Any] | None:
    """Extract lab-import provenance metadata from a domain XML if present."""
    try:
        root = ET.fromstring(domain_xml)
        vm_el = root.find(f"./metadata/{{{METADATA_NS_URI}}}vm")
        if vm_el is None:
            return None
        disks = []
        for d_el in vm_el.findall(f"{{{METADATA_NS_URI}}}disk"):
            disks.append(dict(d_el.attrib))
        info = dict(vm_el.attrib)
        info["disks"] = disks
        return info
    except ET.ParseError:
        return None
