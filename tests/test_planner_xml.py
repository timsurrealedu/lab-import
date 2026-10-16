"""Unit tests for hardware translation planning and libvirt domain XML generation."""

from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET

from lab_import.models import VMDKAnalysis, VMDKExtentInfo
from lab_import.planner import build_import_plan
from lab_import.vmx_parser import parse_vmx_file
from lab_import.xml_builder import (
    build_domain_xml,
    extract_lab_metadata_from_xml,
    validate_xml_with_libvirt_schema,
)
from tests.test_vmx_parser import LINKEDBASE_VMX_SAMPLE


def test_linkedbase_plan_and_xml_validates(tmp_path: Path) -> None:
    vmx_path = tmp_path / "LinkedBase.vmx"
    vmx_path.write_text(LINKEDBASE_VMX_SAMPLE, encoding="utf-8")
    vmdk_path = tmp_path / "LinkedBase.vmdk"
    vmdk_path.write_text("# dummy", encoding="utf-8")

    vmx = parse_vmx_file(vmx_path)
    d_analysis = VMDKAnalysis(
        descriptor_path=vmdk_path,
        format="vmdk",
        create_type="twoGbMaxExtentSparse",
        virtual_size_bytes=20 * 1024**3,
        actual_size_bytes=8 * 1024**3,
        extents=[
            VMDKExtentInfo(
                access="RW",
                sectors=8323072,
                extent_type="SPARSE",
                filename="LinkedBase-s001.vmdk",
                exists=True,
            )
        ],
    )

    plan = build_import_plan(
        vmx_path,
        vmx,
        [d_analysis],
        storage_dir=tmp_path / "images",
    )

    assert plan.vm_name == "LinkedBase"
    assert plan.os_family == "linux"
    assert "Ubuntu 20.04" in plan.os_distro
    assert plan.vcpus == 2
    assert plan.memory_mb == 2048
    assert plan.firmware == "bios"
    assert plan.disks[0].bus == "sata"
    assert plan.disks[0].target_dev == "sda"
    assert plan.nics[0].network_name == "pentest-lab"
    assert plan.nics[0].model == "e1000e"
    assert plan.nics[0].pci_bus == 1
    assert plan.nics[0].pci_slot == 0
    assert plan.nics[0].expected_guest_ifname == "ens33"
    assert plan.machine_type == "q35"

    xml_str = build_domain_xml(plan)
    validate_xml_with_libvirt_schema(xml_str, "domain")

    meta = extract_lab_metadata_from_xml(xml_str)
    assert meta is not None
    assert meta["original_name"] == "LinkedBase"
    assert meta["network"] == "pentest-lab"

    root = ET.fromstring(xml_str)
    iface_addr = root.find("./devices/interface/address")
    assert iface_addr is not None
    assert iface_addr.attrib["bus"] == "0x01"
    assert iface_addr.attrib["slot"] == "0x00"
