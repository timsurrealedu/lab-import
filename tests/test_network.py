"""Unit tests for isolated lab network selection and safe Kali dual-NIC configuration."""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET

from lab_import.models import LabNetworkSpec
from lab_import.network import (
    add_lab_nic_to_domain_xml,
    build_isolated_network_xml,
    choose_unused_private_subnet,
    inspect_kali_lab_attachment,
)
from lab_import.xml_builder import validate_xml_with_libvirt_schema

SAMPLE_KALI_XML = """<domain type='kvm'>
  <name>kalilinux</name>
  <uuid>9fe14074-f147-44ab-b258-0dcf52a6e0c2</uuid>
  <memory unit='KiB'>8388608</memory>
  <vcpu placement='static'>4</vcpu>
  <os>
    <type arch='x86_64' machine='pc-q35-10.2'>hvm</type>
    <boot dev='hd'/>
  </os>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' discard='unmap'/>
      <source file='/var/lib/libvirt/images/kalilinux.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <filesystem type='mount' accessmode='passthrough'>
      <driver type='virtiofs'/>
      <source dir='/home/timsurreal/vm_share'/>
      <target dir='shared_data'/>
    </filesystem>
    <interface type='network'>
      <mac address='52:54:00:ba:66:53'/>
      <source network='default'/>
      <model type='virtio'/>
    </interface>
  </devices>
</domain>
"""


def test_subnet_collision_avoidance() -> None:
    existing = [
        ("iface:wlp191s0", ipaddress.IPv4Network("192.168.1.0/24")),
        ("iface:virbr0", ipaddress.IPv4Network("192.168.122.0/24")),
        ("iface:vmnet1", ipaddress.IPv4Network("192.168.181.0/24")),
        ("iface:vmnet8", ipaddress.IPv4Network("192.168.236.0/24")),
        ("iface:docker0", ipaddress.IPv4Network("172.17.0.0/16")),
        ("iface:tailscale0", ipaddress.IPv4Network("100.84.131.81/32")),
    ]
    chosen = choose_unused_private_subnet(existing)
    assert chosen == ipaddress.IPv4Network("10.10.10.0/24")
    for _, net in existing:
        assert not chosen.overlaps(net)

    # If 10.10.10.0/24 is already in use, must pick next non-overlapping candidate
    existing_with_10 = existing + [("custom", ipaddress.IPv4Network("10.10.10.0/24"))]
    chosen2 = choose_unused_private_subnet(existing_with_10)
    assert chosen2 == ipaddress.IPv4Network("10.10.20.0/24")


def test_isolated_network_xml_has_no_forwarding_and_validates() -> None:
    spec = LabNetworkSpec(
        name="pentest-lab",
        bridge_name="virbr-lab",
        subnet_cidr="10.10.10.0/24",
        gateway_ip="10.10.10.1",
        netmask="255.255.255.0",
        dhcp_start="10.10.10.10",
        dhcp_end="10.10.10.250",
        kali_reserved_ip="10.10.10.2",
        kali_mac="52:54:00:11:22:33",
    )
    xml_str = build_isolated_network_xml(spec)
    validate_xml_with_libvirt_schema(xml_str, "network")

    root = ET.fromstring(xml_str)
    # CRITICAL: Must have NO <forward> element so targets cannot reach internet/LAN
    # and dnsmasq sends dhcp-option=3 (no default gateway to override Kali's route!)
    assert root.find("forward") is None
    assert root.findtext("name") == "pentest-lab"
    host_el = root.find("./ip/dhcp/host")
    assert host_el is not None
    assert host_el.attrib["ip"] == "10.10.10.2"


def test_kali_second_nic_preserves_original_nat_and_is_idempotent() -> None:
    before = inspect_kali_lab_attachment(SAMPLE_KALI_XML, "pentest-lab")
    assert before["has_nat_nic"] is True
    assert before["has_lab_nic"] is False

    updated_xml, lab_mac = add_lab_nic_to_domain_xml(SAMPLE_KALI_XML, "pentest-lab")
    validate_xml_with_libvirt_schema(updated_xml, "domain")

    after = inspect_kali_lab_attachment(updated_xml, "pentest-lab")
    assert after["has_nat_nic"] is True
    assert after["has_lab_nic"] is True
    assert after["lab_mac"] == lab_mac
    assert len(after["interfaces"]) == 2
    assert after["interfaces"][0]["mac"] == "52:54:00:ba:66:53"
    assert after["interfaces"][0]["network"] == "default"
    assert after["interfaces"][1]["network"] == "pentest-lab"
    assert after["interfaces"][1]["model"] == "virtio"

    # Calling a second time must be idempotent
    updated_again, mac_again = add_lab_nic_to_domain_xml(updated_xml, "pentest-lab")
    assert mac_again == lab_mac
    after_again = inspect_kali_lab_attachment(updated_again, "pentest-lab")
    assert len(after_again["interfaces"]) == 2
