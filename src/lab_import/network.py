"""Isolated penetration-testing network management and safe Kali Linux dual-NIC integration."""

from __future__ import annotations

import datetime
import ipaddress
import json
import logging
import random
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .config import (
    DEFAULT_KALI_NAMES,
    DEFAULT_LAB_BRIDGE,
    DEFAULT_LAB_NETWORK,
    get_backups_dir,
)
from .errors import LibvirtOperationError, NetworkConfigError
from .models import LabNetworkSpec

logger = logging.getLogger("lab_import.network")

CANDIDATE_SUBNETS = [
    "10.10.10.0/24",
    "10.10.20.0/24",
    "10.10.30.0/24",
    "10.240.0.0/24",
    "192.168.100.0/24",
    "192.168.144.0/24",
    "172.28.100.0/24",
] + [f"10.10.{i}.0/24" for i in range(40, 250)]


def get_host_ipv4_networks(conn: Any = None) -> list[tuple[str, ipaddress.IPv4Network]]:
    """Collect all active and configured IPv4 subnets on the host and in libvirt."""
    networks: list[tuple[str, ipaddress.IPv4Network]] = []

    # 1. Host interfaces via `ip -j -4 addr show`
    try:
        proc = subprocess.run(
            ["ip", "-j", "-4", "addr", "show"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            data = json.loads(proc.stdout)
            for iface in data:
                ifname = iface.get("ifname", "unknown")
                for addr in iface.get("addr_info", []):
                    local = addr.get("local")
                    prefixlen = addr.get("prefixlen")
                    if local and prefixlen is not None:
                        net = ipaddress.IPv4Network(f"{local}/{prefixlen}", strict=False)
                        if not net.is_loopback:
                            networks.append((f"iface:{ifname}", net))
    except Exception as exc:
        logger.debug("Failed reading ip -j -4 addr show: %s", exc)

    # 2. Host routing table via `ip -j -4 route show`
    try:
        proc = subprocess.run(
            ["ip", "-j", "-4", "route", "show"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            routes = json.loads(proc.stdout)
            for r in routes:
                dst = r.get("dst")
                dev = r.get("dev", "route")
                if dst and dst != "default":
                    try:
                        net = ipaddress.IPv4Network(dst, strict=False)
                        if not net.is_loopback:
                            networks.append((f"route:{dev}", net))
                    except ValueError:
                        pass
    except Exception as exc:
        logger.debug("Failed reading ip -j -4 route show: %s", exc)

    # 3. Defined libvirt networks
    if conn is not None:
        try:
            for net_obj in conn.listAllNetworks(0):
                net_name = net_obj.name()
                xml_str = net_obj.XMLDesc(0)
                for parsed_net in parse_libvirt_network_subnets(xml_str):
                    networks.append((f"libvirt:{net_name}", parsed_net))
        except Exception as exc:
            logger.debug("Failed reading libvirt networks: %s", exc)

    return networks


def parse_libvirt_network_subnets(xml_str: str) -> list[ipaddress.IPv4Network]:
    """Extract IPv4 networks from a libvirt <network> XML string."""
    subnets: list[ipaddress.IPv4Network] = []
    try:
        root = ET.fromstring(xml_str)
        for ip_elem in root.findall("ip"):
            family = ip_elem.attrib.get("family", "ipv4")
            if family != "ipv4":
                continue
            addr = ip_elem.attrib.get("address")
            netmask = ip_elem.attrib.get("netmask")
            prefix = ip_elem.attrib.get("prefix")
            if addr and netmask:
                subnets.append(
                    ipaddress.IPv4Network(f"{addr}/{netmask}", strict=False)
                )
            elif addr and prefix:
                subnets.append(
                    ipaddress.IPv4Network(f"{addr}/{prefix}", strict=False)
                )
    except ET.ParseError:
        pass
    return subnets


def choose_unused_private_subnet(
    existing_networks: list[tuple[str, ipaddress.IPv4Network]],
    preferred_cidr: str | None = None,
) -> ipaddress.IPv4Network:
    """Pick a /24 private subnet that does not overlap with any existing host or libvirt subnet."""
    candidates = list(CANDIDATE_SUBNETS)
    if preferred_cidr:
        candidates.insert(0, preferred_cidr)

    for cidr in candidates:
        cand = ipaddress.IPv4Network(cidr, strict=False)
        collision = False
        for _source, existing in existing_networks:
            if cand.overlaps(existing):
                collision = True
                break
        if not collision:
            return cand

    raise NetworkConfigError(
        "Unable to find an unused private /24 subnet for the isolated lab network.",
        hint="Specify a custom subnet explicitly.",
    )


def generate_kvm_mac(existing_macs: set[str] | None = None, seed_str: str | None = None) -> str:
    """Generate a unicast QEMU/KVM MAC address (52:54:00:xx:xx:xx) avoiding collisions."""
    used = {m.lower() for m in (existing_macs or set())}
    rng = random.Random(seed_str) if seed_str else random.SystemRandom()
    for _ in range(1000):
        octets = [0x52, 0x54, 0x00, rng.randint(0x01, 0xFE), rng.randint(0x01, 0xFE), rng.randint(0x01, 0xFE)]
        mac = ":".join(f"{b:02x}" for b in octets)
        if mac not in used:
            return mac
    raise NetworkConfigError("Failed to generate a unique KVM MAC address.")


def get_all_domain_macs(conn: Any) -> set[str]:
    """Return all MAC addresses currently configured across all libvirt domains."""
    macs: set[str] = set()
    if conn is None:
        return macs
    try:
        for dom in conn.listAllDomains(0):
            try:
                root = ET.fromstring(dom.XMLDesc(0))
                for mac_el in root.findall("./devices/interface/mac"):
                    addr = mac_el.attrib.get("address")
                    if addr:
                        macs.add(addr.lower())
            except Exception:
                continue
    except Exception:
        pass
    return macs


def build_isolated_network_xml(spec: LabNetworkSpec) -> str:
    """Build libvirt XML for a strictly isolated virtual network (no <forward> element!).

    Because there is NO <forward> element:
    1. libvirt enforces firewall isolation (guests on this bridge can communicate with
       each other and Kali, but CANNOT reach the internet or physical LAN).
    2. libvirt configures dnsmasq with `dhcp-option=3` (no default gateway router),
       ensuring Kali's second interface does NOT override Kali's primary default route!
    """
    net_el = ET.Element("network")
    name_el = ET.SubElement(net_el, "name")
    name_el.text = spec.name

    ET.SubElement(
        net_el,
        "bridge",
        {"name": spec.bridge_name, "stp": "on", "delay": "0"},
    )
    ET.SubElement(
        net_el,
        "domain",
        {"name": "pentest.lab", "localOnly": "yes"},
    )

    ip_el = ET.SubElement(
        net_el,
        "ip",
        {"address": spec.gateway_ip, "netmask": spec.netmask},
    )
    dhcp_el = ET.SubElement(ip_el, "dhcp")
    ET.SubElement(
        dhcp_el,
        "range",
        {"start": spec.dhcp_start, "end": spec.dhcp_end},
    )
    if spec.kali_mac and spec.kali_reserved_ip:
        ET.SubElement(
            dhcp_el,
            "host",
            {
                "mac": spec.kali_mac,
                "name": "kali-lab",
                "ip": spec.kali_reserved_ip,
            },
        )

    ET.indent(net_el, space="  ")
    return ET.tostring(net_el, encoding="unicode") + "\n"


def inspect_or_plan_lab_network(
    conn: Any,
    network_name: str = DEFAULT_LAB_NETWORK,
    preferred_cidr: str | None = None,
    kali_mac: str | None = None,
) -> LabNetworkSpec:
    """Inspect whether `pentest-lab` already exists in libvirt or plan its creation."""
    if conn is not None:
        try:
            net_obj = conn.networkLookupByName(network_name)
            xml_str = net_obj.XMLDesc(0)
            root = ET.fromstring(xml_str)
            fwd = root.find("forward")
            is_isolated = fwd is None
            bridge_el = root.find("bridge")
            bridge_name = (
                bridge_el.attrib.get("name", DEFAULT_LAB_BRIDGE)
                if bridge_el is not None
                else DEFAULT_LAB_BRIDGE
            )
            ip_el = root.find("ip")
            if ip_el is not None:
                gw = ip_el.attrib.get("address", "10.10.10.1")
                mask = ip_el.attrib.get("netmask", "255.255.255.0")
                net = ipaddress.IPv4Network(f"{gw}/{mask}", strict=False)
                range_el = ip_el.find("./dhcp/range")
                hosts = list(net.hosts())
                dhcp_start = (
                    range_el.attrib.get("start", str(hosts[9]))
                    if range_el is not None
                    else str(hosts[9])
                )
                dhcp_end = (
                    range_el.attrib.get("end", str(hosts[-5]))
                    if range_el is not None
                    else str(hosts[-5])
                )
                host_el = ip_el.find("./dhcp/host")
                kali_ip = (
                    host_el.attrib.get("ip") if host_el is not None else str(hosts[1])
                )
                k_mac = (
                    host_el.attrib.get("mac") if host_el is not None else kali_mac
                )
                return LabNetworkSpec(
                    name=network_name,
                    bridge_name=bridge_name,
                    subnet_cidr=str(net),
                    gateway_ip=gw,
                    netmask=mask,
                    dhcp_start=dhcp_start,
                    dhcp_end=dhcp_end,
                    kali_reserved_ip=kali_ip,
                    kali_mac=k_mac,
                    already_exists=True,
                    is_active=bool(net_obj.isActive()),
                    is_isolated=is_isolated,
                )
        except Exception:
            pass

    existing_nets = get_host_ipv4_networks(conn)
    chosen = choose_unused_private_subnet(existing_nets, preferred_cidr=preferred_cidr)
    hosts = list(chosen.hosts())
    gw_ip = str(hosts[0])  # e.g. 10.10.10.1
    kali_ip = str(hosts[1])  # e.g. 10.10.10.2
    dhcp_start = str(hosts[9])  # e.g. 10.10.10.10
    dhcp_end = str(hosts[-5])  # e.g. 10.10.10.250

    return LabNetworkSpec(
        name=network_name,
        bridge_name=DEFAULT_LAB_BRIDGE,
        subnet_cidr=str(chosen),
        gateway_ip=gw_ip,
        netmask=str(chosen.netmask),
        dhcp_start=dhcp_start,
        dhcp_end=dhcp_end,
        kali_reserved_ip=kali_ip,
        kali_mac=kali_mac,
        already_exists=False,
        is_active=False,
        is_isolated=True,
    )


def ensure_lab_network_active(conn: Any, spec: LabNetworkSpec) -> LabNetworkSpec:
    """Create (if needed), start, and enable autostart on the isolated lab network."""
    try:
        net_obj = conn.networkLookupByName(spec.name)
        xml_str = net_obj.XMLDesc(0)
        root = ET.fromstring(xml_str)
        if root.find("forward") is not None:
            raise NetworkConfigError(
                f"Existing libvirt network {spec.name!r} has forwarding enabled and is NOT isolated!",
                hint="Refusing to attach vulnerable VMs to a non-isolated network.",
            )
    except NetworkConfigError:
        raise
    except Exception:
        xml_str = build_isolated_network_xml(spec)
        try:
            net_obj = conn.networkDefineXML(xml_str)
        except Exception as exc:
            raise NetworkConfigError(
                f"Failed to define isolated libvirt network {spec.name!r}: {exc}"
            ) from exc

    try:
        if not net_obj.isActive():
            net_obj.create()
        if not net_obj.autostart():
            net_obj.setAutostart(1)
    except Exception as exc:
        raise NetworkConfigError(
            f"Failed to start or enable autostart for network {spec.name!r}: {exc}"
        ) from exc

    spec.already_exists = True
    spec.is_active = True
    return spec


def find_kali_domain(conn: Any, explicit_name: str | None = None) -> Any | None:
    """Locate the user's Kali Linux domain in libvirt (handling kalilinux / kaliLinux)."""
    if conn is None:
        return None
    candidates = [explicit_name] if explicit_name else list(DEFAULT_KALI_NAMES)
    try:
        all_doms = conn.listAllDomains(0)
    except Exception:
        return None

    by_exact = {d.name(): d for d in all_doms}
    by_lower = {d.name().lower(): d for d in all_doms}

    for cand in candidates:
        if not cand:
            continue
        if cand in by_exact:
            return by_exact[cand]
        if cand.lower() in by_lower:
            return by_lower[cand.lower()]
    return None


def inspect_kali_lab_attachment(
    kali_xml: str, lab_network_name: str = DEFAULT_LAB_NETWORK
) -> dict[str, Any]:
    """Inspect Kali's domain XML for its existing interfaces and whether it's on pentest-lab."""
    root = ET.fromstring(kali_xml)
    interfaces: list[dict[str, str]] = []
    has_lab_nic = False
    lab_mac: str | None = None
    has_nat_nic = False

    for iface in root.findall("./devices/interface"):
        itype = iface.attrib.get("type", "")
        src_el = iface.find("source")
        mac_el = iface.find("mac")
        model_el = iface.find("model")
        net_name = src_el.attrib.get("network", "") if src_el is not None else ""
        mac = mac_el.attrib.get("address", "") if mac_el is not None else ""
        model = model_el.attrib.get("type", "") if model_el is not None else ""
        interfaces.append(
            {
                "type": itype,
                "network": net_name,
                "mac": mac,
                "model": model,
            }
        )
        if itype == "network" and net_name == lab_network_name:
            has_lab_nic = True
            lab_mac = mac
        if itype == "network" and net_name == "default":
            has_nat_nic = True

    return {
        "has_lab_nic": has_lab_nic,
        "lab_mac": lab_mac,
        "has_nat_nic": has_nat_nic,
        "interfaces": interfaces,
    }


def backup_domain_xml(domain_name: str, xml_str: str) -> Path:
    """Save a timestamped backup of a libvirt domain's XML before modifying it."""
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = get_backups_dir() / f"{domain_name}-{ts}.xml"
    backup_path.write_text(xml_str, encoding="utf-8")
    return backup_path


def add_lab_nic_to_domain_xml(
    domain_xml: str,
    lab_network_name: str = DEFAULT_LAB_NETWORK,
    mac_address: str | None = None,
    model: str = "virtio",
) -> tuple[str, str]:
    """Add a second network interface connected to `lab_network_name` to a domain XML.

    Preserves all existing devices, disks, and the primary NAT network adapter.
    Returns (updated_xml, lab_nic_mac).
    """
    info = inspect_kali_lab_attachment(domain_xml, lab_network_name)
    if info["has_lab_nic"]:
        return domain_xml, info["lab_mac"] or ""

    root = ET.fromstring(domain_xml)
    devices_el = root.find("devices")
    if devices_el is None:
        raise LibvirtOperationError("Domain XML is missing <devices> section.")

    existing_macs = {i["mac"].lower() for i in info["interfaces"] if i.get("mac")}
    chosen_mac = mac_address or generate_kvm_mac(
        existing_macs, seed_str=f"kali-{lab_network_name}"
    )

    iface_el = ET.Element("interface", {"type": "network"})
    ET.SubElement(iface_el, "mac", {"address": chosen_mac})
    ET.SubElement(iface_el, "source", {"network": lab_network_name})
    ET.SubElement(iface_el, "model", {"type": model})

    # Insert right after the last existing <interface> for clean XML structure
    children = list(devices_el)
    last_iface_idx = -1
    for idx, child in enumerate(children):
        if child.tag == "interface":
            last_iface_idx = idx
    if last_iface_idx >= 0:
        devices_el.insert(last_iface_idx + 1, iface_el)
    else:
        devices_el.append(iface_el)

    ET.indent(root, space="  ")
    updated_xml = ET.tostring(root, encoding="unicode") + "\n"
    return updated_xml, chosen_mac


def attach_kali_to_lab_network(
    conn: Any,
    lab_network_name: str = DEFAULT_LAB_NETWORK,
    explicit_kali_name: str | None = None,
    preferred_mac: str | None = None,
) -> tuple[bool, Path | None, str | None]:
    """Ensure Kali Linux has a second NIC attached to `pentest-lab`.

    Returns (changed, backup_path, kali_lab_mac).
    """
    dom = find_kali_domain(conn, explicit_kali_name)
    if dom is None:
        return False, None, None

    # Use VIR_DOMAIN_XML_INACTIVE (2) if available so we inspect/update persistent config
    inactive_flag = 2
    try:
        orig_xml = dom.XMLDesc(inactive_flag)
    except Exception:
        orig_xml = dom.XMLDesc(0)

    info = inspect_kali_lab_attachment(orig_xml, lab_network_name)
    if info["has_lab_nic"]:
        return False, None, info["lab_mac"]

    backup_path = backup_domain_xml(dom.name(), orig_xml)
    updated_xml, chosen_mac = add_lab_nic_to_domain_xml(
        orig_xml,
        lab_network_name=lab_network_name,
        mac_address=preferred_mac,
        model="virtio",
    )

    try:
        if dom.isActive():
            # Attach live + persistent
            nic_xml = (
                f"<interface type='network'>"
                f"<mac address='{chosen_mac}'/>"
                f"<source network='{lab_network_name}'/>"
                f"<model type='virtio'/>"
                f"</interface>"
            )
            # VIR_DOMAIN_AFFECT_LIVE (1) | VIR_DOMAIN_AFFECT_CONFIG (2) = 3
            dom.attachDeviceFlags(nic_xml, 3)
        else:
            conn.defineXML(updated_xml)
    except Exception as exc:
        raise LibvirtOperationError(
            f"Failed to attach {lab_network_name!r} adapter to {dom.name()}: {exc}",
            hint=f"Original XML backup saved at {backup_path}",
        ) from exc

    return True, backup_path, chosen_mac


def get_network_dhcp_leases(conn: Any, network_name: str = DEFAULT_LAB_NETWORK) -> list[dict[str, Any]]:
    """Retrieve active DHCP leases from a libvirt network."""
    if conn is None:
        return []
    try:
        net_obj = conn.networkLookupByName(network_name)
        if not net_obj.isActive():
            return []
        return list(net_obj.DHCPLeases())
    except Exception:
        return []
