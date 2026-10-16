"""VM lifecycle management: list, start, stop, info, remove, and lab network operations."""

from __future__ import annotations

import json
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .config import DEFAULT_KALI_NAMES, DEFAULT_LAB_NETWORK
from .errors import LabImportError, LibvirtOperationError
from .network import (
    ensure_lab_network_active,
    find_kali_domain,
    get_network_dhcp_leases,
    inspect_kali_lab_attachment,
    inspect_or_plan_lab_network,
)
from .xml_builder import extract_lab_metadata_from_xml

DOMAIN_STATE_NAMES = {
    0: "No state",
    1: "Running",
    2: "Blocked",
    3: "Paused",
    4: "Shutting down",
    5: "Shut off",
    6: "Crashed",
    7: "Suspended",
}


def list_domains_summary(
    conn: Any, *, include_non_lab: bool = True
) -> list[dict[str, Any]]:
    """Return structured summary of all libvirt domains (marking lab-imported VMs and Kali)."""
    all_doms = conn.listAllDomains(0)
    leases_by_mac: dict[str, list[str]] = {}

    for net_obj in conn.listAllNetworks(0):
        try:
            if net_obj.isActive():
                for lease in net_obj.DHCPLeases():
                    mac = (lease.get("mac") or "").lower()
                    ip = lease.get("ipaddr")
                    if mac and ip:
                        leases_by_mac.setdefault(mac, []).append(
                            f"{ip} ({net_obj.name()})"
                        )
        except Exception:
            continue

    items: list[dict[str, Any]] = []
    for dom in sorted(all_doms, key=lambda d: d.name().lower()):
        name = dom.name()
        state_code, _ = dom.state()
        state_str = DOMAIN_STATE_NAMES.get(state_code, "Unknown")
        xml_str = dom.XMLDesc(0)
        root = ET.fromstring(xml_str)
        lab_meta = extract_lab_metadata_from_xml(xml_str)
        is_kali = name.lower() in {n.lower() for n in DEFAULT_KALI_NAMES}

        if not include_non_lab and not lab_meta and not is_kali:
            continue

        vcpus = int(root.findtext("vcpu") or "0")
        mem_kib = int(root.findtext("memory") or "0")
        mem_mib = mem_kib // 1024

        nets: list[str] = []
        ips: list[str] = []
        for iface in root.findall("./devices/interface"):
            src = iface.find("source")
            mac_el = iface.find("mac")
            net_name = src.attrib.get("network", "") if src is not None else ""
            if net_name:
                nets.append(net_name)
            mac = (mac_el.attrib.get("address", "") if mac_el is not None else "").lower()
            if mac in leases_by_mac:
                ips.extend(leases_by_mac[mac])

        disks: list[str] = []
        for disk_el in root.findall("./devices/disk[@device='disk']/source"):
            f = disk_el.attrib.get("file")
            if f:
                disks.append(f)

        role = "Lab Target" if lab_meta else ("Attacker (Kali)" if is_kali else "System VM")
        items.append(
            {
                "name": name,
                "role": role,
                "state": state_str,
                "is_active": bool(dom.isActive()),
                "vcpus": vcpus,
                "memory_mib": mem_mib,
                "networks": nets,
                "ips": ips,
                "disks": disks,
                "lab_metadata": lab_meta,
            }
        )
    return items


def lookup_domain_case_insensitive(conn: Any, vm_name: str) -> Any:
    """Find a libvirt domain by exact or case-insensitive name."""
    try:
        return conn.lookupByName(vm_name)
    except Exception:
        pass
    target_low = vm_name.lower()
    for dom in conn.listAllDomains(0):
        if dom.name().lower() == target_low:
            return dom
    raise LibvirtOperationError(
        f"Virtual machine {vm_name!r} not found in libvirt.",
        hint="Run `lab-list` to see all available virtual machines.",
    )


def get_vm_detailed_info(conn: Any, vm_name: str) -> dict[str, Any]:
    """Gather comprehensive hardware, disk, network, and metadata info for a VM."""
    dom = lookup_domain_case_insensitive(conn, vm_name)
    state_code, _ = dom.state()
    state_str = DOMAIN_STATE_NAMES.get(state_code, "Unknown")
    xml_str = dom.XMLDesc(0)
    root = ET.fromstring(xml_str)
    lab_meta = extract_lab_metadata_from_xml(xml_str)

    os_type_el = root.find("./os/type")
    arch = os_type_el.attrib.get("arch", "x86_64") if os_type_el is not None else "x86_64"
    machine = os_type_el.attrib.get("machine", "pc") if os_type_el is not None else "pc"
    os_el = root.find("os")
    firmware = (
        os_el.attrib.get("firmware", "bios")
        if os_el is not None and "firmware" in os_el.attrib
        else ("efi" if root.find("./os/loader") is not None else "bios")
    )

    disks_info: list[dict[str, Any]] = []
    for d_el in root.findall("./devices/disk[@device='disk']"):
        src_el = d_el.find("source")
        tgt_el = d_el.find("target")
        drv_el = d_el.find("driver")
        fpath = src_el.attrib.get("file", "") if src_el is not None else ""
        dev = tgt_el.attrib.get("dev", "") if tgt_el is not None else ""
        bus = tgt_el.attrib.get("bus", "") if tgt_el is not None else ""
        fmt = drv_el.attrib.get("type", "") if drv_el is not None else ""
        size_bytes = 0
        actual_bytes = 0
        if fpath:
            try:
                vol = conn.storageVolLookupByPath(fpath)
                vinfo = vol.info()
                size_bytes = int(vinfo[1])
                actual_bytes = int(vinfo[2])
            except Exception:
                p = Path(fpath)
                if p.is_file():
                    actual_bytes = p.stat().st_size
        disks_info.append(
            {
                "dev": dev,
                "bus": bus,
                "format": fmt,
                "path": fpath,
                "virtual_size_bytes": size_bytes,
                "actual_size_bytes": actual_bytes,
            }
        )

    leases_by_mac: dict[str, list[dict[str, str]]] = {}
    for net_obj in conn.listAllNetworks(0):
        try:
            if net_obj.isActive():
                for lease in net_obj.DHCPLeases():
                    mac = (lease.get("mac") or "").lower()
                    if mac:
                        leases_by_mac.setdefault(mac, []).append(
                            {
                                "network": net_obj.name(),
                                "ip": lease.get("ipaddr", ""),
                                "hostname": lease.get("hostname") or "",
                            }
                        )
        except Exception:
            continue

    nics_info: list[dict[str, Any]] = []
    for iface in root.findall("./devices/interface"):
        src_el = iface.find("source")
        mac_el = iface.find("mac")
        mod_el = iface.find("model")
        addr_el = iface.find("address")
        mac = (mac_el.attrib.get("address", "") if mac_el is not None else "").lower()
        pci_str = ""
        if addr_el is not None and addr_el.attrib.get("type") == "pci":
            bus_hex = addr_el.attrib.get("bus", "0x00")
            slot_hex = addr_el.attrib.get("slot", "0x00")
            pci_str = f"bus={bus_hex}, slot={slot_hex}"
        nics_info.append(
            {
                "network": src_el.attrib.get("network", "") if src_el is not None else "",
                "model": mod_el.attrib.get("type", "") if mod_el is not None else "",
                "mac": mac,
                "pci": pci_str,
                "leases": leases_by_mac.get(mac, []),
            }
        )

    return {
        "name": dom.name(),
        "uuid": dom.UUIDString(),
        "state": state_str,
        "is_active": bool(dom.isActive()),
        "autostart": bool(dom.autostart()),
        "vcpus": int(root.findtext("vcpu") or "0"),
        "memory_mib": int(root.findtext("memory") or "0") // 1024,
        "arch": arch,
        "machine": machine,
        "firmware": firmware.upper(),
        "disks": disks_info,
        "nics": nics_info,
        "lab_metadata": lab_meta,
        "xml": xml_str,
    }


def start_lab_vm(
    conn: Any,
    vm_name: str,
    *,
    wait_ip: bool = False,
    timeout_sec: int = 45,
) -> dict[str, Any]:
    """Start a VM (ensuring its attached networks are active) and optionally wait for DHCP IP."""
    dom = lookup_domain_case_insensitive(conn, vm_name)
    xml_str = dom.XMLDesc(0)
    root = ET.fromstring(xml_str)

    # Ensure all attached libvirt networks are active before starting the VM
    target_macs: set[str] = set()
    net_names: list[str] = []
    for iface in root.findall("./devices/interface[@type='network']"):
        src = iface.find("source")
        mac_el = iface.find("mac")
        if mac_el is not None and mac_el.attrib.get("address"):
            target_macs.add(mac_el.attrib["address"].lower())
        if src is not None and src.attrib.get("network"):
            nname = src.attrib["network"]
            net_names.append(nname)
            try:
                net_obj = conn.networkLookupByName(nname)
                if not net_obj.isActive():
                    net_obj.create()
            except Exception as exc:
                if nname == DEFAULT_LAB_NETWORK:
                    spec = inspect_or_plan_lab_network(conn, network_name=nname)
                    ensure_lab_network_active(conn, spec)
                else:
                    raise LibvirtOperationError(
                        f"Network {nname!r} required by {dom.name()} could not be started: {exc}"
                    ) from exc

    already_running = bool(dom.isActive())
    if not already_running:
        try:
            dom.create()
        except Exception as exc:
            raise LibvirtOperationError(
                f"Failed to start VM {dom.name()!r}: {exc}"
            ) from exc

    discovered_ip: str | None = None
    if wait_ip and net_names:
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            for nname in net_names:
                for lease in get_network_dhcp_leases(conn, nname):
                    if (lease.get("mac") or "").lower() in target_macs and lease.get("ipaddr"):
                        discovered_ip = f"{lease['ipaddr']} ({nname})"
                        break
                if discovered_ip:
                    break
            if discovered_ip:
                break
            time.sleep(1.5)

    return {
        "name": dom.name(),
        "already_running": already_running,
        "ip": discovered_ip,
    }


def stop_lab_vm(
    conn: Any,
    vm_name: str,
    *,
    force: bool = False,
    timeout_sec: int = 30,
) -> dict[str, Any]:
    """Gracefully shut down (`shutdown`) or force power-off (`destroy`) a VM."""
    dom = lookup_domain_case_insensitive(conn, vm_name)
    if not dom.isActive():
        return {"name": dom.name(), "was_running": False, "method": "already_off"}

    if force:
        dom.destroy()
        return {"name": dom.name(), "was_running": True, "method": "forced_poweroff"}

    dom.shutdown()
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        if not dom.isActive():
            return {"name": dom.name(), "was_running": True, "method": "graceful_shutdown"}
        time.sleep(1.0)

    raise LibvirtOperationError(
        f"VM {dom.name()!r} did not finish shutting down within {timeout_sec}s.",
        hint=f"Run `lab-stop {dom.name()} --force` to force power off the machine.",
    )


def remove_lab_vm(
    conn: Any,
    vm_name: str,
    *,
    delete_disks: bool = True,
    allow_non_lab: bool = False,
) -> dict[str, Any]:
    """Undefine a lab VM and optionally delete its converted QCOW2 disk volumes.

    Protects `kalilinux` and non-imported system VMs. Never deletes original source archives.
    """
    dom = lookup_domain_case_insensitive(conn, vm_name)
    actual_name = dom.name()

    if actual_name.lower() in {n.lower() for n in DEFAULT_KALI_NAMES}:
        raise LabImportError(
            f"Refusing to remove protected Kali Linux VM ({actual_name!r})."
        )

    xml_str = dom.XMLDesc(0)
    lab_meta = extract_lab_metadata_from_xml(xml_str)
    if not lab_meta and not allow_non_lab:
        raise LabImportError(
            f"VM {actual_name!r} was not created by lab-import.",
            hint="Pass --allow-non-lab if you really intend to remove a manually created VM.",
        )

    root = ET.fromstring(xml_str)
    disk_paths = [
        el.attrib.get("file", "")
        for el in root.findall("./devices/disk[@device='disk']/source")
        if el.attrib.get("file")
    ]

    if dom.isActive():
        dom.destroy()

    try:
        # VIR_DOMAIN_UNDEFINE_NVRAM (4) | VIR_DOMAIN_UNDEFINE_MANAGED_SAVE (1)
        dom.undefineFlags(4 | 1)
    except Exception:
        dom.undefine()

    deleted_disks: list[str] = []
    if delete_disks:
        for dpath in disk_paths:
            # Safety guard: only delete .qcow2 files, never .vmdk or source archives
            if not dpath.lower().endswith(".qcow2"):
                continue
            try:
                vol = conn.storageVolLookupByPath(dpath)
                vol.delete(0)
                deleted_disks.append(dpath)
            except Exception:
                p = Path(dpath)
                if p.is_file():
                    p.unlink()
                    deleted_disks.append(dpath)

    return {
        "name": actual_name,
        "deleted_disks": deleted_disks,
        "preserved_disks": [] if delete_disks else disk_paths,
        "source_preserved": lab_meta.get("source_path") if lab_meta else None,
    }


def get_lab_network_status(
    conn: Any, network_name: str = DEFAULT_LAB_NETWORK
) -> dict[str, Any]:
    """Return comprehensive status of the isolated penetration-testing network."""
    spec = inspect_or_plan_lab_network(conn, network_name=network_name)
    leases = get_network_dhcp_leases(conn, network_name) if spec.already_exists else []

    attached_vms: list[dict[str, Any]] = []
    for dom in conn.listAllDomains(0):
        xml_str = dom.XMLDesc(0)
        root = ET.fromstring(xml_str)
        for iface in root.findall("./devices/interface[@type='network']"):
            src = iface.find("source")
            mac_el = iface.find("mac")
            mod_el = iface.find("model")
            if src is not None and src.attrib.get("network") == network_name:
                mac = (mac_el.attrib.get("address", "") if mac_el is not None else "").lower()
                matched_ips = [
                    l.get("ipaddr", "")
                    for l in leases
                    if (l.get("mac") or "").lower() == mac and l.get("ipaddr")
                ]
                attached_vms.append(
                    {
                        "vm": dom.name(),
                        "active": bool(dom.isActive()),
                        "mac": mac,
                        "model": mod_el.attrib.get("type", "") if mod_el is not None else "",
                        "ips": matched_ips,
                    }
                )

    kali_dom = find_kali_domain(conn)
    kali_info = None
    if kali_dom is not None:
        k_attach = inspect_kali_lab_attachment(kali_dom.XMLDesc(0), network_name)
        kali_info = {
            "name": kali_dom.name(),
            "active": bool(kali_dom.isActive()),
            **k_attach,
        }

    return {
        "spec": spec,
        "leases": leases,
        "attached_vms": attached_vms,
        "kali": kali_info,
    }


def discover_lab_subnet_hosts(
    conn: Any,
    network_name: str = DEFAULT_LAB_NETWORK,
    *,
    ping_sweep: bool = False,
) -> list[dict[str, str]]:
    """Perform safe, restricted discovery of hosts on the isolated lab network."""
    status = get_lab_network_status(conn, network_name)
    spec = status["spec"]
    if not spec.already_exists or not spec.is_active:
        return []

    by_mac: dict[str, dict[str, str]] = {}
    for vm_entry in status["attached_vms"]:
        mac = vm_entry["mac"].lower()
        by_mac[mac] = {
            "vm": vm_entry["vm"],
            "state": "Running" if vm_entry["active"] else "Shut off",
            "mac": mac,
            "ip": ", ".join(vm_entry["ips"]) if vm_entry["ips"] else "-",
            "source": "dhcp-lease" if vm_entry["ips"] else "domain-xml",
        }

    for lease in status["leases"]:
        mac = (lease.get("mac") or "").lower()
        ip = lease.get("ipaddr", "")
        if mac in by_mac:
            by_mac[mac]["ip"] = ip
            by_mac[mac]["source"] = "dhcp-lease"
        elif mac:
            by_mac[mac] = {
                "vm": lease.get("hostname") or "unknown",
                "state": "Running",
                "mac": mac,
                "ip": ip,
                "source": "dhcp-lease",
            }

    if ping_sweep:
        # Lightweight broadcast/gateway ping restricted strictly to the isolated bridge interface
        subprocess.run(
            ["ping", "-c", "1", "-W", "1", "-b", "-I", spec.bridge_name, spec.dhcp_end],
            capture_output=True,
            check=False,
        )

    # Check host kernel ARP/neighbor cache on virbr-lab
    proc = subprocess.run(
        ["ip", "-j", "-4", "neigh", "show", "dev", spec.bridge_name],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        try:
            neighs = json.loads(proc.stdout)
            for n in neighs:
                mac = (n.get("lladdr") or "").lower()
                dst = n.get("dst", "")
                if mac and dst:
                    if mac in by_mac and by_mac[mac]["ip"] == "-":
                        by_mac[mac]["ip"] = dst
                        by_mac[mac]["source"] = "arp-cache"
                    elif mac not in by_mac:
                        by_mac[mac] = {
                            "vm": "unknown",
                            "state": "Reachable",
                            "mac": mac,
                            "ip": dst,
                            "source": "arp-cache",
                        }
        except json.JSONDecodeError:
            pass

    return list(by_mac.values())
