"""Transactional VM import orchestrator, rollback handler, and post-import validator."""

from __future__ import annotations

import grp
import logging
import os
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .config import DEFAULT_STORAGE_POOL
from .disks import (
    check_storage_space_for_conversion,
    convert_vmdk_to_qcow2,
    validate_qcow2_image,
)
from .errors import LibvirtOperationError, ValidationFailedError
from .models import (
    ImportPlan,
    ImportResult,
    TargetDiskPlan,
    ValidationCheck,
)
from .network import (
    attach_kali_to_lab_network,
    ensure_lab_network_active,
    get_network_dhcp_leases,
)
from .xml_builder import build_domain_xml, validate_xml_with_libvirt_schema

logger = logging.getLogger("lab_import.importer")


def get_libvirt_group_gid() -> int:
    """Return the GID of the 'libvirt' group if it exists, else current user's GID."""
    try:
        return grp.getgrnam("libvirt").gr_gid
    except KeyError:
        return os.getgid()


def create_writable_pool_volume(
    conn: Any,
    pool_name: str,
    vol_name: str,
    capacity_bytes: int,
) -> tuple[Any, Path]:
    """Pre-create a QCOW2 volume in a libvirt storage pool owned by the current user.

    This allows `qemu-img convert -n` to stream directly into `/var/lib/libvirt/images`
    at full NVMe speed without requiring `sudo` or root privileges.
    """
    pool = conn.storagePoolLookupByName(pool_name)
    if not pool.isActive():
        pool.create(0)

    uid = os.getuid()
    gid = get_libvirt_group_gid()
    vol_xml = f"""<volume>
  <name>{vol_name}</name>
  <capacity unit="bytes">{capacity_bytes}</capacity>
  <target>
    <format type="qcow2"/>
    <permissions>
      <mode>0660</mode>
      <owner>{uid}</owner>
      <group>{gid}</group>
    </permissions>
  </target>
</volume>"""
    vol = pool.createXML(vol_xml, 0)
    return vol, Path(vol.path())


def execute_import_plan(
    plan: ImportPlan,
    conn: Any,
    *,
    attach_kali: bool = True,
    replace_existing: bool = False,
    validate_boot: bool = False,
    start_after_import: bool = False,
    step_callback: Callable[[str], None] | None = None,
    disk_progress_callback: Callable[[int, int, str, float], None] | None = None,
) -> ImportResult:
    """Execute an ImportPlan transactionally with automatic rollback on failure."""
    created_volumes: list[Any] = []
    created_files: list[Path] = []
    defined_domain: Any | None = None

    def _notify(msg: str) -> None:
        logger.info(msg)
        if step_callback:
            step_callback(msg)

    try:
        # 1. Check free space across all planned disks
        total_required = sum(
            max(d.source_vmdk.actual_size_bytes, 64 * 1024 * 1024) for d in plan.disks
        )
        if plan.disks:
            check_storage_space_for_conversion(
                plan.disks[0].target_path.parent, total_required
            )

        # 2. If replacing an existing domain, remove its old definition/disks first
        if replace_existing and conn is not None:
            _remove_existing_domain_for_replace(conn, plan.vm_name)

        # 3. Ensure isolated lab network is configured and active
        if plan.lab_network is not None and conn is not None:
            ensure_lab_network_active(conn, plan.lab_network)
            _notify("Isolated lab network configured")

        # 4. Attach Kali VM to pentest-lab if requested and needed
        kali_attached = False
        kali_backup_path: Path | None = None
        if attach_kali and plan.kali_needs_lab_nic and conn is not None and plan.lab_network:
            kali_attached, kali_backup_path, _kali_mac = attach_kali_to_lab_network(
                conn,
                lab_network_name=plan.lab_network.name,
                explicit_kali_name=plan.kali_domain_name,
                preferred_mac=plan.lab_network.kali_mac,
            )

        # 5. Convert each disk to QCOW2
        converted_paths: list[Path] = []
        total_disks = len(plan.disks)
        for idx, d_plan in enumerate(plan.disks, start=1):
            src_vmdk = d_plan.source_vmdk.descriptor_path
            vsize = d_plan.source_vmdk.virtual_size_bytes

            use_pool_vol = False
            target_path = d_plan.target_path
            parent_dir = target_path.parent

            if (
                conn is not None
                and parent_dir == Path("/var/lib/libvirt/images")
                and not os.access(parent_dir, os.W_OK)
            ):
                vol_obj, target_path = create_writable_pool_volume(
                    conn,
                    DEFAULT_STORAGE_POOL,
                    d_plan.target_vol_name,
                    vsize,
                )
                created_volumes.append(vol_obj)
                d_plan.target_path = target_path
                use_pool_vol = True
            else:
                parent_dir.mkdir(parents=True, exist_ok=True)
                created_files.append(target_path)

            def _on_pct(pct: float, disk_idx: int = idx, name: str = src_vmdk.name) -> None:
                if disk_progress_callback:
                    disk_progress_callback(disk_idx, total_disks, name, pct)

            convert_vmdk_to_qcow2(
                src_vmdk,
                target_path,
                skip_create=use_pool_vol,
                expected_virtual_size=vsize,
                progress_callback=_on_pct,
            )
            converted_paths.append(target_path)

        if conn is not None:
            try:
                pool = conn.storagePoolLookupByName(DEFAULT_STORAGE_POOL)
                pool.refresh(0)
            except Exception:
                pass

        _notify("Disk converted to QCOW2")

        # 6. Build and validate libvirt domain XML
        domain_xml = build_domain_xml(plan)
        validate_xml_with_libvirt_schema(domain_xml, "domain")

        # 7. Define persistent domain in libvirt
        domain_uuid = ""
        if conn is not None:
            try:
                defined_domain = conn.defineXML(domain_xml)
                domain_uuid = defined_domain.UUIDString()
            except Exception as exc:
                raise LibvirtOperationError(
                    f"Failed to register domain {plan.vm_name!r} with libvirt: {exc}"
                ) from exc
        else:
            root = ET.fromstring(domain_xml)
            domain_uuid = root.findtext("uuid") or ""

        _notify("Libvirt domain created")

        # 8. Perform non-destructive post-import validation
        checks = validate_imported_vm(plan, conn, domain_xml)

        boot_ok = False
        discovered_ip: str | None = None
        if validate_boot and defined_domain is not None:
            boot_ok, discovered_ip = _run_boot_validation(
                conn,
                defined_domain,
                plan,
                keep_running=start_after_import,
            )
            checks.append(
                ValidationCheck(
                    name="Boot verification",
                    passed=boot_ok,
                    detail=(
                        f"VM started cleanly on KVM"
                        + (f" (DHCP IP: {discovered_ip})" if discovered_ip else "")
                    ),
                )
            )
        elif start_after_import and defined_domain is not None:
            defined_domain.create()

        _notify("VM registered successfully")

        return ImportResult(
            plan=plan,
            domain_uuid=domain_uuid,
            domain_xml=domain_xml,
            converted_disks=converted_paths,
            validation_checks=checks,
            boot_validated=boot_ok,
            discovered_ip=discovered_ip,
            kali_attached=kali_attached,
            kali_backup_path=kali_backup_path,
        )

    except BaseException as exc:
        logger.error("Import failed or interrupted (%s); rolling back artifacts...", exc)
        if defined_domain is not None:
            try:
                if defined_domain.isActive():
                    defined_domain.destroy()
                try:
                    # VIR_DOMAIN_UNDEFINE_NVRAM = 4
                    defined_domain.undefineFlags(4)
                except Exception:
                    defined_domain.undefine()
            except Exception as cleanup_exc:
                logger.warning("Rollback domain undefine warning: %s", cleanup_exc)

        for vol in created_volumes:
            try:
                vol.delete(0)
            except Exception as cleanup_exc:
                logger.warning("Rollback volume delete warning: %s", cleanup_exc)

        for fpath in created_files:
            try:
                fpath.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def validate_imported_vm(
    plan: ImportPlan, conn: Any, domain_xml: str
) -> list[ValidationCheck]:
    """Run non-destructive post-import validation checks on the newly created VM."""
    checks: list[ValidationCheck] = []

    # 1. QCOW2 image integrity
    for d in plan.disks:
        info = validate_qcow2_image(
            d.target_path, expected_virtual_size=d.source_vmdk.virtual_size_bytes
        )
        checks.append(
            ValidationCheck(
                name=f"QCOW2 integrity ({d.target_path.name})",
                passed=True,
                detail=f"Format=qcow2, virtual_size={int(info['virtual-size']) / (1024**3):.2f} GiB",
            )
        )

    # 2. Firmware availability
    if plan.firmware == "efi":
        fw_ok = bool(plan.ovmf_code_path and plan.ovmf_code_path.is_file())
        if not fw_ok:
            raise ValidationFailedError("UEFI OVMF firmware file is missing.")
        checks.append(
            ValidationCheck(
                name="Firmware availability",
                passed=True,
                detail=f"UEFI ({plan.ovmf_code_path})",
            )
        )
    else:
        checks.append(
            ValidationCheck(
                name="Firmware availability",
                passed=True,
                detail="SeaBIOS (standard x86_64 HVM BIOS)",
            )
        )

    # 3. Libvirt domain registration & XML inspection
    xml_to_inspect = domain_xml
    if conn is not None:
        try:
            dom = conn.lookupByName(plan.vm_name)
            xml_to_inspect = dom.XMLDesc(0)
            checks.append(
                ValidationCheck(
                    name="Libvirt domain registration",
                    passed=bool(dom.isPersistent()),
                    detail=f"Domain {plan.vm_name!r} registered (persistent={bool(dom.isPersistent())})",
                )
            )
        except Exception as exc:
            raise ValidationFailedError(
                f"Registered domain {plan.vm_name!r} could not be looked up in libvirt: {exc}"
            ) from exc

    root = ET.fromstring(xml_to_inspect)

    # 4. Disk attachment check
    xml_disk_sources = [
        el.attrib.get("file", "")
        for el in root.findall("./devices/disk[@device='disk']/source")
    ]
    for d in plan.disks:
        if str(d.target_path) not in xml_disk_sources:
            raise ValidationFailedError(
                f"Disk {d.target_path} is missing from registered domain XML."
            )
    checks.append(
        ValidationCheck(
            name="Disk attachment",
            passed=True,
            detail=f"{len(plan.disks)} disk(s) attached ({', '.join(d.target_dev for d in plan.disks)})",
        )
    )

    # 5. Network attachment & isolation check
    xml_nets = [
        el.attrib.get("network", "")
        for el in root.findall("./devices/interface[@type='network']/source")
    ]
    expected_net = plan.nics[0].network_name if plan.nics else "pentest-lab"
    if expected_net not in xml_nets:
        raise ValidationFailedError(
            f"Expected network {expected_net!r} not attached in domain XML."
        )
    if conn is not None:
        net_obj = conn.networkLookupByName(expected_net)
        net_root = ET.fromstring(net_obj.XMLDesc(0))
        if net_root.find("forward") is not None:
            raise ValidationFailedError(
                f"Network {expected_net!r} has forwarding enabled (not isolated)!"
            )
    checks.append(
        ValidationCheck(
            name="Network attachment & isolation",
            passed=True,
            detail=f"Connected to isolated network {expected_net!r}",
        )
    )

    # 6. Resource allocation check
    vcpu_val = int(root.findtext("vcpu") or "0")
    mem_kib = int(root.findtext("memory") or "0")
    if vcpu_val != plan.vcpus or mem_kib != plan.memory_mb * 1024:
        raise ValidationFailedError("Domain CPU/Memory allocation does not match plan.")
    checks.append(
        ValidationCheck(
            name="Resource allocation",
            passed=True,
            detail=f"{plan.vcpus} vCPU(s), {plan.memory_mb} MiB RAM",
        )
    )

    return checks


def _run_boot_validation(
    conn: Any,
    dom: Any,
    plan: ImportPlan,
    *,
    keep_running: bool = False,
    wait_seconds: int = 25,
) -> tuple[bool, str | None]:
    """Start the VM briefly to verify KVM boot & check for a DHCP lease on pentest-lab."""
    dom.create()
    discovered_ip: str | None = None
    target_macs = {n.mac_address.lower() for n in plan.nics}
    net_name = plan.nics[0].network_name if plan.nics else "pentest-lab"

    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        state, _ = dom.state()
        # VIR_DOMAIN_RUNNING == 1
        if state != 1:
            raise ValidationFailedError(
                f"Domain {plan.vm_name!r} exited running state unexpectedly during boot check (state={state})."
            )
        leases = get_network_dhcp_leases(conn, net_name)
        for lease in leases:
            mac = (lease.get("mac") or "").lower()
            if mac in target_macs and lease.get("ipaddr"):
                discovered_ip = lease["ipaddr"]
                break
        if discovered_ip:
            break
        time.sleep(2)

    if not keep_running:
        try:
            dom.shutdown()
            shut_deadline = time.monotonic() + 20
            while time.monotonic() < shut_deadline and dom.isActive():
                time.sleep(1)
            if dom.isActive():
                dom.destroy()
        except Exception:
            if dom.isActive():
                dom.destroy()

    return True, discovered_ip


def _remove_existing_domain_for_replace(conn: Any, vm_name: str) -> None:
    try:
        dom = conn.lookupByName(vm_name)
    except Exception:
        return
    if dom.isActive():
        dom.destroy()
    xml_str = dom.XMLDesc(0)
    root = ET.fromstring(xml_str)
    disk_paths = [
        el.attrib.get("file")
        for el in root.findall("./devices/disk[@device='disk']/source")
        if el.attrib.get("file")
    ]
    try:
        dom.undefineFlags(4)
    except Exception:
        dom.undefine()

    for dpath in disk_paths:
        try:
            vol = conn.storageVolLookupByPath(dpath)
            vol.delete(0)
        except Exception:
            Path(dpath).unlink(missing_ok=True)
