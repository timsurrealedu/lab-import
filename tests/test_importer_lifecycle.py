"""Integration tests for transactional import, rollback on failure, and lifecycle commands."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from lab_import.disks import analyze_vmdk_disk
from lab_import.errors import LabImportError, LibvirtOperationError
from lab_import.importer import execute_import_plan
from lab_import.lifecycle import (
    get_vm_detailed_info,
    list_domains_summary,
    remove_lab_vm,
    start_lab_vm,
    stop_lab_vm,
)
from lab_import.planner import build_import_plan
from lab_import.vmx_parser import parse_vmx_file
from tests.test_network import SAMPLE_KALI_XML
from tests.test_vmx_parser import LINKEDBASE_VMX_SAMPLE


class FakeDomain:
    def __init__(self, name: str, xml_str: str, active: bool = False) -> None:
        self._name = name
        self._xml = xml_str
        self._active = active
        self._autostart = False
        self.undefine_called = False

    def name(self) -> str:
        return self._name

    def UUIDString(self) -> str:
        return "11111111-2222-3333-4444-555555555555"

    def XMLDesc(self, _flags: int = 0) -> str:
        return self._xml

    def isActive(self) -> int:
        return 1 if self._active else 0

    def isPersistent(self) -> int:
        return 1

    def autostart(self) -> int:
        return 1 if self._autostart else 0

    def state(self) -> tuple[int, int]:
        return (1 if self._active else 5, 0)

    def create(self) -> int:
        self._active = True
        return 0

    def shutdown(self) -> int:
        self._active = False
        return 0

    def destroy(self) -> int:
        self._active = False
        return 0

    def undefine(self) -> int:
        self.undefine_called = True
        return 0

    def undefineFlags(self, _flags: int) -> int:
        self.undefine_called = True
        return 0


class FakeNetwork:
    def __init__(self, name: str, xml_str: str, active: bool = True) -> None:
        self._name = name
        self._xml = xml_str
        self._active = active
        self._autostart = True
        self.leases: list[dict[str, Any]] = []

    def name(self) -> str:
        return self._name

    def XMLDesc(self, _flags: int = 0) -> str:
        return self._xml

    def isActive(self) -> int:
        return 1 if self._active else 0

    def autostart(self) -> int:
        return 1 if self._autostart else 0

    def create(self) -> int:
        self._active = True
        return 0

    def setAutostart(self, val: int) -> int:
        self._autostart = bool(val)
        return 0

    def DHCPLeases(self) -> list[dict[str, Any]]:
        return self.leases


class FakeConn:
    def __init__(self, fail_on_define: bool = False) -> None:
        self.domains: dict[str, FakeDomain] = {
            "kalilinux": FakeDomain("kalilinux", SAMPLE_KALI_XML, active=False)
        }
        self.networks: dict[str, FakeNetwork] = {}
        self.fail_on_define = fail_on_define

    def listAllDomains(self, _flags: int = 0) -> list[FakeDomain]:
        return list(self.domains.values())

    def lookupByName(self, name: str) -> FakeDomain:
        if name not in self.domains:
            raise RuntimeError(f"Domain {name} not found")
        return self.domains[name]

    def defineXML(self, xml_str: str) -> FakeDomain:
        import xml.etree.ElementTree as ET

        root = ET.fromstring(xml_str)
        name = root.findtext("name") or "unknown"
        if self.fail_on_define and name != "kalilinux":
            raise RuntimeError("Simulated libvirt defineXML failure")
        dom = FakeDomain(name, xml_str, active=False)
        self.domains[name] = dom
        return dom

    def listAllNetworks(self, _flags: int = 0) -> list[FakeNetwork]:
        return list(self.networks.values())

    def networkLookupByName(self, name: str) -> FakeNetwork:
        if name not in self.networks:
            raise RuntimeError(f"Network {name} not found")
        return self.networks[name]

    def networkDefineXML(self, xml_str: str) -> FakeNetwork:
        import xml.etree.ElementTree as ET

        root = ET.fromstring(xml_str)
        name = root.findtext("name") or "pentest-lab"
        net = FakeNetwork(name, xml_str, active=False)
        self.networks[name] = net
        return net


def test_end_to_end_import_and_lifecycle_with_mock_libvirt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))

    vm_dir = tmp_path / "LinkedBase"
    vm_dir.mkdir()
    vmx_path = vm_dir / "LinkedBase.vmx"
    vmx_path.write_text(LINKEDBASE_VMX_SAMPLE, encoding="utf-8")

    vmdk_path = vm_dir / "LinkedBase.vmdk"
    subprocess.run(
        [
            "qemu-img",
            "create",
            "-f",
            "vmdk",
            "-o",
            "subformat=twoGbMaxExtentSparse",
            str(vmdk_path),
            "8M",
        ],
        check=True,
        capture_output=True,
    )

    conn = FakeConn()
    vmx = parse_vmx_file(vmx_path)
    d_analysis = analyze_vmdk_disk(vmdk_path, base_dir=vm_dir)
    images_dir = tmp_path / "images"

    plan = build_import_plan(
        vm_dir,
        vmx,
        [d_analysis],
        conn=conn,
        storage_dir=images_dir,
    )

    res = execute_import_plan(plan, conn, attach_kali=True)
    assert res.plan.vm_name == "LinkedBase"
    assert (images_dir / "LinkedBase.qcow2").is_file()
    assert vmdk_path.is_file()  # Source VMDK untouched!
    assert res.kali_attached is True
    assert res.kali_backup_path is not None and res.kali_backup_path.is_file()

    # Check lifecycle commands
    summary = list_domains_summary(conn)
    names = {s["name"] for s in summary}
    assert "LinkedBase" in names
    assert "kalilinux" in names

    info = get_vm_detailed_info(conn, "linkedbase")
    assert info["name"] == "LinkedBase"
    assert info["state"] == "Shut off"

    start_res = start_lab_vm(conn, "LinkedBase")
    assert start_res["already_running"] is False
    assert conn.lookupByName("LinkedBase").isActive() == 1

    stop_res = stop_lab_vm(conn, "LinkedBase", force=False)
    assert stop_res["method"] == "graceful_shutdown"

    # Protected Kali VM cannot be removed
    with pytest.raises(LabImportError, match="protected Kali Linux"):
        remove_lab_vm(conn, "kalilinux")

    # Remove LinkedBase and verify QCOW2 deleted while source VMDK remains intact
    rem_res = remove_lab_vm(conn, "LinkedBase", delete_disks=True)
    assert rem_res["name"] == "LinkedBase"
    assert not (images_dir / "LinkedBase.qcow2").exists()
    assert vmdk_path.is_file()


def test_rollback_cleans_up_converted_qcow2_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    vm_dir = tmp_path / "FailVM"
    vm_dir.mkdir()
    vmx_path = vm_dir / "FailVM.vmx"
    vmx_path.write_text(
        'displayName = "FailVM"\nscsi0:0.fileName = "FailVM.vmdk"\nscsi0:0.present = "TRUE"\n',
        encoding="utf-8",
    )
    vmdk_path = vm_dir / "FailVM.vmdk"
    subprocess.run(
        ["qemu-img", "create", "-f", "vmdk", str(vmdk_path), "4M"],
        check=True,
        capture_output=True,
    )

    conn = FakeConn(fail_on_define=True)
    vmx = parse_vmx_file(vmx_path)
    d_analysis = analyze_vmdk_disk(vmdk_path, base_dir=vm_dir)
    images_dir = tmp_path / "images"

    plan = build_import_plan(
        vm_dir,
        vmx,
        [d_analysis],
        conn=conn,
        storage_dir=images_dir,
    )

    with pytest.raises(LibvirtOperationError):
        execute_import_plan(plan, conn, attach_kali=False)

    # Partial converted QCOW2 must have been cleaned up on rollback!
    assert not (images_dir / "FailVM.qcow2").exists()
    # Original VMDK must still exist!
    assert vmdk_path.is_file()
