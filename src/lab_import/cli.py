"""Polished command-line interface for VM Lab Importer (`lab-import`, `lab-*`, `lab`)."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TransferSpeedColumn,
)
from rich.syntax import Syntax
from rich.table import Table

from . import __version__
from .config import (
    DEFAULT_LAB_NETWORK,
    DEFAULT_LIBVIRT_URI,
    detect_dependencies,
    setup_logging,
)
from .disks import analyze_vmdk_disk
from .errors import LabImportError
from .extractor import (
    StagingWorkspace,
    extract_archive_safely,
    inspect_archive_members,
    is_archive_path,
)
from .importer import execute_import_plan
from .lifecycle import (
    discover_lab_subnet_hosts,
    get_lab_network_status,
    get_vm_detailed_info,
    list_domains_summary,
    remove_lab_vm,
    start_lab_vm,
    stop_lab_vm,
)
from .models import DiscoveredVM, ImportPlan, VMDKAnalysis
from .network import (
    attach_kali_to_lab_network,
    build_isolated_network_xml,
    ensure_lab_network_active,
    inspect_or_plan_lab_network,
)
from .planner import build_import_plan
from .scanner import discover_vms_in_path, select_discovered_vm
from .vmx_parser import (
    build_synthetic_vmx_from_vmdk,
    check_source_vm_runtime_state,
    parse_vmx_file,
)
from .xml_builder import build_domain_xml, validate_xml_with_libvirt_schema

console = Console()
err_console = Console(stderr=True)


def open_libvirt_connection(uri: str = DEFAULT_LIBVIRT_URI) -> Any:
    """Connect to libvirt (suppressing C library stderr chatter)."""
    try:
        import libvirt
    except ImportError as exc:
        raise LabImportError(
            "Python libvirt bindings are not installed.",
            hint="Install on Arch Linux with: sudo pacman -S python-libvirt",
        ) from exc

    libvirt.registerErrorHandler(lambda _ctx, _err: None, None)
    try:
        conn = libvirt.open(uri)
    except Exception as exc:
        raise LabImportError(
            f"Could not connect to libvirt at {uri}: {exc}",
            hint="Ensure libvirtd.service is running (`systemctl status libvirtd`) and your user is in the `libvirt` group.",
        ) from exc
    if conn is None:
        raise LabImportError(f"Failed to open libvirt connection to {uri}.")
    return conn


def _print_error(exc: LabImportError | Exception) -> None:
    if isinstance(exc, LabImportError):
        err_console.print(f"\n[bold red]✗ Error:[/bold red] {exc.message}")
        if exc.hint:
            err_console.print(f"  [yellow]Hint:[/yellow] {exc.hint}")
    else:
        err_console.print(f"\n[bold red]✗ Unexpected error:[/bold red] {exc}")


def _prompt_vm_selection(candidates: list[DiscoveredVM]) -> DiscoveredVM:
    console.print("\n[bold cyan]Multiple virtual machines found in source:[/bold cyan]")
    tbl = Table(show_header=True, header_style="bold magenta")
    tbl.add_column("#", justify="right", style="cyan")
    tbl.add_column("VM Name", style="bold")
    tbl.add_column("Type")
    tbl.add_column("Config / Disk")
    for idx, c in enumerate(candidates, start=1):
        cfg_label = (
            c.vmx_path.name
            if c.vmx_path
            else (c.primary_vmdk.name if c.primary_vmdk else "-")
        )
        tbl.add_row(str(idx), c.name, c.source_type, cfg_label)
    console.print(tbl)
    choice = click.prompt(
        "Select VM number to import",
        type=click.IntRange(1, len(candidates)),
        default=1,
    )
    return candidates[choice - 1]


def _format_gib(size_bytes: int) -> str:
    gib = size_bytes / (1024**3)
    if gib >= 1.0:
        if abs(gib - round(gib)) < 0.05:
            return f"{int(round(gib))} GiB"
        return f"{gib:.2f} GiB"
    mib = size_bytes / (1024**2)
    return f"{mib:.1f} MiB"


def _format_mem(memory_mb: int) -> str:
    if memory_mb % 1024 == 0:
        return f"{memory_mb // 1024} GiB"
    return f"{memory_mb / 1024:.2f} GiB ({memory_mb} MiB)"


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("source", type=click.Path(exists=True, path_type=Path))
@click.option("--name", "name_override", help="Override imported libvirt domain name.")
@click.option(
    "--vm",
    "vm_selector",
    help="Select specific VM by name or 1-based index when archive contains multiple VMs.",
)
@click.option(
    "--network",
    "network_name",
    default=DEFAULT_LAB_NETWORK,
    show_default=True,
    help="Target isolated libvirt network for the imported VM.",
)
@click.option(
    "--disk-bus",
    type=click.Choice(["auto", "sata", "scsi", "virtio", "ide", "nvme"], case_sensitive=False),
    default="auto",
    show_default=True,
    help="Virtual disk bus type (auto selects SATA/AHCI /dev/sdX for maximum boot compatibility).",
)
@click.option(
    "--nic-model",
    type=click.Choice(["auto", "e1000", "e1000e", "virtio", "vmxnet3"], case_sensitive=False),
    default="auto",
    show_default=True,
    help="Virtual network interface model.",
)
@click.option("--memory", "memory_mb", type=int, help="Override RAM allocation in MiB.")
@click.option("--cpus", "vcpus", type=int, help="Override virtual CPU count.")
@click.option(
    "--firmware",
    type=click.Choice(["auto", "bios", "efi"], case_sensitive=False),
    default="auto",
    show_default=True,
    help="Guest firmware mode (auto-detected from .vmx or GPT EFI partition).",
)
@click.option(
    "--collision",
    type=click.Choice(["ask", "rename", "fail", "replace"], case_sensitive=False),
    default="rename",
    show_default=True,
    help="Policy when a VM with the same name already exists in libvirt.",
)
@click.option(
    "--attach-kali / --skip-kali-attach",
    default=True,
    show_default=True,
    help="Ensure existing Kali VM has a second NIC attached to the isolated lab network.",
)
@click.option(
    "--allow-suspended",
    is_flag=True,
    help="Allow importing a suspended VMware VM (discards unsaved .vmss RAM state).",
)
@click.option(
    "--ignore-unreferenced-snapshots",
    is_flag=True,
    help="Proceed even if unreferenced delta snapshot VMDKs exist in the source folder.",
)
@click.option(
    "--validate-boot",
    is_flag=True,
    help="Briefly boot the imported VM to verify KVM startup and check for a lab DHCP lease.",
)
@click.option(
    "--start",
    "start_after",
    is_flag=True,
    help="Leave the imported VM running after import completes.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Analyze source, verify disks, and display the import plan without modifying the system.",
)
@click.option(
    "--show-xml",
    is_flag=True,
    help="Display the generated libvirt domain XML (useful with --dry-run).",
)
@click.option(
    "--interactive / --non-interactive",
    default=True,
    show_default=True,
    help="Enable or disable interactive prompts for ambiguous choices.",
)
@click.option("-y", "--yes", is_flag=True, help="Automatically confirm prompts.")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose diagnostic logging.")
@click.option(
    "-c",
    "--connect",
    "libvirt_uri",
    default=DEFAULT_LIBVIRT_URI,
    show_default=True,
    help="Libvirt connection URI.",
)
def import_cmd(
    source: Path,
    name_override: str | None,
    vm_selector: str | None,
    network_name: str,
    disk_bus: str,
    nic_model: str,
    memory_mb: int | None,
    vcpus: int | None,
    firmware: str,
    collision: str,
    attach_kali: bool,
    allow_suspended: bool,
    ignore_unreferenced_snapshots: bool,
    validate_boot: bool,
    start_after: bool,
    dry_run: bool,
    show_xml: bool,
    interactive: bool,
    yes: bool,
    verbose: bool,
    libvirt_uri: str,
) -> None:
    """Import a VMware archive (.zip, .7z, .tar.*, .ova), directory, .vmx, or .vmdk into QEMU/KVM."""
    setup_logging(verbose=verbose)
    deps = detect_dependencies()
    if not deps.ok:
        err_console.print("[bold red]✗ Missing required system dependencies:[/bold red]")
        for m in deps.missing_required:
            err_console.print(f"  - {m}")
        sys.exit(1)

    console.print("\n[bold white]VM Lab Importer[/bold white]\n")
    console.print(f"Source: [cyan]{source.name}[/cyan]\n")

    try:
        conn = open_libvirt_connection(libvirt_uri)
        with StagingWorkspace(prefix="lab-import-") as staging_dir:
            # Step 1: Archive inspection & extraction (if archive)
            is_arch = is_archive_path(source)
            work_root = source.resolve()

            if is_arch:
                if dry_run:
                    # In dry-run on an archive, we still inspect archive security!
                    # Wait: to parse .vmx and inspect .vmdk inside an archive during dry-run,
                    # extracting to temporary staging (which is cleaned up on exit) or inspecting:
                    pass
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    DownloadColumn(),
                    TransferSpeedColumn(),
                    TimeElapsedColumn(),
                    console=console,
                    transient=True,
                ) as progress:
                    task_id = progress.add_task(
                        f"Extracting {source.name} safely to staging...", total=100
                    )

                    def _on_extract_prog(done: int, total: int, fname: str) -> None:
                        progress.update(
                            task_id,
                            completed=done,
                            total=total,
                            description=f"Extracting [cyan]{fname}[/cyan]...",
                        )

                    ext_report = extract_archive_safely(
                        source,
                        staging_dir,
                        skip_transient=True,
                        progress_callback=_on_extract_prog,
                    )
                work_root = staging_dir
                console.print("[green]✓[/green] Archive extracted safely")
                if ext_report.had_vmss_files and not allow_suspended:
                    raise LabImportError(
                        f"Archive {source.name} contains a suspended VMware checkpoint (.vmss).",
                        hint="Pass --allow-suspended to import disk state without suspended RAM state.",
                    )

            # Step 2: Discover VMs in work_root
            candidates = discover_vms_in_path(work_root)
            selected = select_discovered_vm(
                candidates,
                selector=vm_selector,
                interactive=(interactive and not yes),
                prompt_fn=_prompt_vm_selection,
            )

            # Step 3: Parse .vmx (or synthesize for standalone VMDK)
            if selected.source_type == "vmx" and selected.vmx_path:
                vmx = parse_vmx_file(selected.vmx_path)
                console.print("[green]✓[/green] VMware configuration detected")
            else:
                assert selected.primary_vmdk is not None
                vmx = build_synthetic_vmx_from_vmdk(
                    selected.primary_vmdk,
                    extra_vmdks=selected.extra_vmdks,
                    name=name_override or selected.name,
                    vcpus=vcpus or 2,
                    memory_mb=memory_mb or 2048,
                    firmware=firmware if firmware != "auto" else "bios",
                )
                console.print(
                    "[green]✓[/green] Standalone virtual disk detected (synthesized safe VM configuration)"
                )

            # Check runtime lock/suspend state
            state_warnings = check_source_vm_runtime_state(
                selected.base_dir,
                vmx,
                allow_suspended=allow_suspended,
            )
            vmx.warnings.extend(state_warnings)

            if not vmx.disks:
                # Fallback: scan base_dir for descriptor VMDKs if .vmx had none
                fallback_vmdks = discover_vms_in_path(selected.base_dir)
                if fallback_vmdks and fallback_vmdks[0].primary_vmdk:
                    synth = build_synthetic_vmx_from_vmdk(fallback_vmdks[0].primary_vmdk)
                    vmx.disks = synth.disks
                else:
                    raise LabImportError(
                        f"No virtual hard disks found in configuration for {vmx.display_name!r}."
                    )

            # Step 4: Analyze VMDKs & verify snapshot dependencies
            vmsd_path = (
                selected.vmx_path.with_suffix(".vmsd")
                if selected.vmx_path
                else None
            )
            disk_analyses: list[VMDKAnalysis] = []
            for d_spec in vmx.disks:
                assert d_spec.resolved_path is not None
                analysis = analyze_vmdk_disk(
                    d_spec.resolved_path,
                    base_dir=selected.base_dir,
                    vmsd_path=vmsd_path,
                    ignore_unreferenced_snapshots=ignore_unreferenced_snapshots,
                )
                disk_analyses.append(analysis)

            console.print("[green]✓[/green] Virtual disks identified")
            console.print("[green]✓[/green] Snapshot dependencies verified")

            # Handle interactive collision policy if 'ask'
            effective_collision = collision.lower()
            if effective_collision == "ask":
                effective_collision = "rename"

            plan = build_import_plan(
                source,
                vmx,
                disk_analyses,
                conn=conn,
                name_override=name_override,
                memory_override_mb=memory_mb,
                vcpus_override=vcpus,
                firmware_override=firmware.lower(),
                disk_bus_override=disk_bus.lower(),
                nic_model_override=nic_model.lower(),
                network_name=network_name,
                collision_policy=effective_collision,
                skip_kali_check=not attach_kali,
            )

            if collision.lower() == "ask" and plan.vm_name != plan.original_vm_name and interactive and not yes:
                console.print(
                    f"\n[yellow]! Domain {plan.original_vm_name!r} already exists in libvirt.[/yellow]"
                )
                action = click.prompt(
                    "Choose collision action",
                    type=click.Choice(["rename", "replace", "abort"], case_sensitive=False),
                    default="rename",
                )
                if action == "abort":
                    console.print("Aborted.")
                    sys.exit(0)
                if action == "replace":
                    plan = build_import_plan(
                        source,
                        vmx,
                        disk_analyses,
                        conn=conn,
                        name_override=name_override,
                        memory_override_mb=memory_mb,
                        vcpus_override=vcpus,
                        firmware_override=firmware.lower(),
                        disk_bus_override=disk_bus.lower(),
                        nic_model_override=nic_model.lower(),
                        network_name=network_name,
                        collision_policy="replace",
                        skip_kali_check=not attach_kali,
                    )
                    effective_collision = "replace"

            if dry_run:
                _render_dry_run_plan(plan, show_xml=show_xml)
                return

            # Confirm Kali 2nd NIC attachment if needed and interactive
            do_attach_kali = attach_kali and plan.kali_needs_lab_nic
            if do_attach_kali and interactive and not yes:
                console.print(
                    f"\n[cyan]Network Setup:[/cyan] Existing Kali VM [bold]{plan.kali_domain_name}[/bold] "
                    f"is not yet connected to isolated network [bold]{network_name}[/bold]."
                )
                console.print(
                    f"  A backup of [bold]{plan.kali_domain_name}[/bold]'s XML will be saved and a second "
                    f"virtio NIC on [bold]{network_name}[/bold] will be added (preserving its primary NAT adapter)."
                )
                do_attach_kali = click.confirm(
                    f"Attach second NIC ({network_name}) to {plan.kali_domain_name}?",
                    default=True,
                )

            # Step 5: Execute conversion, network setup, and domain registration
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                conv_task = progress.add_task("Converting disk to QCOW2...", total=100.0)

                def _on_disk_pct(
                    disk_idx: int, total_disks: int, dname: str, pct: float
                ) -> None:
                    prefix = (
                        f"[{disk_idx}/{total_disks}] " if total_disks > 1 else ""
                    )
                    progress.update(
                        conv_task,
                        completed=pct,
                        description=f"{prefix}Converting [cyan]{dname}[/cyan] to QCOW2...",
                    )

                result = execute_import_plan(
                    plan,
                    conn,
                    attach_kali=do_attach_kali,
                    replace_existing=(effective_collision == "replace"),
                    validate_boot=validate_boot,
                    start_after_import=start_after,
                    disk_progress_callback=_on_disk_pct,
                )

            console.print("[green]✓[/green] Disk converted to QCOW2")
            console.print("[green]✓[/green] Libvirt domain created")
            console.print("[green]✓[/green] Isolated lab network configured")
            console.print("[green]✓[/green] VM registered successfully")

            if result.kali_attached and result.kali_backup_path:
                console.print(
                    f"[green]✓[/green] Attached [bold]{plan.kali_domain_name}[/bold] 2nd NIC to "
                    f"[bold]{network_name}[/bold] (backup: {result.kali_backup_path.name})"
                )

            if show_xml:
                console.print()
                console.print(Syntax(result.domain_xml, "xml", theme="monokai"))

            _render_import_summary(result, started=start_after)

    except Exception as exc:
        _print_error(exc)
        sys.exit(1)


def _render_dry_run_plan(plan: ImportPlan, *, show_xml: bool = False) -> None:
    domain_xml = build_domain_xml(plan)
    validate_xml_with_libvirt_schema(domain_xml, "domain")

    console.print("[green]✓[/green] Libvirt domain XML schema validated (dry-run)\n")
    tbl = Table(title="Dry-Run Import Plan", show_header=False, box=None, pad_edge=False)
    tbl.add_column("Field", style="bold cyan", width=20)
    tbl.add_column("Value")
    tbl.add_row("Virtual Machine:", f"[bold]{plan.vm_name}[/bold] (source: {plan.original_vm_name})")
    tbl.add_row("Guest OS:", f"{plan.os_distro} ({plan.os_family})")
    tbl.add_row("Hypervisor:", f"QEMU/KVM ({plan.arch}, machine={plan.machine_type}, firmware={plan.firmware.upper()})")
    tbl.add_row("Memory:", _format_mem(plan.memory_mb))
    tbl.add_row("Processors:", str(plan.vcpus))
    for d in plan.disks:
        tbl.add_row(
            f"Disk ({d.target_dev}):",
            f"{_format_gib(d.source_vmdk.virtual_size_bytes)} virtual "
            f"({_format_gib(d.source_vmdk.actual_size_bytes)} actual, "
            f"{len(d.source_vmdk.extents) or 1} extent(s), bus={d.bus}) -> {d.target_path}",
        )
    for nic in plan.nics:
        ifname_note = f", guest ifname={nic.expected_guest_ifname}" if nic.expected_guest_ifname else ""
        tbl.add_row(
            f"NIC #{nic.index}:",
            f"network={nic.network_name}, model={nic.model}, mac={nic.mac_address}{ifname_note}",
        )
    if plan.lab_network:
        net = plan.lab_network
        net_state = "Exists" if net.already_exists else "Will be created"
        tbl.add_row(
            "Lab Network:",
            f"{net.name} ({net.subnet_cidr}, bridge={net.bridge_name}, isolated={net.is_isolated}, {net_state})",
        )
    if plan.kali_domain_name:
        k_status = (
            f"Will attach 2nd NIC ({plan.lab_network.name if plan.lab_network else 'pentest-lab'})"
            if plan.kali_needs_lab_nic
            else "Already connected to lab network"
        )
        tbl.add_row(f"Kali ({plan.kali_domain_name}):", k_status)
    console.print(tbl)

    if plan.notes:
        console.print("\n[bold cyan]Translation Notes:[/bold cyan]")
        for n in plan.notes:
            console.print(f"  • {n}")
    if plan.warnings:
        console.print("\n[bold yellow]Warnings:[/bold yellow]")
        for w in plan.warnings:
            console.print(f"  [yellow]![/yellow] {w}")

    if show_xml:
        console.print("\n[bold cyan]Generated Libvirt Domain XML:[/bold cyan]")
        console.print(Syntax(domain_xml, "xml", theme="monokai"))

    console.print("\n[dim]Dry-run complete. No disks converted and no libvirt state modified.[/dim]")


def _render_import_summary(result: Any, *, started: bool = False) -> None:
    plan = result.plan
    total_virtual_bytes = sum(d.source_vmdk.virtual_size_bytes for d in plan.disks)
    net_label = plan.nics[0].network_name if plan.nics else DEFAULT_LAB_NETWORK
    status_label = "Running" if started else "Shut off"

    console.print()
    summary_lines = [
        f"[bold]Virtual Machine:[/bold] {plan.vm_name}",
        f"[bold]Hypervisor:[/bold]      QEMU/KVM",
        f"[bold]Memory:[/bold]          {_format_mem(plan.memory_mb)}",
        f"[bold]Processors:[/bold]      {plan.vcpus}",
        f"[bold]Disk:[/bold]            {_format_gib(total_virtual_bytes)}",
        f"[bold]Network:[/bold]         {net_label}",
        f"[bold]Status:[/bold]          {status_label}",
    ]
    if result.discovered_ip:
        summary_lines.append(f"[bold]Discovered IP:[/bold]   {result.discovered_ip}")

    for line in summary_lines:
        console.print(line)

    if plan.warnings:
        console.print("\n[bold yellow]Notes / Warnings:[/bold yellow]")
        for w in plan.warnings:
            console.print(f"  [yellow]•[/yellow] {w}")

    if started:
        console.print(f"\n[bold green]VM {plan.vm_name} is running.[/bold green]")
    elif result.boot_validated:
        console.print(
            f"\n[bold green]Boot validated and shut down cleanly. Ready to start (`lab-start {plan.vm_name}`).[/bold green]"
        )
    else:
        console.print(f"\n[bold green]Ready to start.[/bold green]")


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--all",
    "show_all",
    is_flag=True,
    default=True,
    help="Include all libvirt domains (lab targets, Kali, and system VMs).",
)
@click.option(
    "--lab-only",
    is_flag=True,
    help="Only show VMs imported by lab-import and Kali Linux.",
)
@click.option(
    "-c",
    "--connect",
    "libvirt_uri",
    default=DEFAULT_LIBVIRT_URI,
    show_default=True,
    help="Libvirt connection URI.",
)
def list_cmd(show_all: bool, lab_only: bool, libvirt_uri: str) -> None:
    """List virtual machines in the penetration-testing lab and their network status."""
    try:
        conn = open_libvirt_connection(libvirt_uri)
        items = list_domains_summary(conn, include_non_lab=not lab_only)
        if not items:
            console.print("No virtual machines found.")
            return

        tbl = Table(title="Virtual Machine Lab Inventory", header_style="bold cyan")
        tbl.add_column("Name", style="bold")
        tbl.add_column("Role")
        tbl.add_column("State")
        tbl.add_column("vCPUs", justify="right")
        tbl.add_column("Memory", justify="right")
        tbl.add_column("Networks")
        tbl.add_column("Active DHCP IPs")

        for item in items:
            state = item["state"]
            state_styled = (
                f"[green]{state}[/green]"
                if item["is_active"]
                else f"[dim]{state}[/dim]"
            )
            tbl.add_row(
                item["name"],
                item["role"],
                state_styled,
                str(item["vcpus"]),
                _format_mem(item["memory_mib"]),
                ", ".join(item["networks"]) or "-",
                ", ".join(item["ips"]) or "-",
            )
        console.print(tbl)
    except Exception as exc:
        _print_error(exc)
        sys.exit(1)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("vm_name")
@click.option(
    "--viewer",
    is_flag=True,
    help="Launch virt-viewer in the background after starting the VM.",
)
@click.option(
    "--wait-ip",
    is_flag=True,
    help="Wait for and display the VM's DHCP IP address on the lab network.",
)
@click.option(
    "--timeout",
    type=int,
    default=45,
    show_default=True,
    help="Seconds to wait when --wait-ip is enabled.",
)
@click.option(
    "-c",
    "--connect",
    "libvirt_uri",
    default=DEFAULT_LIBVIRT_URI,
    show_default=True,
    help="Libvirt connection URI.",
)
def start_cmd(
    vm_name: str,
    viewer: bool,
    wait_ip: bool,
    timeout: int,
    libvirt_uri: str,
) -> None:
    """Start a lab virtual machine and ensure its lab network is active."""
    try:
        conn = open_libvirt_connection(libvirt_uri)
        with console.status(f"Starting [bold]{vm_name}[/bold]..."):
            res = start_lab_vm(conn, vm_name, wait_ip=wait_ip, timeout_sec=timeout)

        actual = res["name"]
        if res["already_running"]:
            console.print(f"[green]✓[/green] VM [bold]{actual}[/bold] is already running.")
        else:
            console.print(f"[green]✓[/green] VM [bold]{actual}[/bold] started.")

        if res.get("ip"):
            console.print(f"  [cyan]Lab IP:[/cyan] [bold]{res['ip']}[/bold]")
        elif wait_ip:
            console.print(
                "  [yellow]![/yellow] No DHCP lease observed yet (guest may still be booting or using static IP)."
            )

        if viewer:
            vv = shutil.which("virt-viewer")
            if not vv:
                err_console.print("[yellow]! virt-viewer is not installed.[/yellow]")
            else:
                subprocess.Popen(
                    [vv, "-c", libvirt_uri, "--wait", actual],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                console.print(f"[green]✓[/green] Launched virt-viewer for [bold]{actual}[/bold].")
    except Exception as exc:
        _print_error(exc)
        sys.exit(1)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("vm_name")
@click.option(
    "-f",
    "--force",
    is_flag=True,
    help="Force immediate power-off (virsh destroy) instead of graceful ACPI shutdown.",
)
@click.option(
    "--timeout",
    type=int,
    default=30,
    show_default=True,
    help="Seconds to wait for graceful ACPI shutdown.",
)
@click.option(
    "-c",
    "--connect",
    "libvirt_uri",
    default=DEFAULT_LIBVIRT_URI,
    show_default=True,
    help="Libvirt connection URI.",
)
def stop_cmd(vm_name: str, force: bool, timeout: int, libvirt_uri: str) -> None:
    """Gracefully shut down or force-stop (`--force`) a lab virtual machine."""
    try:
        conn = open_libvirt_connection(libvirt_uri)
        action_desc = "Force-stopping" if force else "Shutting down"
        with console.status(f"{action_desc} [bold]{vm_name}[/bold]..."):
            res = stop_lab_vm(conn, vm_name, force=force, timeout_sec=timeout)

        actual = res["name"]
        if not res["was_running"]:
            console.print(f"[dim]VM {actual} is already shut off.[/dim]")
        elif res["method"] == "forced_poweroff":
            console.print(f"[green]✓[/green] VM [bold]{actual}[/bold] force-stopped (powered off).")
        else:
            console.print(f"[green]✓[/green] VM [bold]{actual}[/bold] shut down gracefully.")
    except Exception as exc:
        _print_error(exc)
        sys.exit(1)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("vm_name")
@click.option("--xml", "show_xml", is_flag=True, help="Print full libvirt domain XML.")
@click.option(
    "-c",
    "--connect",
    "libvirt_uri",
    default=DEFAULT_LIBVIRT_URI,
    show_default=True,
    help="Libvirt connection URI.",
)
def info_cmd(vm_name: str, show_xml: bool, libvirt_uri: str) -> None:
    """Display detailed configuration, disk, and network information for a VM."""
    try:
        conn = open_libvirt_connection(libvirt_uri)
        info = get_vm_detailed_info(conn, vm_name)

        tbl = Table(
            title=f"Virtual Machine: {info['name']}",
            show_header=False,
            box=None,
            pad_edge=False,
        )
        tbl.add_column("Field", style="bold cyan", width=22)
        tbl.add_column("Value")
        tbl.add_row("Name:", f"[bold]{info['name']}[/bold]")
        tbl.add_row("UUID:", info["uuid"])
        tbl.add_row("Status:", f"[green]{info['state']}[/green]" if info["is_active"] else info["state"])
        tbl.add_row("Architecture / Machine:", f"{info['arch']} ({info['machine']})")
        tbl.add_row("Firmware:", info["firmware"])
        tbl.add_row("Processors:", str(info["vcpus"]))
        tbl.add_row("Memory:", _format_mem(info["memory_mib"]))

        meta = info.get("lab_metadata")
        if meta:
            tbl.add_row("Imported At:", meta.get("imported_at", "-"))
            tbl.add_row("Original Source:", meta.get("source_path", "-"))
            tbl.add_row("Original VM Name:", meta.get("original_name", "-"))
            tbl.add_row("Detected Guest OS:", meta.get("os_distro", "-"))

        for d in info["disks"]:
            vsize_str = _format_gib(d["virtual_size_bytes"]) if d["virtual_size_bytes"] else "?"
            asize_str = _format_gib(d["actual_size_bytes"]) if d["actual_size_bytes"] else "?"
            tbl.add_row(
                f"Disk ({d['dev']}):",
                f"{d['path']} [bus={d['bus']}, fmt={d['format']}, virtual={vsize_str}, actual={asize_str}]",
            )

        for idx, nic in enumerate(info["nics"]):
            lease_str = (
                ", ".join(f"{l['ip']}" for l in nic["leases"])
                if nic["leases"]
                else "none"
            )
            pci_note = f", {nic['pci']}" if nic.get("pci") else ""
            tbl.add_row(
                f"NIC #{idx} ({nic['network']}):",
                f"model={nic['model']}, mac={nic['mac']}{pci_note}, active_ip={lease_str}",
            )

        console.print()
        console.print(tbl)

        if show_xml:
            console.print()
            console.print(Syntax(info["xml"], "xml", theme="monokai"))
    except Exception as exc:
        _print_error(exc)
        sys.exit(1)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("vm_name")
@click.option(
    "--keep-disks",
    is_flag=True,
    help="Unregister the libvirt domain but keep its converted QCOW2 disk image(s).",
)
@click.option(
    "--allow-non-lab",
    is_flag=True,
    help="Allow removing a non-Kali VM that was not created by lab-import.",
)
@click.option(
    "-y",
    "--yes",
    is_flag=True,
    help="Skip interactive confirmation prompt.",
)
@click.option(
    "-c",
    "--connect",
    "libvirt_uri",
    default=DEFAULT_LIBVIRT_URI,
    show_default=True,
    help="Libvirt connection URI.",
)
def remove_cmd(
    vm_name: str,
    keep_disks: bool,
    allow_non_lab: bool,
    yes: bool,
    libvirt_uri: str,
) -> None:
    """Remove an imported lab VM and (after confirmation) delete its converted QCOW2 disks."""
    try:
        conn = open_libvirt_connection(libvirt_uri)
        info = get_vm_detailed_info(conn, vm_name)
        actual_name = info["name"]
        disks = [d["path"] for d in info["disks"] if d.get("path")]

        if not yes:
            console.print(f"\n[bold yellow]About to remove VM:[/bold yellow] [bold]{actual_name}[/bold]")
            if not keep_disks and disks:
                console.print("The following converted QCOW2 virtual disk(s) will be permanently deleted:")
                for dpath in disks:
                    console.print(f"  - [red]{dpath}[/red]")
                if info.get("lab_metadata", {}) and info["lab_metadata"].get("source_path"):
                    console.print(
                        f"  [dim](Original source {info['lab_metadata']['source_path']} will NOT be touched.)[/dim]"
                    )
                if not click.confirm(
                    f"Delete VM {actual_name!r} and its converted QCOW2 disk(s)?",
                    default=False,
                ):
                    console.print("Cancelled.")
                    return
            else:
                if not click.confirm(
                    f"Unregister VM {actual_name!r} from libvirt (keeping disk files)?",
                    default=False,
                ):
                    console.print("Cancelled.")
                    return

        res = remove_lab_vm(
            conn,
            actual_name,
            delete_disks=not keep_disks,
            allow_non_lab=allow_non_lab,
        )
        console.print(f"[green]✓[/green] Unregistered domain [bold]{res['name']}[/bold].")
        for d in res["deleted_disks"]:
            console.print(f"[green]✓[/green] Deleted QCOW2 volume: {d}")
        for d in res["preserved_disks"]:
            console.print(f"[cyan]•[/cyan] Preserved disk volume: {d}")
    except Exception as exc:
        _print_error(exc)
        sys.exit(1)


@click.group(
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option(
    "--name",
    "network_name",
    default=DEFAULT_LAB_NETWORK,
    show_default=True,
    help="Isolated lab network name.",
)
@click.option(
    "-c",
    "--connect",
    "libvirt_uri",
    default=DEFAULT_LIBVIRT_URI,
    show_default=True,
    help="Libvirt connection URI.",
)
@click.pass_context
def network_group(ctx: click.Context, network_name: str, libvirt_uri: str) -> None:
    """Inspect, configure, or query the isolated penetration-testing network (`pentest-lab`)."""
    ctx.ensure_object(dict)
    ctx.obj["network_name"] = network_name
    ctx.obj["libvirt_uri"] = libvirt_uri
    if ctx.invoked_subcommand is None:
        ctx.invoke(network_status_cmd)


@network_group.command("status")
@click.pass_context
def network_status_cmd(ctx: click.Context) -> None:
    """Display the status, isolation verification, attached VMs, and DHCP leases of pentest-lab."""
    try:
        conn = open_libvirt_connection(ctx.obj["libvirt_uri"])
        status = get_lab_network_status(conn, ctx.obj["network_name"])
        spec = status["spec"]

        tbl = Table(
            title=f"Isolated Lab Network: {spec.name}",
            show_header=False,
            box=None,
            pad_edge=False,
        )
        tbl.add_column("Field", style="bold cyan", width=22)
        tbl.add_column("Value")
        tbl.add_row("Network Name:", f"[bold]{spec.name}[/bold]")
        tbl.add_row(
            "State:",
            (
                "[green]Active[/green]"
                if spec.is_active
                else ("[yellow]Defined (Inactive)[/yellow]" if spec.already_exists else "[dim]Not created yet (Planned)[/dim]")
            ),
        )
        tbl.add_row("Bridge Interface:", spec.bridge_name)
        tbl.add_row("Subnet CIDR:", spec.subnet_cidr)
        tbl.add_row("Bridge IP:", spec.gateway_ip)
        tbl.add_row("DHCP Range:", f"{spec.dhcp_start} – {spec.dhcp_end}")
        tbl.add_row(
            "Isolation Mode:",
            "[green]Strictly Isolated (No NAT / No External Forwarding)[/green]"
            if spec.is_isolated
            else "[bold red]WARNING: Forwarding Enabled[/bold red]",
        )
        if status["kali"]:
            k = status["kali"]
            k_str = (
                f"[green]Connected[/green] (mac={k['lab_mac']}, primary NAT preserved={k['has_nat_nic']})"
                if k["has_lab_nic"]
                else "[yellow]Not connected yet[/yellow] (run `lab-network setup`)"
            )
            tbl.add_row(f"Kali VM ({k['name']}):", k_str)
        console.print()
        console.print(tbl)

        if status["attached_vms"]:
            vtbl = Table(title="Attached Virtual Machines", header_style="bold magenta")
            vtbl.add_column("VM Name", style="bold")
            vtbl.add_column("State")
            vtbl.add_column("NIC Model")
            vtbl.add_column("MAC Address")
            vtbl.add_column("Active DHCP Lease(s)")
            for v in status["attached_vms"]:
                vtbl.add_row(
                    v["vm"],
                    "[green]Running[/green]" if v["active"] else "[dim]Shut off[/dim]",
                    v["model"],
                    v["mac"],
                    ", ".join(v["ips"]) if v["ips"] else "-",
                )
            console.print()
            console.print(vtbl)
    except Exception as exc:
        _print_error(exc)
        sys.exit(1)


@network_group.command("setup")
@click.option(
    "--subnet",
    "preferred_cidr",
    help="Preferred /24 private subnet CIDR (auto-selected if omitted).",
)
@click.option(
    "--attach-kali / --skip-kali",
    default=True,
    show_default=True,
    help="Attach a second NIC on pentest-lab to the Kali VM.",
)
@click.option("-y", "--yes", is_flag=True, help="Skip confirmation prompt.")
@click.pass_context
def network_setup_cmd(
    ctx: click.Context,
    preferred_cidr: str | None,
    attach_kali: bool,
    yes: bool,
) -> None:
    """Create and start the isolated pentest-lab network and attach Kali Linux."""
    try:
        conn = open_libvirt_connection(ctx.obj["libvirt_uri"])
        net_name = ctx.obj["network_name"]
        spec = inspect_or_plan_lab_network(
            conn, network_name=net_name, preferred_cidr=preferred_cidr
        )
        ensure_lab_network_active(conn, spec)
        console.print(
            f"[green]✓[/green] Isolated network [bold]{spec.name}[/bold] ({spec.subnet_cidr} on {spec.bridge_name}) is active."
        )

        if attach_kali:
            status = get_lab_network_status(conn, net_name)
            kali = status.get("kali")
            if kali and not kali["has_lab_nic"]:
                if not yes:
                    if not click.confirm(
                        f"Attach second NIC ({net_name}) to Kali VM {kali['name']!r} (preserving primary NAT adapter)?",
                        default=True,
                    ):
                        return
                changed, backup_path, k_mac = attach_kali_to_lab_network(
                    conn, lab_network_name=net_name, preferred_mac=spec.kali_mac
                )
                if changed:
                    console.print(
                        f"[green]✓[/green] Attached [bold]{net_name}[/bold] NIC (mac={k_mac}) to [bold]{kali['name']}[/bold]."
                    )
                    console.print(f"  [dim]Original XML backup saved at: {backup_path}[/dim]")
            elif kali and kali["has_lab_nic"]:
                console.print(
                    f"[green]✓[/green] Kali VM [bold]{kali['name']}[/bold] is already connected to [bold]{net_name}[/bold]."
                )
    except Exception as exc:
        _print_error(exc)
        sys.exit(1)


@network_group.command("discover")
@click.option(
    "--ping",
    "ping_sweep",
    is_flag=True,
    help="Send a lightweight broadcast ping restricted to the isolated bridge.",
)
@click.pass_context
def network_discover_cmd(ctx: click.Context, ping_sweep: bool) -> None:
    """Discover active VMs and IP leases on the isolated penetration-testing subnet."""
    try:
        conn = open_libvirt_connection(ctx.obj["libvirt_uri"])
        net_name = ctx.obj["network_name"]
        rows = discover_lab_subnet_hosts(conn, net_name, ping_sweep=ping_sweep)
        if not rows:
            console.print(f"No VMs or active leases found on {net_name!r}.")
            return
        tbl = Table(title=f"Hosts on {net_name}", header_style="bold cyan")
        tbl.add_column("VM / Hostname", style="bold")
        tbl.add_column("State")
        tbl.add_column("MAC Address")
        tbl.add_column("IPv4 Address", style="green")
        tbl.add_column("Discovery Source")
        for r in rows:
            tbl.add_row(r["vm"], r["state"], r["mac"], r["ip"], r["source"])
        console.print(tbl)
    except Exception as exc:
        _print_error(exc)
        sys.exit(1)


@click.command("doctor", context_settings={"help_option_names": ["-h", "--help"]})
def doctor_cmd() -> None:
    """Check Arch Linux virtualization dependencies, libvirt connectivity, and firmware."""
    deps = detect_dependencies()
    tbl = Table(title="VM Lab Importer Environment Check", header_style="bold cyan")
    tbl.add_column("Component", style="bold")
    tbl.add_column("Status")
    tbl.add_column("Details")

    def _row(label: str, ok: bool, detail: str, required: bool = True) -> None:
        badge = (
            "[green]✓ OK[/green]"
            if ok
            else ("[red]✗ Missing[/red]" if required else "[yellow]! Optional[/yellow]")
        )
        tbl.add_row(label, badge, detail)

    _row("qemu-img", bool(deps.qemu_img), deps.qemu_img or "Not found")
    _row("virsh", bool(deps.virsh), deps.virsh or "Not found")
    _row("qemu-system-x86_64", bool(deps.qemu_system_x86_64), deps.qemu_system_x86_64 or "Not found")
    _row("python-libvirt", deps.python_libvirt, "Available" if deps.python_libvirt else "Missing")
    _row(
        "virt-xml-validate",
        bool(deps.virt_xml_validate),
        deps.virt_xml_validate or "Not found",
        required=False,
    )
    _row("7z (7zip)", bool(deps.seven_zip), deps.seven_zip or "Not found", required=False)
    _row("virt-manager", bool(deps.virt_manager), deps.virt_manager or "Not found", required=False)
    _row("virt-viewer", bool(deps.virt_viewer), deps.virt_viewer or "Not found", required=False)
    _row(
        "UEFI Firmware (OVMF)",
        bool(deps.ovmf_code_path),
        str(deps.ovmf_code_path) if deps.ovmf_code_path else "Not found",
        required=False,
    )

    try:
        conn = open_libvirt_connection()
        hv_ver = conn.getVersion()
        _row("libvirt (qemu:///system)", True, f"Connected (hypervisor version {hv_ver})")
    except Exception as exc:
        _row("libvirt (qemu:///system)", False, str(exc))

    console.print(tbl)
    if not deps.ok:
        sys.exit(1)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", prog_name="lab-import")
def lab_group() -> None:
    """Unified CLI for the QEMU/KVM Penetration-Testing Lab Importer and Manager."""


lab_group.add_command(import_cmd, name="import")
lab_group.add_command(list_cmd, name="list")
lab_group.add_command(start_cmd, name="start")
lab_group.add_command(stop_cmd, name="stop")
lab_group.add_command(info_cmd, name="info")
lab_group.add_command(remove_cmd, name="remove")
lab_group.add_command(network_group, name="network")
lab_group.add_command(doctor_cmd, name="doctor")


def import_main() -> None:
    import_cmd.main(prog_name="lab-import")


def list_main() -> None:
    list_cmd.main(prog_name="lab-list")


def start_main() -> None:
    start_cmd.main(prog_name="lab-start")


def stop_main() -> None:
    stop_cmd.main(prog_name="lab-stop")


def info_main() -> None:
    info_cmd.main(prog_name="lab-info")


def remove_main() -> None:
    remove_cmd.main(prog_name="lab-remove")


def network_main() -> None:
    network_group.main(prog_name="lab-network")
