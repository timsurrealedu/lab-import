# VM Lab Importer (`lab-import`)

Automated Virtual Machine Lab Importer from VMware formats (`.zip`, `.7z`, `.tar.*`, `.ova`, extracted VMware directories, `.vmx`, or standalone `.vmdk`) into **QEMU/KVM** with **libvirt** (`qemu:///system`) and **Virt-Manager**.

Designed specifically for penetration-testing coursework and CTF environments on Arch Linux, where target machines are distributed as VMware bundles and need to be imported into an isolated virtual network alongside Kali Linux (`kalilinux`).

---

## Key Features

- **Single-Command Import**:
  ```bash
  lab-import ~/Documents/Workspace/University/BINUS/Sem3/NetPentest/Lab/Sources/LinkedBase.zip
  ```
- **Secure Archive Extraction**:
  - Treats all archives (`.zip`, `.7z`, `.tar`, `.tar.gz`, `.tar.xz`, `.ova`) as untrusted.
  - Pre-extraction inspection blocks path traversal (`..`, absolute paths, Windows drive letters), symbolic/hard links, special device/FIFO nodes, path collisions, and decompression bombs.
  - Streams into a `0700` staging directory under `~/.cache/lab-import/staging` (on main NVMe storage, avoiding `/tmp` RAM `tmpfs` exhaustion), strips all executable/setuid bits (`0600`), skips multi-gigabyte transient `.vmem`/`.lck`/`.log` artifacts, and automatically cleans up on completion or interruption.
- **Smart VMware-to-KVM Hardware Translation**:
  - Parses `.vmx` and `.vmsd` metadata, filtering out missing host ISO/floppy paths (such as Windows `D:\...iso` or `autoinst.iso`/`autoinst.flp`).
  - Uses **SATA (`ich9-ahci`, `/dev/sdX`)** by default for disk buses so guests without VirtIO block drivers (`virtio_blk`) and guests with `/dev/sda` hardcoded in `/etc/fstab` or GRUB boot cleanly on the first attempt.
  - **Predictable Network Interface Naming (`ens33`) Preservation**: Maps VMware's `ethernet0.pciSlotNumber = "33"` (`pciBridge0` slot 1) to a QEMU `pci-bridge` (`chassisNr=1`, `bus=0x01, slot=0x01`), so Linux `acpiphp`/`systemd-udevd` assigns the exact same interface name (`ens33`) and MAC address (`00:0c:29:...`) inside KVM—allowing Ubuntu Server Netplan (`ens33: dhcp4: true`) and `70-persistent-net.rules` configs to work on first boot without modifying guest disks.
- **Unprivileged Native-Speed Disk Conversion**:
  - Pre-allocates target `.qcow2` volumes in `/var/lib/libvirt/images` via the libvirt storage pool API (`qemu:///system`) with user write permissions (`0660`, `<uid>:libvirt`), then runs `qemu-img convert -p -n -O qcow2` directly without needing `sudo`.
  - Detects and verifies split VMDKs (`twoGbMaxExtentSparse`), monolithic VMDKs, and snapshot chains (`parentCID` / `parentFileNameHint` / `.vmsd`). Blocks ambiguous or broken snapshot chains before conversion.
- **Reusable Isolated Penetration-Testing Network (`pentest-lab`)**:
  - Automatically scans all host interfaces (`wlp191s0`, `virbr0`, `vmnet1`, `vmnet8`, `docker0`, `tailscale0`), routing tables, and libvirt networks to select a collision-free private `/24` subnet (default `10.10.10.0/24` on `virbr-lab`).
  - Configured with **no `<forward>` element** in libvirt:
    1. Vulnerable target VMs cannot reach the internet or physical home LAN.
    2. Libvirt's `dnsmasq` automatically advertises `dhcp-option=3` (empty router option), so when `kalilinux` brings up its second interface (`eth1` on `pentest-lab`), it does **not** replace its primary default route (`eth0` via `192.168.122.1`).
- **Transactional Rollback**:
  - If conversion or domain creation fails or is interrupted (`Ctrl+C`), any newly created partial `.qcow2` volumes and domain definitions are rolled back automatically while preserving original source archives and VMDKs untouched.

---

## Installation (Arch Linux)

### 1. System Dependencies

Required packages (already installed on this system):
- `libvirt`, `python-libvirt`, `qemu-base`, `qemu-system-x86`, `python-click`, `python-rich`
- Optional: `7zip` (`7z`), `virt-manager`, `virt-viewer`, `edk2-ovmf`

Check environment readiness at any time:
```bash
lab doctor
```

### 2. Install CLI Commands

```bash
cd ~/Documents/Workspace/Projects/lab-import
./install.sh
```

This installs the following commands into `~/.local/bin`:
- `lab-import`
- `lab-list`
- `lab-start`
- `lab-stop`
- `lab-info`
- `lab-remove`
- `lab-network`
- `lab` (unified CLI group with `import`, `list`, `start`, `stop`, `info`, `remove`, `network`, `doctor`)

### 3. Uninstall

```bash
cd ~/Documents/Workspace/Projects/lab-import
./uninstall.sh          # Removes CLI symlinks; preserves VMs, networks, and virtualenv
./uninstall.sh --purge  # Also removes .venv and ~/.cache/lab-import staging cache
```

---

## Usage Examples

### Import a VMware Archive or Folder

```bash
# Import directly from a ZIP, 7z, TAR, or OVA archive
lab-import ~/Documents/Workspace/University/BINUS/Sem3/NetPentest/Lab/Sources/LinkedBase.zip

# Import from an already extracted VMware folder
lab-import ~/Documents/Workspace/University/BINUS/Sem3/NetPentest/Lab/Sources/LinkedBase

# Preview the hardware translation plan and generated libvirt XML without modifying anything
lab-import --dry-run --show-xml ~/Documents/Workspace/University/BINUS/Sem3/NetPentest/Lab/Sources/LinkedBase

# Import and immediately run a boot + DHCP lease verification check
lab-import --validate-boot ~/Documents/Workspace/University/BINUS/Sem3/NetPentest/Lab/Sources/LinkedBase

# Non-interactive import with custom name and RAM override
lab-import --non-interactive --yes --name LinkedBase-Lab --memory 4096 LinkedBase.zip
```

### Manage Lab VMs

```bash
# List all lab VMs, Kali Linux, and active DHCP leases
lab-list

# Start a target VM and wait for its DHCP IP on pentest-lab
lab-start LinkedBase --wait-ip

# Start a target VM and open a Virt-Viewer graphical console
lab-start LinkedBase --viewer

# View detailed hardware, disk, network, and provenance metadata
lab-info LinkedBase

# Gracefully shut down a VM (ACPI)
lab-stop LinkedBase

# Force power-off an unresponsive VM
lab-stop LinkedBase --force

# Remove an imported VM and (with confirmation) delete its converted QCOW2 disk
lab-remove LinkedBase
```

### Manage the Isolated Lab Network (`pentest-lab`)

```bash
# Show network state, isolation verification, Kali attachment, and attached VMs
lab-network status

# Initialize pentest-lab and attach a second NIC to kalilinux
lab-network setup

# Discover active hosts and DHCP/ARP leases on pentest-lab
lab-network discover --ping
```

---

## Known Limitations

- **Suspended VMware RAM State (`.vmss`)**: VMware memory checkpoints are proprietary and cannot be converted into KVM RAM state. If a source VM is suspended (`checkpoint.vmState`), `lab-import` stops and asks you to either shut it down cleanly in VMware first or pass `--allow-suspended` to import the disk state (equivalent to a cold reboot).
- **Encrypted VMDKs / vTPM**: VMware password-encrypted `.vmx`/`.vmdk` bundles must be decrypted in VMware Workstation prior to import.
- **Branched Snapshot Trees**: Linear active snapshot chains are flattened automatically into the output `.qcow2`. If a VM folder contains unreferenced delta disks (`*-000001.vmdk`) outside the active chain, `lab-import` stops and explains the ambiguity unless `--ignore-unreferenced-snapshots` is specified.
