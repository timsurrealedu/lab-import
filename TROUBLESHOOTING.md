# Troubleshooting Guide (`lab-import`)

## 1. Environment & Libvirt Connection Issues

### `Could not connect to libvirt at qemu:///system`
- Verify the system libvirt daemon is running:
  ```bash
  systemctl status libvirtd.socket libvirtd.service
  ```
- Verify your user belongs to the `libvirt` group:
  ```bash
  id -nG | grep -w libvirt
  ```
- Run `lab doctor` to verify all required binaries (`qemu-img`, `virsh`, `qemu-system-x86_64`, `python-libvirt`, `OVMF`).

---

## 2. Guest Boot & Storage Troubleshooting

### Guest drops into `initramfs` / `dracut` emergency shell
- **Cause**: The guest OS lacks drivers for the selected disk controller, or `/etc/fstab` references `/dev/sdaX` while the disk was attached as `/dev/vdaX` (`virtio`).
- **Fix**: By default, `lab-import` selects `--disk-bus sata` (`ich9-ahci`, exposing `/dev/sda`), which is supported out-of-the-box by nearly all Linux and Windows kernels. For very old legacy OSes (e.g., Windows XP or ancient 2.4/2.6 Linux kernels), re-import with:
  ```bash
  lab-import --disk-bus ide <source>
  ```
  Or if the guest specifically requires a SCSI controller:
  ```bash
  lab-import --disk-bus scsi <source>
  ```

### Guest fails to find bootable device (`No bootable device`)
- **Cause**: The VM may have been installed in UEFI mode without `firmware = "efi"` in `.vmx` (or vice versa).
- **Fix**: Override firmware mode explicitly:
  ```bash
  lab-import --firmware efi <source>
  # or
  lab-import --firmware bios <source>
  ```

---

## 3. Guest Networking Troubleshooting

### Target VM boots but does not appear in `lab-network discover`
1. **Wait for boot completion**: Older Ubuntu/Debian appliances may run `fsck` or cloud-init network wait targets for 30–60 seconds on first boot, especially if the lecturer archived the VM with `cleanShutdown = "FALSE"`.
2. **Predictable interface naming (`ens33`)**:
   - `lab-import` automatically maps VMware's `ethernet0.pciSlotNumber = "33"` to `pci-bridge` `bus=0x01, slot=0x01` so Linux `acpiphp`/`udev` names the NIC `ens33` and preserves the VMware MAC address.
   - If the target VM was configured with a hardcoded static IP on another subnet inside the guest OS, use `lab-start <vm> --viewer` or `virsh -c qemu:///system console <vm>` or run ARP discovery from Kali on `eth1`:
     ```bash
     sudo arp-scan --interface=eth1 --localnet
     ```

### Kali Linux (`kalilinux`) Second Interface (`eth1`) Setup
- When `kalilinux` is attached to `pentest-lab`, it has two `virtio` NICs:
  - `eth0` (`default` NAT network `192.168.122.0/24`): Retains the default gateway (`192.168.122.1`) and internet access.
  - `eth1` (`pentest-lab` isolated network `10.10.10.0/24`): Receives `10.10.10.2/24` via DHCP with **no default gateway** (`dhcp-option=3` on isolated libvirt networks), so it never overrides `eth0`'s internet route.
- If `eth1` inside Kali is down, run inside Kali:
  ```bash
  sudo ip link set eth1 up
  sudo dhclient eth1   # or: sudo nmcli device connect eth1
  ```
- Original XML backups for `kalilinux` are stored in:
  ```text
  ~/.local/state/lab-import/backups/
  ```
  To restore `kalilinux` to its pre-lab XML at any time:
  ```bash
  virsh -c qemu:///system define ~/.local/state/lab-import/backups/kalilinux-<timestamp>.xml
  ```

---

## 4. Snapshots, Locks, and Disk Space

### `Ambiguous snapshot state ... found delta snapshot disk(s)`
- The source directory contains `*-000001.vmdk` delta files that are not part of the active disk chain in `.vmx`.
- To import only the active disk referenced by `.vmx`:
  ```bash
  lab-import --ignore-unreferenced-snapshots <source>
  ```
- Or pass the specific leaf snapshot `.vmdk` directly.

### Staging / Cache Cleanup
- Temporary archive extractions are stored in `~/.cache/lab-import/staging/` and removed automatically.
- Diagnostic logs are written to `~/.local/state/lab-import/lab-import.log`.
