# bf-release

src/mlnx-pre-hlk

src/mlnx-post-hlk

# Network configuration tool for Ubuntu

src/network_admin.py

# Ubuntu OS upgrade tool using DUAL boot
src/bfb_tool.py

src/bfb_admin.py

src/kexec_reboot - Script to reboot DPU using kexec

src/config.toml - containerd configuration

# kubelet configuration
src/10-bf.conf

src/config.yaml

src/99-loopback.conf - CNI configuration

src/crictl.yaml

~~src/crictl~~ install from [cri-tools](https://github.com/kubernetes-sigs/cri-tools#debrpm-packages)

src/override-networkd-wait-online - networkd-wait-online override.conf

src/override-networking - networking override.conf

src/override-netplan-ovs-cleanup - netplan-ovs-cleanup override.conf

src/90-bluefield.conf - sysctl configuration file

# NetworkManager configuration

src/40-mlnx.conf

src/45-mlnx-dns.conf

# UDEV rules
src/80-ifupdown.rules - override /usr/lib/udev/rules.d/80-ifupdown.rules

src/93-nodnic.rules

src/92-oob_net.rules

src/91-tmfifo_net.rules

# mlnx_bf_confifure configuration files

src/mlnx-bf.conf

src/mlnx-ovs.conf

# DOCA APT repository

src/doca.list

# Cloud-init conifugration files for Ubuntu

src/cloud/seed/nocloud-net/meta-data

src/cloud/seed/nocloud-net/user-data

# Network configuration files for Debian:

src/debian-network/0-tmfifo

src/debian-network/1-oob_net0

# ACPI power button configurations

src/mlnx-powerconf

src/rebootcontrol

# RPM kernel selection

`bf-select-kernel` selects the installed kernel required by
`doca-runtime-kernel` / `doca-devel-kernel` for the next boot. A transaction file
trigger invokes it after RPM post-transaction scripts when the helper, kernel
files, modules, or DOCA kernel profile files are installed or upgraded. This also
covers kernel upgrades that do not upgrade `bf-release` itself.

The helper resolves the exact kernel requirement through the installed RPMs,
including split `kernel` / `kernel-core` packages. It checks the image, initramfs,
and module directory before regenerating GRUB and selecting that image with
`grubby`. Existing kernel arguments are preserved. EFI forwarding stubs are left
intact; the configuration behind them is updated. Failed generation or selection
restores the previous GRUB configuration and environment. Failures are reported
by the RPM trigger; installed packages are not rolled back.

To inspect the selected target without writing boot files:

```sh
sudo bf-select-kernel --check
```

Image builds without live EFI, RHCOS/OSTree systems, and installations without an
exact DOCA kernel requirement are skipped. Ambiguous kernel or boot layouts and
missing boot files produce an error rather than selecting a different kernel.
The helper does not install/remove kernels, change version locks, activate
firmware, or reboot. Repository and kernel lock policy must allow DNF to install
the required kernel first. The selection takes effect at the next planned reboot.

Run the isolated boot-selection tests with:

```sh
python3 -B -m unittest discover -s tests -p 'test_bf_select_kernel.py' -v
```

These tests use temporary boot files and mocked RPM/GRUB tools. Validation on
supported RPM distros and BlueField hardware is required before removing the
manual kernel/GRUB steps from upgrade documentation.
