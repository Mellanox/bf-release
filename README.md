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

src/cloud/seed/nocloud-net/network-config

# Network configuration files for Debian:

src/debian-network/0-tmfifo

src/debian-network/1-oob_net0

src/debian-network/enp3s0f0s0

src/debian-network/enp3s0f1s0

