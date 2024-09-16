Name: bf-release
Version: 4.9.0
Release: 1%{?dist}
Summary: BF release information

License: GPLv2/BSD
Url: https://developer.nvidia.com/networking/doca
Group: System Environment/Base
Source: %{name}-%{version}.tar.gz
%if "%_vendor" == "redhat" && 0%{?rhel} < 9
BuildRequires: redhat-lsb-core
%endif
Requires: kexec-tools
Requires: acpid
Requires: grub2-tools
Requires: NetworkManager
Requires: mlnx-tools
%if !0%{?oraclelinux}
Requires: containerd.io
Requires: mlnx-ofa_kernel
%endif
BuildRoot: %{?build_root:%{build_root}}%{!?build_root:/var/tmp/%{name}-%{version}-root}
Vendor: Nvidia
%description
BlueField release files and post-installation configuration

%{!?NETWORKING_TIMEOUT: %global NETWORKING_TIMEOUT 30}

%define __python %{__python3}

%prep
%setup -q

%install

BF_VERSION=""
if [[ -e /etc/mlnx-release && -s /etc/mlnx-release ]]; then
	BF_VERSION=`cat /etc/mlnx-release`
fi

if [ ! -n "$BF_VERSION" ]; then
	BF_BOOTIMG_VERSION=$(rpm -q --queryformat "[%{VERSION}.%{RELEASE}]" $(rpm -q --whatprovides mlxbf-bootimages))
	DOCA_VERSION=$(rpm -q --queryformat "[%{VERSION}]" doca-prime-runtime)
	DIST_NAME=`lsb_release -is`
	BF_VERSION="DOCA_${DOCA_VERSION}_BSP_${BF_BOOTIMG_VERSION}_${DIST_NAME}_${DIST_VERSION}-$(date +%Y%m%d).prod"
fi

install -d %{buildroot}/etc
echo ${BF_VERSION} > %{buildroot}/etc/mlnx-release

# Tools
install -d %{buildroot}/opt/mellanox/hlk
install -d %{buildroot}/sbin
install -d %{buildroot}/%{_sbindir}

install -m 0755	src/mlnx-pre-hlk     %{buildroot}/opt/mellanox/hlk/mlnx-pre-hlk
install -m 0755	src/mlnx-post-hlk    %{buildroot}/opt/mellanox/hlk/mlnx-post-hlk
install -m 0755	src/kexec_reboot     %{buildroot}/sbin/kexec_reboot
install -m 0755	src/dpu-bmc-upgrade  %{buildroot}/%{_sbindir}/dpu-bmc-upgrade

# Sysctl
install -d %{buildroot}/usr/lib/sysctl.d/
install -m 0644	src/90-bluefield.conf	%{buildroot}/usr/lib/sysctl.d/

# UDEV rules
install -d %{buildroot}/lib/udev/rules.d
install -m 0644 src/91-tmfifo_net.rules		%{buildroot}/lib/udev/rules.d
install -m 0644 src/92-oob_net.rules		%{buildroot}/lib/udev/rules.d

# System services
install -d %{buildroot}/etc/systemd/system/NetworkManager-wait-online.service.d
install -d %{buildroot}/etc/systemd/system/network.service.d
install -d %{buildroot}/etc/sysconfig/network-scripts

# Network configuration
cat > %{buildroot}/etc/sysconfig/network-scripts/ifcfg-tmfifo_net0 << EOF
TYPE=Ethernet
BOOTPROTO=none
IPADDR=192.168.100.2
PREFIX=30
DNS1=192.168.100.1
NAME=tmfifo_net0
DEVICE=tmfifo_net0
ONBOOT=yes
GATEWAY=192.168.100.1
IPV4_ROUTE_METRIC=1025
EOF

cat > %{buildroot}/etc/sysconfig/network-scripts/ifcfg-enp3s0f0s0 << EOF
NAME="enp3s0f0s0"
DEVICE="enp3s0f0s0"
NM_CONTROLLED="no"
DEVTIMEOUT=30
PEERDNS="yes"
ONBOOT="yes"
BOOTPROTO="dhcp"
TYPE=Ethernet
EOF

cat > %{buildroot}/etc/sysconfig/network-scripts/ifcfg-enp3s0f1s0 << EOF
NAME="enp3s0f1s0"
DEVICE="enp3s0f1s0"
NM_CONTROLLED="no"
DEVTIMEOUT=30
PEERDNS="yes"
ONBOOT="yes"
BOOTPROTO="dhcp"
TYPE=Ethernet
EOF

cat > %{buildroot}/etc/sysconfig/network-scripts/ifcfg-oob_net0 << EOF
NAME="oob_net0"
DEVICE="oob_net0"
NM_CONTROLLED="yes"
PEERDNS="yes"
ONBOOT="yes"
BOOTPROTO="dhcp"
TYPE=Ethernet
EOF

cat > %{buildroot}/etc/systemd/system/NetworkManager-wait-online.service.d/override.conf << EOF
[Service]
ExecStart=
ExecStart=/usr/bin/nm-online -s -q --timeout=%{NETWORKING_TIMEOUT}
EOF
chmod 644 %{buildroot}/etc/systemd/system/NetworkManager-wait-online.service.d/override.conf

cat > %{buildroot}/etc/systemd/system/network.service.d/override.conf << EOF
[Service]
TimeoutSec=%{NETWORKING_TIMEOUT}sec
EOF
chmod 644 %{buildroot}/etc/systemd/system/network.service.d/override.conf

install -d %{buildroot}/etc/NetworkManager/conf.d
install -m 0644 src/40-mlnx.conf		%{buildroot}/etc/NetworkManager/conf.d/
install -m 0644 src/45-mlnx-dns.conf	%{buildroot}/etc/NetworkManager/conf.d/

install -d %{buildroot}/etc/mellanox
install -m 0644 src/mlnx-bf.conf	%{buildroot}/etc/mellanox
install -m 0644 src/mlnx-ovs.conf	%{buildroot}/etc/mellanox

install -d %{buildroot}/etc/acpi/actions/
install -m 0755 src/rebootcontrol	%{buildroot}/etc/acpi/actions/
install -m 0755 src/bf-upgrade		%{buildroot}/etc/acpi/actions/
cp -a src/bf-upgrade.env			%{buildroot}/etc/acpi/actions/

install -d %{buildroot}/etc/acpi/events/
install -m 0644 src/mlnx-powerconf	%{buildroot}/etc/acpi/events/
install -m 0644 src/mlnx-lidconf	%{buildroot}/etc/acpi/events/

install -d %{buildroot}/etc/systemd/logind.conf.d/
install -m 0644 src/lid.conf		%{buildroot}/etc/systemd/logind.conf.d/

# mlnx-snap
install -d %{buildroot}/opt/mellanox/mlnx_snap/exec_files
install -m 0755	src/network_admin.py %{buildroot}/opt/mellanox/mlnx_snap/exec_files/network_admin.py
install -m 0755	src/bfb_admin.py     %{buildroot}/opt/mellanox/mlnx_snap/exec_files/bfb_admin.py
install -m 0755	src/bfb_tool.py      %{buildroot}/opt/mellanox/mlnx_snap/exec_files/bfb_tool.py

# K8s
install -d %{buildroot}/etc/containerd
install -d %{buildroot}/usr/lib/systemd/system/kubelet.service.d
install -d %{buildroot}/etc/cni/net.d
install -d %{buildroot}/var/lib/kubelet
install -d %{buildroot}/usr/bin
install -d %{buildroot}/%{_datadir}/%{name}
install -d %{buildroot}/etc/kubelet.d/

install -m 0644	src/config.toml      %{buildroot}/%{_datadir}/%{name}/config.toml
install -m 0644	src/90-kubelet-bluefield.conf %{buildroot}/usr/lib/systemd/system/kubelet.service.d/90-kubelet-bluefield.conf
install -m 0644	src/99-loopback.conf %{buildroot}/etc/cni/net.d/99-loopback.conf
install -m 0644	src/crictl.yaml      %{buildroot}/etc/crictl.yaml
install -m 0644	src/config.yaml      %{buildroot}/var/lib/kubelet/config.yaml

# BFB Info
install -m 0755	src/bfb-info           %{buildroot}/usr/bin/bfb-info

%post
if [ $1 -eq 1 ]; then
if (grep -q OFED-internal /usr/bin/ofed_info > /dev/null 2>&1); then
    ofed_version=`ofed_info -n`
    ofed_minor=${ofed_version#*-}
    fw_minor=`rpm -q --queryformat "%{RELEASE}" mlnx-fw-updater 2> /dev/null 2>&1 | cut -d '-' -f 2`
    fw_sub_minor=`echo $fw_minor | cut -d '.' -f -3`
    if [ "$ofed_minor" == "$fw_sub_minor" ]; then
        ofed_version=${ofed_version}.`echo $fw_minor | cut -d '.' -f 4`
    fi
    sed -i -r -e "s/^(OFED)(.*)(-[0-9]*.*-[0-9]*.*):/MLNX_OFED_LINUX-${ofed_version} (\1\3):\n/" /usr/bin/ofed_info
    sed -i -r -e "s/(.*then echo) (.*):(.*)/\1 MLNX_OFED_LINUX-${ofed_version}: \3/" /usr/bin/ofed_info
    sed -i -r -e "s/(.*X-n\" ]; then echo) (.*)(; exit.*)/\1 ${ofed_version} \3/" /usr/bin/ofed_info
    sed -i -e "s/OFED-internal/MLNX_OFED_LINUX/g" /usr/bin/ofed_info
fi

if [ ! -e /etc/containerd/config.toml ]; then
	mkdir -p /etc/containerd
	cp %{_datadir}/%{name}/config.toml /etc/containerd
else
	mv /etc/containerd/config.toml %{_datadir}/%{name}/config.toml.orig
	cp %{_datadir}/%{name}/config.toml /etc/containerd/config.toml
fi

# Use mlxconfig instead of mstconfig to support BF2
if [ -x /usr/bin/mlxconfig ]; then
    sed -i -e "s/mstconfig/mlxconfig/g" /sbin/mlnx_bf_configure /sbin/mlnx-sf
fi

if [ -e /etc/default/grub ]; then
	# Show grub menu and set a timeout
	sed -i 's/.*GRUB_TIMEOUT_STYLE=.*/GRUB_TIMEOUT_STYLE=countdown/' /etc/default/grub
	if ! (grep -q GRUB_TIMEOUT_STYLE /etc/default/grub); then
		echo "GRUB_TIMEOUT_STYLE=countdown" >> /etc/default/grub
	fi
	perl -ni -e 'print unless /GRUB_RECORDFAIL_TIMEOUT/' /etc/default/grub
	sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=2\nGRUB_RECORDFAIL_TIMEOUT=2/' /etc/default/grub
	sed -i -r -e 's/(GRUB_ENABLE_BLSCFG=).*/\1false/' /etc/default/grub
	sed -i 's/GRUB_RECORDFAIL_TIMEOUT:-30/GRUB_RECORDFAIL_TIMEOUT:-2/' /etc/grub.d/00_header

	# Use console
	sed -i 's/.*GRUB_TERMINAL=.*/GRUB_TERMINAL=console/' /etc/default/grub
fi

# Linux: use console and set a sensible date on boot (the later is important
# when resizing the partitions on first boot).
sed -i \
    -e 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="console=hvc0 console=ttyAMA0 earlycon=pl011,0x01000000 fixrtc net.ifnames=0 biosdevname=0 iommu.passthrough=1"/' \
    -e 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=""/' \
    /etc/default/grub

perl -ni -e 'print unless /GRUB_DISABLE_LINUX_UUID/' /etc/default/grub
echo "GRUB_DISABLE_LINUX_UUID=false" >> /etc/default/grub

if [ -d /etc/default/grub.d ]; then
    echo "GRUB_DISABLE_OS_PROBER=true" > /etc/default/grub.d/10-disableos-prober.cfg
fi

if [ -e /etc/default/networking ]; then
    sed -i -r -e "s/.*WAIT_ONLINE_TIMEOUT.*/WAIT_ONLINE_TIMEOUT=5/" /etc/default/networking
fi

# Disable kexec
if [ -e /etc/default/kexec ]; then
	sed -i -r -e "s/(LOAD_KEXEC=).*/\1false/;s/(USE_GRUB_CONFIG=).*/\1true/" /etc/default/kexec
fi

# Verify/copy udev rules
rule82=`/bin/ls -1 /usr/share/doc/mlnx-ofa_kernel*/82-net-setup-link.rules 2> /dev/null`
if [ -n "$rule82" ]; then
	mkdir -p /lib/udev/rules.d
	/bin/rm -f /lib/udev/rules.d/82-net-setup-link.rules
	/bin/rm -f /etc/udev/rules.d/82-net-setup-link.rules
	install -m 0644 $rule82 /lib/udev/rules.d/82-net-setup-link.rules
fi

vf_net=`/bin/ls -1 /usr/share/doc/mlnx-ofa_kernel*/vf-net-link-name.sh 2> /dev/null`
if [ -n "$vf_net" ]; then
	mkdir -p /etc/infiniband
	/bin/rm -f /etc/infiniband/vf-net-link-name.sh
	install -m 0755 $vf_net /etc/infiniband/vf-net-link-name.sh
	# Add a workaround for the port names staring with c<n>
	sed -i  -e 's@^PORT_NAME=$1@PORT_NAME=`echo ${1} | sed -e "s/c[[:digit:]]\\+//"`@' /etc/infiniband/vf-net-link-name.sh
fi

enable_service()
{
    service_name=$1

    if ! (systemctl list-unit-files 2>&1 | grep -w ^$service_name); then
        return
    fi
    systemctl unmask $service_name || true
    systemctl enable $service_name || true
}

disable_service()
{
    service_name=$1

    if ! (systemctl list-unit-files 2>&1 | grep -w ^$service_name); then
        return
    fi
    systemctl disable $service_name || true
}

# Enable tmpfs in /tmp
enable_service tmp.mount

enable_service NetworkManager.service
enable_service NetworkManager-wait-online.service
enable_service acpid.service
enable_service openibd
enable_service network
enable_service mlnx_snap
enable_service mst
enable_service openvswitch.service
enable_service watchdog.service
# Enable ipmi services
enable_service mlx_ipmid.service
enable_service set_emu_param.service
enable_service kdump.service

disable_service openvswitch-ipsec
disable_service ibacm.service
disable_service opensmd.service
disable_service strongswan-starter.service

fi

%preun
if [ $1 = 0 ]; then  # 1 : Erase, not upgrade
	if [ -e %{_datadir}/%{name}/config.toml.orig ]; then
		/bin/rm -f /etc/containerd/config.toml
		mv  %{_datadir}/%{name}/config.toml.orig /etc/containerd/config.toml
	fi
fi

%files
/etc/mlnx-release
%{_datadir}/%{name}/config.toml

%dir /etc/acpi/events/
/etc/acpi/events/mlnx-powerconf
/etc/acpi/events/mlnx-lidconf

%dir /etc/acpi/actions/
/etc/acpi/actions/rebootcontrol
/etc/acpi/actions/bf-upgrade
%dir /etc/acpi/actions/bf-upgrade.env
/etc/acpi/actions/bf-upgrade.env/*

%dir /etc/systemd/logind.conf.d/
/etc/systemd/logind.conf.d/lid.conf

%dir /opt/mellanox/hlk
/opt/mellanox/hlk/*

/sbin/kexec_reboot
%{_sbindir}/dpu-bmc-upgrade

/usr/lib/sysctl.d/*
/lib/udev/rules.d/*
/etc/sysconfig/network-scripts/*
/etc/systemd/system/NetworkManager-wait-online.service.d/override.conf
/etc/systemd/system/network.service.d/override.conf
/etc/NetworkManager/conf.d/*

%dir /etc/mellanox
/etc/mellanox/*

%dir /opt/mellanox/mlnx_snap/exec_files
/opt/mellanox/mlnx_snap/exec_files/*

# %dir /etc/containerd
# /etc/containerd/config.toml

/usr/lib/systemd/system/kubelet.service.d/90-kubelet-bluefield.conf

%dir /etc/cni/net.d
/etc/cni/net.d/99-loopback.conf

/etc/crictl.yaml

%dir /var/lib/kubelet
/var/lib/kubelet/config.yaml

%dir /etc/kubelet.d

/usr/bin/bfb-info

%changelog
