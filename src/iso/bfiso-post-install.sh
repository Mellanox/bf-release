#!/bin/bash

###############################################################################
#
# Copyright 2024 NVIDIA Corporation
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
###############################################################################

PATH="/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/opt/mellanox/scripts"

NIC_FW_UPDATE_DONE=0
FORCE_NIC_FW_UPDATE=${FORCE_NIC_FW_UPDATE:-"no"}
NIC_FW_RESET_REQUIRED=0
NIC_FW_FOUND=0
FW_UPDATER=/opt/mellanox/mlnx-fw-updater/mlnx_fw_updater.pl
FW_DIR=/opt/mellanox/mlnx-fw-updater/firmware/

distro="Ubuntu"

rshimlog=$(which bfrshlog 2> /dev/null)
RC=0
err_msg=""
export LC_ALL=C

rlog()
{
    msg=$(echo "$*" | sed 's/INFO://;s/ERROR:/ERR/;s/WARNING:/WARN/')
    if [ -n "$rshimlog" ]; then
        $rshimlog "$msg"
    fi
}

ilog()
{
    msg="[$(date +%H:%M:%S)] $*"
    echo "$msg" >> $LOG
    echo "$msg" > /dev/ttyAMA0
    echo "$msg" > /dev/hvc0
}

log()
{
    ilog "$*"
    rlog "$*"
}

if [ ! -e /etc/udev/rules.d/92-oob_net.rules ]; then
	cat > /etc/udev/rules.d/92-oob_net.rules << 'EOF'
SUBSYSTEM=="net", ACTION=="add", DEVPATH=="/devices/platform/MLNXBF17:00/net/e*", NAME="oob_net0", RUN+="/sbin/sysctl -w net.ipv4.conf.oob_net0.arp_notify=1"
SUBSYSTEM=="net", ACTION=="add", DRIVERS=="virtio_net", PROGRAM="/bin/sh -c 'lspci -vv | grep -wq SimX'", NAME="oob_net0", RUN+="/sbin/sysctl -w net.ipv4.conf.oob_net0.arp_notify=1"
EOF
fi

modprobe nls_iso8859-1
modprobe sdhci-of-dwcmshc
modprobe dw_mmc-bluefield
modprobe mlxbf_tmfifo
modprobe gpio_mlxbf3
modprobe mlxbf_gige
modprobe -a ipmi_msghandler ipmi_devintf i2c-mlxbf
modprobe ipmb_host slave_add=0x10
echo ipmb-host 0x1011 > /sys/bus/i2c/devices/i2c-1/new_device
modprobe -a mlx5_ib mlxfw ib_umad
modprobe nvme
modprobe mlxbf_bootctl
modprobe sbsa_gwdt
sleep 5

ilog "Starting mst:"
ilog "$(mst start)"

#
# Check PXE installation
#
if [ ! -e /tmp/bfpxe.done ]; then touch /tmp/bfpxe.done; bfpxe; fi


if [ -e /etc/bf.cfg ]; then
    log "INFO: Found bf.cfg"
    if ( bash -n /etc/bf.cfg ); then
        . /etc/bf.cfg
    else
        log "INFO: Invalid bf.cfg"
    fi
fi

logfile=${distro}.installation.log
LOG=/root/$logfile

fspath=$(readlink -f "$(dirname $0)")

ROOTFS=${ROOTFS:-"ext4"}

export cx_pcidev=$(lspci -nD 2> /dev/null | grep 15b3:a2d[26c] | awk '{print $1}' | head -1)
export flint_dev=$cx_pcidev

export FLINT=mstflint
if [ ! -x /usr/bin/mstflint ]; then
	FLINT=flint
fi

is_SecureBoot=0
if (mokutil --sb-state 2>&1 | grep -q "SecureBoot enabled"); then
        is_SecureBoot=1
fi

if [ $is_SecureBoot -eq 1 ]; then
        mst_dev=$(/bin/ls -1 /dev/mst/mt*_pciconf0 2> /dev/null)
        if [ ! -n "${mst_dev}" ]; then
                mst start > /dev/null 2>&1
        fi
        flint_dev=$(/bin/ls -1 /dev/mst/mt*_pciconf0 2> /dev/null)
        FLINT=flint
fi

export dpu_part_number=$($FLINT -d $flint_dev q full | grep "Part Number:" | awk '{print $NF}')

cx_dev_id=$(lspci -nD -s ${cx_pcidev} 2> /dev/null | awk -F ':' '{print strtonum("0x" $NF)}')
pciids=$(lspci -nD 2> /dev/null | grep 15b3:a2d[26c] | awk '{print $1}')
dpu_part_number=$($FLINT -d $flint_dev q full | grep "Part Number:" | awk '{print $NF}')
PSID=$($FLINT -d $flint_dev q | grep PSID | awk '{print $NF}')

UPDATE_ATF_UEFI=${UPDATE_ATF_UEFI:-"yes"}
UPDATE_DPU_OS=${UPDATE_DPU_OS:-"yes"}
WITH_NIC_FW_UPDATE=${WITH_NIC_FW_UPDATE:-"yes"}
NIC_FW_UPDATE_PASSED=0
DHCP_CLASS_ID=${PXE_DHCP_CLASS_ID:-""}
DHCP_CLASS_ID_OOB=${DHCP_CLASS_ID_OOB:-"NVIDIA/BF/OOB"}
DHCP_CLASS_ID_DP=${DHCP_CLASS_ID_DP:-"NVIDIA/BF/DP"}
# 00:00:16:47 represents the IANA-assigned Enterprise Number for NVIDIA (5703 in decimal) NVIDIA/BF/OOB
DHCP_CLASS_ID_OOB_IPV6=${DHCP_CLASS_ID_OOB_IPV6:-"00:00:16:47:00:0d:4E:56:49:44:49:41:2F:42:46:2F:4F:4F:42"}
# 00:00:16:47 represents the IANA-assigned Enterprise Number for NVIDIA (5703 in decimal) NVIDIA/BF/DP
DHCP_CLASS_ID_DP_IPV6=${DHCP_CLASS_ID_DP_IPV6:-"00:00:16:47:00:0c:4E:56:49:44:49:41:2f:42:46:2f:44:50"}
FACTORY_DEFAULT_DHCP_BEHAVIOR=${FACTORY_DEFAULT_DHCP_BEHAVIOR:-"true"}

if [ "${FACTORY_DEFAULT_DHCP_BEHAVIOR}" == "true" ]; then
    # Set factory defaults
    DHCP_CLASS_ID="NVIDIA/BF/PXE"
    DHCP_CLASS_ID_OOB="NVIDIA/BF/OOB"
    DHCP_CLASS_ID_DP="NVIDIA/BF/DP"
    DHCP_CLASS_ID_OOB_IPV6="00:00:16:47:00:0d:4E:56:49:44:49:41:2F:42:46:2F:4F:4F:42"
    DHCP_CLASS_ID_DP_IPV6="00:00:16:47:00:0c:4E:56:49:44:49:41:2f:42:46:2f:44:50"
fi

default_device=/dev/mmcblk0
if [ -b /dev/nvme0n1 ]; then
    default_device="/dev/$(cd /sys/block; /bin/ls -1d nvme* | sort -n | tail -1)"
fi
device=${device:-"$default_device"}
BOOT_PARTITION=${device}p1
ROOT_PARTITION=${device}p2

save_log()
{
cat >> $LOG << EOF

########################## DMESG ##########################
$(dmesg -x)
EOF
	sync
	for pw in $(grep "PASSWORD=" $LOG | cut -d '=' -f 2 | sed 's/["'\'']//'g)
	do
		sed -i -e "s,$pw,xxxxxx,g" $LOG
	done
	sync
}

function_exists()
{
	declare -f -F "$1" > /dev/null
	return $?
}

configure_target_os()
{
	memtotal=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
	if [ $memtotal -gt 16000000 ]; then
		sed -i -r -e "s/(net.netfilter.nf_conntrack_max).*/\1 = 1000000/" /usr/lib/sysctl.d/90-bluefield.conf
	fi

	# Password policy
	apt install -y libpam-pwquality
	sed -i -r -e "s/# minlen =.*/minlen = 12/" /etc/security/pwquality.conf
	sed -i -e '/use_authtok/ipassword\trequired\t\t\tpam_pwhistory.so  remember=3' /etc/pam.d/common-password
	sed -i -r -e "s/# silent/silent/;s/# deny.*/deny = 10/;s/# unlock_time.*/unlock_time = 600/" /etc/security/faillock.conf

	perl -ni -e 'print unless /PasswordAuthentication no/' /etc/ssh/sshd_config
	echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
	echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

	# Update HW-dependant files
	if (lspci -n -d 15b3: | grep -wq 'a2d2'); then
		# BlueField-1
		ln -snf snap_rpc_init_bf1.conf /etc/mlnx_snap/snap_rpc_init.conf
		# OOB interface does not exist on BlueField-1
		sed -i -e '/oob_net0/,+1d' /var/lib/cloud/seed/nocloud-net/network-config
	elif (lspci -n -d 15b3: | grep -wq 'a2d6'); then
		# BlueField-2
		ln -snf snap_rpc_init_bf2.conf /etc/mlnx_snap/snap_rpc_init.conf
	elif (lspci -n -d 15b3: | grep -wq 'a2dc'); then
		# BlueField-3
		apt remove -y --purge mlnx-snap || true
	fi

	pciid=$(echo $pciids | awk '{print $1}' | head -1)
	if [ -e /usr/sbin/mlnx_snap_check_emulation.sh ]; then
		sed -r -i -e "s@(NVME_SF_ECPF_DEV=).*@\1${pciid}@" /usr/sbin/mlnx_snap_check_emulation.sh
	fi

	case "${PSID}" in
		MT_0000000634)
		sed -r -i -e 's@(EXTRA_ARGS=).*@\1"--mem-size 1200"@' /etc/default/mlnx_snap
		;;
		MT_0000000667|MT_0000000698)
		/bin/systemctl disable lldpad.service
		/bin/systemctl disable lldpad.socket
		perl -ni -e "print unless /controller_nvme_namespace_attach/" /etc/mlnx_snap/snap_rpc_init_bf2.conf
		sed -r -i -e "s@(controller_nvme_create.*)@\1 -c /etc/mlnx_snap/mlnx_snap.json.example@" /etc/mlnx_snap/snap_rpc_init_bf2.conf
		sed -r -i -e 's@(CPU_MASK=).*@\10xff@' \
			      -e 's@.*RDMAV_FORK_SAFE=.*@RDMAV_FORK_SAFE=1@' \
			      -e 's@.*RDMAV_HUGEPAGES_SAFE=.*@RDMAV_HUGEPAGES_SAFE=1@' \
				  -e 's@.*NVME_FW_SUPP=.*@NVME_FW_SUPP=1@' \
				  -e 's@.*NVME_FW_UPDATE_PERSISTENT_LOCATION=.*@NVME_FW_UPDATE_PERSISTENT_LOCATION=/common@' \
				  /etc/default/mlnx_snap
		perl -ni -e "print unless /rpc_server/" /etc/mlnx_snap/mlnx_snap.json.example
		sed -i -e '/"ctrl": {/a\'$'\n''        "rpc_server": "/var/tmp/spdk.sock",' /etc/mlnx_snap/mlnx_snap.json.example
		sed -r -i -e 's@("max_namespaces":).*([a-zA-Z0-9]+)@\1 30@' \
				  -e 's@("quirks":).*([a-zA-Z0-9]+)@\1 0x8@' \
				  /etc/mlnx_snap/mlnx_snap.json.example
		sed -i -e "s/bdev_nvme_set_options.*/bdev_nvme_set_options --bdev-retry-count 10 --transport-retry-count 7 --transport-ack-timeout 0 --timeout-us 0 --timeout-admin-us 0 --action-on-timeout none --reconnect-delay-sec 10 --ctrlr-loss-timeout-sec -1 --fast-io-fail-timeout-sec 0/" /etc/mlnx_snap/spdk_rpc_init.conf

	cat >> /lib/udev/mlnx_bf_udev << EOF

# RoCE configuration
case "\$1" in
        p0|p1)
        mlnx_qos -i \$1 --trust dscp
        echo 106 > /sys/class/infiniband/mlx5_\${1/p/}/tc/1/traffic_class
        cma_roce_tos -d mlx5_\${1/p/} -t 106
        ;;
esac
EOF
		sed -i -e "s/dns=default/dns=none/" /etc/NetworkManager/conf.d/45-mlnx-dns.conf
		;;
	esac

	sed -i -r -e "s/^(MACAddressPolicy.*)/# \1/" /usr/lib/systemd/network/99-default.link

	# openibd to support MLNX_OFED drivers coming with Canonical's deb
	sed -i -e "s/FORCE_MODE=.*/FORCE_MODE=yes/" /etc/infiniband/openib.conf

	/bin/rm -f /etc/ssh/sshd_config.d/60-cloudimg-settings.conf
	/bin/rm -f /etc/default/grub.d/50-cloudimg-settings.cfg
	/bin/rm -f /etc/hostname

} # End of configure_target_os

configure_dhcp()
{
	ilog "Configure dhcp:"
	mkdir -p /etc/dhcp
	cat >> /etc/dhcp/dhclient.conf << EOF
send vendor-class-identifier "$DHCP_CLASS_ID_DP";
interface "oob_net0" {
  send vendor-class-identifier "$DHCP_CLASS_ID_OOB";
}
EOF

    cat >> /etc/dhcp/dhclient6.conf << EOF
option dhcp6.vendor-opts code 16 = string;
send dhcp6.vendor-opts $DHCP_CLASS_ID_DP_IPV6;

interface "oob_net0" {
  send dhcp6.vendor-opts $DHCP_CLASS_ID_OOB_IPV6;
}
EOF

if [[ "X$ENABLE_SFC_HBN" == "Xyes" || "X$ENABLE_BR_HBN" == "Xyes" ]]; then
    cat >> /etc/dhcp/dhclient.conf << EOF

interface "mgmt" {
  send vendor-class-identifier "$DHCP_CLASS_ID_OOB";
}
EOF
    cat >> /etc/dhcp/dhclient6.conf << EOF
interface "mgmt" {
  send dhcp6.vendor-opts $DHCP_CLASS_ID_OOB_IPV6;
}
EOF
fi

if [ -e /etc/dhcpcd.conf ]; then
	if ! (grep -q "^noipv4ll" /etc/dhcpcd.conf); then
		cat >> /etc/dhcpcd.conf << EOF

# Disable IPv4 Link-Local
noipv4ll
EOF
	fi
fi
}

update_efi_bootmgr()
{
	ilog "Adding $distro boot entry:"
	efivars_mount=0
	if [ ! -d /sys/firmware/efi/efivars ]; then
		mount -t efivarfs none /sys/firmware/efi/efivars
		efivars_mount=1
	fi

	UBUNTU_CODENAME=$(grep ^ID= /etc/os-release | cut -d '=' -f 2)
	NEXT_OS_IMAGE=0

	if efibootmgr | grep ${UBUNTU_CODENAME}; then
		efibootmgr -b "$(efibootmgr | grep ${UBUNTU_CODENAME} | cut -c 5-8)" -B > /dev/null 2>&1
	fi
	ilog "$(efibootmgr -c -d $device -p $((1 + 2*$NEXT_OS_IMAGE)) -L ${UBUNTU_CODENAME}${NEXT_OS_IMAGE} -l '\EFI\ubuntu\shimaa64.efi')"

	if ! (efibootmgr | grep ${UBUNTU_CODENAME}); then
		log "ERROR: Failed to add ${UBUNTU_CODENAME}${NEXT_OS_IMAGE} boot entry. Retrying..."
		ilog "efibootmgr -c -d $device -p $((1 + 2*$NEXT_OS_IMAGE)) -L ${UBUNTU_CODENAME}${NEXT_OS_IMAGE} -l '\EFI\ubuntu\shimaa64.efi'"
		if ! (efibootmgr | grep ${UBUNTU_CODENAME}); then
			bfbootmgr --cleanall > /dev/null 2>&1
			efibootmgr -c -d "$device" -p $((1 + 2*$NEXT_OS_IMAGE)) -L ${UBUNTU_CODENAME}${NEXT_OS_IMAGE} -l "\EFI\ubuntu\shimaa64.efi" > /dev/null 2>&1
			if ! (efibootmgr | grep ${UBUNTU_CODENAME}); then
				log "ERROR: Failed to add ${UBUNTU_CODENAME}${NEXT_OS_IMAGE} boot entry."
			fi
		fi
	fi

	if [ $efivars_mount -eq 1 ]; then
		umount /sys/firmware/efi/efivars
	fi
}

configure_services()
{
	ilog "$(/bin/systemctl enable serial-getty@ttyAMA0.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl enable serial-getty@ttyAMA1.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl enable serial-getty@hvc0.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl disable mlx-regex.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl enable NetworkManager.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl enable NetworkManager-wait-online.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl enable networking.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl enable mlnx_snap.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl enable acpid.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl enable mlx-openipmi.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl enable mlx_ipmid.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl enable set_emu_param.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl enable bfvcheck.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl enable bfup.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl disable openvswitch-ipsec > /dev/null 2>&1)"
	ilog "$(/bin/systemctl disable srp_daemon.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl disable ibacm.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl disable opensmd.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl disable unattended-upgrades.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl disable apt-daily-upgrade.timer > /dev/null 2>&1)"
	ilog "$(/bin/systemctl disable docker.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl disable docker.socket > /dev/null 2>&1)"
	ilog "$(/bin/systemctl disable kubelet.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl disable containerd.service > /dev/null 2>&1)"
	ilog "$(/bin/systemctl disable ModemManager.service > /dev/null 2>&1)"
}

enable_sfc_hbn()
{
	ilog "Enable SFC HBN"
	ARG_PORT0=""
	ARG_PORT1=""
	# initial sfc parameters
	if ! [ -z "${NUM_VFs_PHYS_PORT0}" ]; then
		ARG_PORT0="--ecpf0 "${NUM_VFs_PHYS_PORT0}
	fi
	if ! [ -z "${NUM_VFs_PHYS_PORT1}" ]; then
		ARG_PORT1="--ecpf1 "${NUM_VFs_PHYS_PORT1}
	fi
	# configurable sf/vf mapping
	HBN_UPLINKS=${HBN_UPLINKS:-"p0,p1"}
	HBN_REPS=${HBN_REPS:-"pf0hpf,pf1hpf,pf0vf0-pf0vf13"}
	HBN_DPU_SFS=${HBN_DPU_SFS:-"pf0dpu1,pf0dpu3"}
	# generic steering bridge mapping
	if ! [ -z "${BR_HBN_UPLINKS-x}" ]; then
		BR_HBN_UPLINKS=${BR_HBN_UPLINKS:-"$HBN_UPLINKS"}
	fi
	if ! [ -z "${BR_HBN_REPS-x}" ]; then
		BR_HBN_REPS=${BR_HBN_REPS:-"$HBN_REPS"}
	fi
	if ! [ -z "${BR_HBN_SFS-x}" ]; then
		BR_HBN_SFS=${BR_HBN_SFS:-"$HBN_DPU_SFS"}
	fi
	BR_SFC_UPLINKS=${BR_SFC_UPLINKS:-""}
	BR_SFC_REPS=${BR_SFC_REPS:-""}
	BR_SFC_SFS=${BR_SFC_SFS:-""}
	BR_HBN_SFC_PATCH_PORTS=${BR_HBN_SFC_PATCH_PORTS:-""}
	LINK_PROPAGATION=${LINK_PROPAGATION:-""}
	ENABLE_BR_SFC=${ENABLE_BR_SFC:-""}
	ENABLE_BR_SFC_DEFAULT_FLOWS=${ENABLE_BR_SFC_DEFAULT_FLOWS:-""}

        # configurable sf/vf mapping
	HUGEPAGE_SIZE=${HUGEPAGE_SIZE:-2048}
	HUGEPAGE_COUNT=${HUGEPAGE_COUNT:-3072}
	CLOUD_OPTION=${CLOUD_OPTION:-""}
	log "INFO: Installing SFC HBN environment"
	ilog "$(BR_HBN_UPLINKS=${BR_HBN_UPLINKS} BR_HBN_REPS=${BR_HBN_REPS} BR_HBN_SFS=${BR_HBN_SFS} BR_SFC_UPLINKS=${BR_SFC_UPLINKS} BR_SFC_REPS=${BR_SFC_REPS} BR_SFC_SFS=${BR_SFC_SFS} BR_HBN_SFC_PATCH_PORTS=${BR_HBN_SFC_PATCH_PORTS} LINK_PROPAGATION=${LINK_PROPAGATION} ENABLE_BR_SFC=${ENABLE_BR_SFC} ENABLE_BR_SFC_DEFAULT_FLOWS=${ENABLE_BR_SFC_DEFAULT_FLOWS} HUGEPAGE_SIZE=${HUGEPAGE_SIZE} HUGEPAGE_COUNT=${HUGEPAGE_COUNT} CLOUD_OPTION=${CLOUD_OPTION} /opt/mellanox/sfc-hbn/install.sh ${ARG_PORT0} ${ARG_PORT1} 2>&1)"
	NIC_FW_RESET_REQUIRED=1
}

create_initramfs()
{
	kver=$(uname -r)
	if [ ! -d /lib/modules/$kver ]; then
		kver=$(/bin/ls -1 /lib/modules/ | tail -1)
	fi

	ilog "Updating $distro initramfs"
	initrd=$(cd /boot; /bin/ls -1 initrd.img-* | tail -1 | sed -e "s/.old-dkms//")
	ilog "$(dracut --force --add-drivers "mlxbf-bootctl sdhci-of-dwcmshc mlxbf-tmfifo dw_mmc-bluefield mlx5_core mlx5_ib mlxfw ib_umad nvme sbsa_gwdt gpio-mlxbf2 gpio-mlxbf3 mlxbf-gige pinctrl-mlxbf3 8021q" --gzip /boot/$initrd ${kver} 2>&1)"
}

configure_grub()
{
	ilog "Configure grub:"
	if [ -n "${grub_admin_PASSWORD}" ]; then
		sed -i -r -e "s/(password_pbkdf2 admin).*/\1 ${grub_admin_PASSWORD}/" /etc/grub.d/40_custom
	fi

	if (grep -q MLNXBF33 /sys/firmware/acpi/tables/SSDT*); then
		# BlueField-3
		sed -i -e "s/0x01000000/0x13010000/g" /etc/default/grub
	fi

	if (lspci -vv | grep -wq SimX); then
		# Remove earlycon from grub parameters on SimX
		sed -i -r -e 's/earlycon=[^ ]* //g' /etc/default/grub
	fi

	# Grub password
	echo 'set superusers="admin"' >> /etc/grub.d/40_custom; \
	echo 'password_pbkdf2 admin grub.pbkdf2.sha512.10000.5EB1FF92FDD89BDAF3395174282C77430656A6DBEC1F9289D5F5DAD17811AD0E2196D0E49B49EF31C21972669D180713E265BB2D1D4452B2EA9C7413C3471C53.F533423479EE7465785CC2C79B637BDF77004B5CC16C1DDE806BCEA50BF411DE04DFCCE42279E2E1F605459F1ABA3A0928CE9271F2C84E7FE7BF575DC22935B1' >> /etc/grub.d/40_custom
	sed -i -e "s@'gnulinux-simple-\$boot_device_id'@'gnulinux-simple-\$boot_device_id' --unrestricted@" \
	       -e "s@'gnulinux-\$version-\$type-\$boot_device_id'@'gnulinux-\$version-\$type-\$boot_device_id' --users ''@" /etc/grub.d/10_linux

	ilog "Creating GRUB configuration"
	ilog "$(/usr/sbin/grub-install ${device})"
	ilog "$(/usr/sbin/grub-mkconfig -o /boot/grub/grub.cfg)"
	ilog "$(/usr/sbin/grub-set-default 0)"
}

set_root_password()
{
	if [ -n "${ubuntu_PASSWORD}" ]; then
		log "INFO: Changing the default password for user ubuntu"
		perl -ni -e "if(/^users:/../^runcmd/) {
						next unless m{^runcmd};
		print q@users:
  - name: ubuntu
    lock_passwd: False
    groups: adm, audio, cdrom, dialout, dip, floppy, lxd, netdev, plugdev, sudo, video
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    passwd: $ubuntu_PASSWORD
@;
		print } else {print}" /var/lib/cloud/seed/nocloud-net/user-data
	else
		perl -ni -e "print unless /plain_text_passwd/" /var/lib/cloud/seed/nocloud-net/user-data
	fi
}

update_atf_uefi()
{
	if function_exists pre_update_atf_uefi; then
		log "INFO: Running pre_update_atf_uefi from bf.cfg"
		pre_update_atf_uefi
	fi

	UPDATE_BOOT=${UPDATE_BOOT:-1}
	if [ $UPDATE_BOOT -eq 1 ]; then
		ilog "Updating ATF/UEFI:"
		ilog "$(bfrec --bootctl || true)"
		if [ -e /lib/firmware/mellanox/boot/capsule/boot_update2.cap ]; then
			ilog "$(bfrec --capsule /lib/firmware/mellanox/boot/capsule/boot_update2.cap)"
		fi

		if [ -e /lib/firmware/mellanox/boot/capsule/efi_sbkeysync.cap ]; then
			ilog "$(bfrec --capsule /lib/firmware/mellanox/boot/capsule/efi_sbkeysync.cap)"
		fi
		umount /efi_system_partition
	fi

	if function_exists post_update_atf_uefi; then
		log "INFO: Running post_update_atf_uefi from bf.cfg"
		post_update_atf_uefi
	fi
}

running_nic_fw()
{
	$FLINT -d $flint_dev q 2>&1 | grep -w 'FW Version:' | awk '{print $NF}'
}

provided_nic_fw()
{
	${FW_DIR}/mlxfwmanager_sriov_dis_aarch64_${cx_dev_id} --list 2> /dev/null | grep -w "${PSID}" | awk '{print $4}'
}

fw_update()
{
	if [[ -x ${FW_UPDATER} && -d ${FW_DIR} ]]; then
		NIC_FW_FOUND=1
	fi

	if [ $NIC_FW_FOUND -eq 1 ]; then
		if [ "$(running_nic_fw)" == "$(provided_nic_fw)" ]; then
			if [ "${FORCE_NIC_FW_UPDATE}" == "yes" ]; then
				log "INFO: Installed NIC Firmware is the same as provided. FORCE_NIC_FW_UPDATE is set."
			else
				log "INFO: Installed NIC Firmware is the same as provided. Skipping NIC Firmware update."
				return
			fi
		fi

		log "INFO: Updating NIC firmware..."
		${FW_UPDATER} --log /tmp/mlnx_fw_update.log -v \
			--force-fw-update \
			--fw-dir ${FW_DIR} > /tmp/mlnx_fw_update.out 2>&1
		rc=$?
		sync
		if [ -e /tmp/mlnx_fw_update.out ]; then
			cat /tmp/mlnx_fw_update.out > /dev/hvc0
			cat /tmp/mlnx_fw_update.out > /dev/ttyAMA0
			cat /tmp/mlnx_fw_update.out >> $LOG
		fi
		if [ -e /tmp/mlnx_fw_update.log ]; then
			cat /tmp/mlnx_fw_update.log > /dev/hvc0
			cat /tmp/mlnx_fw_update.log > /dev/ttyAMA0
			cat /tmp/mlnx_fw_update.log >> $LOG
		fi
		if [ $rc -ne 0 ] || (grep -q '\-E- Failed' /tmp/mlnx_fw_update.log); then
			NIC_FW_UPDATE_PASSED=0
			log "INFO: NIC firmware update failed"
		else
			NIC_FW_UPDATE_PASSED=1
			log "INFO: NIC firmware update done: $(provided_nic_fw)"
		fi
		NIC_FW_UPDATE_DONE=1
	else
		log "WARNING: NIC Firmware files were not found"
	fi
}

fw_reset()
{
	/sbin/modprobe -a mlx5_core ib_umad

	MLXFWRESET_TIMEOUT=${MLXFWRESET_TIMEOUT:-180}
	SECONDS=0
	while ! (mlxfwreset -d /dev/mst/mt*_pciconf0 q 2>&1 | grep -w "Driver is the owner" | grep -qw "\-Supported")
	do
		if [ $SECONDS -gt $MLXFWRESET_TIMEOUT ]; then
			log "INFO: NIC Firmware reset is not supported. Host power cycle is required"
			return
		fi
		sleep 1
	done

	log "INFO: Running NIC Firmware reset"
	# Wait for these messages to be pulled by the rshim service
	# as mlxfwreset will restart the DPU
	sleep 3

	msg=$(mlxfwreset -d /dev/mst/mt*_pciconf0 -y -l 3 --sync 1 r 2>&1)
	if [ $? -ne 0 ]; then
		log "INFO: NIC Firmware reset failed"
		log "INFO: $msg"
	else
		log "INFO: NIC Firmware reset done"
	fi
}

update_nic_firmware()
{
	if [ $NIC_FW_UPDATE_DONE -eq 0 ]; then
		fw_update
	fi
}

reset_nic_firmware()
{
	if [ $NIC_FW_UPDATE_DONE -eq 1 ]; then
		if [ $NIC_FW_UPDATE_PASSED -eq 1 ]; then
			# Reset NIC FW
			fw_reset
		fi
	fi
}

configure_sfs()
{
	: > /etc/mellanox/mlnx-sf.conf

	for pciid in $(lspci -nD 2> /dev/null | grep 15b3:a2d[26c] | awk '{print $1}')
	do
		cat >> /etc/mellanox/mlnx-sf.conf << EOF
/sbin/mlnx-sf --action create --device $pciid --sfnum 0 --hwaddr $(uuidgen | sed -e 's/-//;s/^\(..\)\(..\)\(..\)\(..\)\(..\).*$/02:\1:\2:\3:\4:\5/')
EOF
	done
}

update_uefi_boot_entries()
{
	ilog "Updating EFI boot entries:"
	efivars_mount=0
	if [ ! -d /sys/firmware/efi/efivars ]; then
		mount -t efivarfs none /sys/firmware/efi/efivars
		efivars_mount=1
	fi

	ilog "Remove old boot entries"
	ilog "$(bfbootmgr --cleanall 2>&1)"
	/bin/rm -f /sys/firmware/efi/efivars/Boot* > /dev/null 2>&1
	/bin/rm -f /sys/firmware/efi/efivars/dump-* > /dev/null 2>&1

	BFCFG=$(which bfcfg 2> /dev/null)
if [ -n "$BFCFG" ]; then
	# Create PXE boot entries
	if [ -e /etc/bf.cfg ]; then
		mv /etc/bf.cfg /etc/bf.cfg.orig
	fi

	cat > /etc/bf.cfg << EOF
BOOT0=DISK
BOOT1=NET-NIC_P0-IPV4
BOOT2=NET-NIC_P0-IPV6
BOOT3=NET-NIC_P1-IPV4
BOOT4=NET-NIC_P1-IPV6
BOOT5=NET-OOB-IPV4
BOOT6=NET-OOB-IPV6
BOOT7=NET-NIC_P0-IPV4-HTTP
BOOT8=NET-NIC_P1-IPV4-HTTP
BOOT9=NET-OOB-IPV4-HTTP
PXE_DHCP_CLASS_ID=$DHCP_CLASS_ID
EOF

	$BFCFG
	rc=$?
	if [ $rc -ne 0 ]; then
		if (grep -q "boot: failed to get MAC" /tmp/bfcfg.log > /dev/null 2>&1); then
			err_msg="Failed to add PXE boot entries"
		fi
	fi

	RC=$((RC+rc))
	cat >> $LOG << EOF

### Adding PXE boot entries: ###
$(cat /etc/bf.cfg)
### bfcfg LOG: ###
$(cat /tmp/bfcfg.log)
### bfcfg log End ###
EOF
	# Restore the original bf.cfg
	/bin/rm -f /etc/bf.cfg
	if [ -e /etc/bf.cfg.orig ]; then
		grep -v PXE_DHCP_CLASS_ID= /etc/bf.cfg.orig > /etc/bf.cfg
	fi
fi

	if [[ -n "$BFCFG" && -e /etc/bf.cfg ]]; then
		$BFCFG
		rc=$?
		if [ $rc -ne 0 ]; then
			if (grep -q "boot: failed to get MAC" /tmp/bfcfg.log > /dev/null 2>&1); then
				err_msg="Failed to add PXE boot entries"
			fi
		fi

		RC=$((RC+rc))
		cat >> $LOG << EOF

### Applying original bf.cfg: ###
$(cat /etc/bf.cfg)
### bfcfg LOG: ###
$(cat /tmp/bfcfg.log)
### bfcfg log End ###
EOF
	fi

	if [ $efivars_mount -eq 1 ]; then
		umount /sys/firmware/efi/efivars
	fi
}

BMC_IP=${BMC_IP:-"192.168.240.1"}
BMC_PORT=${BMC_PORT:-"443"}
BMC_USER=${BMC_USER:-"root"}
DEFAULT_BMC_PASSWORD="0penBmc"
TMP_BMC_PASSWORD="Nvidia_12345!"
RESET_BMC_PASSWORD=0
BMC_PASSWORD=${BMC_PASSWORD:-""}
BMC_SSH_USER=${BMC_SSH_USER:-"$BMC_USER"}
BMC_SSH_PASSWORD=${BMC_SSH_PASSWORD:-"$BMC_PASSWORD"}
NEW_BMC_PASSWORD=${NEW_BMC_PASSWORD:-""}
UEFI_PASSWORD=${UEFI_PASSWORD:-""}
NEW_UEFI_PASSWORD=${NEW_UEFI_PASSWORD:-""}
OOB_IP=${OOB_IP:-"192.168.240.2"}
OOB_NETPREFIX=${OOB_NETPREFIX:-"29"}
BMC_IP_TIMEOUT=${BMC_IP_TIMEOUT:-600}
BMC_TASK_TIMEOUT=${BMC_TASK_TIMEOUT:-"1800"}
UPDATE_BMC_FW=${UPDATE_BMC_FW:-"yes"}
BMC_REBOOT=${BMC_REBOOT:-"no"}
CEC_REBOOT=${CEC_REBOOT:-"no"}
FIELD_MODE_SET=0
UPDATE_CEC_FW=${UPDATE_CEC_FW:-"yes"}
BMC_INSTALLED_VERSION=""
BMC_MIN_MULTIPART_VERSION="24.04"
CEC_MIN_RESET_VERSION="00.02.0180.0000"
UPDATE_DPU_GOLDEN_IMAGE=${UPDATE_DPU_GOLDEN_IMAGE:-"yes"}
UPDATE_NIC_FW_GOLDEN_IMAGE=${UPDATE_NIC_FW_GOLDEN_IMAGE:-"yes"}
bmc_pref=""
if (lspci -n -d 15b3: | grep -wq 'a2dc'); then
	bmc_pref="bf3"
	cec_sfx="fwpkg"
	if [ -d /BF3BMC ]; then
		NIC_FW_GI_PATH=${NIC_FW_GI_PATH:-"/BF3BMC/golden_images/fw"}
		DPU_GI_PATH=${DPU_GI_PATH:-"/BF3BMC/golden_images/dpu"}
		BMC_PATH=${BMC_PATH:-"/BF3BMC/bmc"}
		CEC_PATH=${CEC_PATH:-"/BF3BMC/cec"}
	else
		NIC_FW_GI_PATH=${NIC_FW_GI_PATH:-"/lib/firmware/mellanox/bmc"}
		DPU_GI_PATH=${DPU_GI_PATH:-"/lib/firmware/mellanox/bmc"}
		BMC_PATH=${BMC_PATH:-"/lib/firmware/mellanox/bmc"}
		CEC_PATH=${CEC_PATH:-"/lib/firmware/mellanox/cec"}
	fi
elif (lspci -n -d 15b3: | grep -wq 'a2d6'); then
	bmc_pref="bf2"
	# BF2 does not support Golden Images
	UPDATE_DPU_GOLDEN_IMAGE="no"
	UPDATE_NIC_FW_GOLDEN_IMAGE="no"
	if [ -d /BF2BMC ]; then
		cec_sfx="bin"
		BMC_PATH=${BMC_PATH:-"/BF2BMC/bmc"}
		CEC_PATH=${CEC_PATH:-"/BF2BMC/cec"}
	else
		BMC_PATH=${BMC_PATH:-"/lib/firmware/mellanox/bmc"}
		CEC_PATH=${CEC_PATH:-"/lib/firmware/mellanox/cec"}
	fi
fi

FORCE_BMC_FW_INSTALL=${FORCE_BMC_FW_INSTALL:-"no"}
FORCE_CEC_INSTALL=${FORCE_CEC_INSTALL:-"no"}

export NIC_FW_GI_PATH
export DPU_GI_PATH
export BMC_PATH
export CEC_PATH

BMC_CREDENTIALS="'{\"username\":\"$BMC_USER\", \"password\":\"${BMC_PASSWORD}\"}'"
BMC_LINK_UP="no"
BMC_FIRMWARE_UPDATED="no"
export BMC_TOKEN=""
export task_id=""
export task_state=""
export task_status=""

SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
SCP="scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

skip_bmc()
{
	log "WARN Skipping BMC components upgrade."
	RC=$((RC+1))
	UPDATE_BMC_FW="no"
	UPDATE_CEC_FW="no"
	UPDATE_DPU_GOLDEN_IMAGE="no"
	UPDATE_NIC_FW_GOLDEN_IMAGE="no"
}

wait_for_bmc_ip()
{
    SECONDS=0
    while ! (ping -c 3 $BMC_IP > /dev/null 2>&1)
    do
        sleep 10
        if [ $SECONDS -gt $BMC_IP_TIMEOUT ]; then
            if ! (ping -c 3 $BMC_IP > /dev/null 2>&1); then
                rlog "ERR Failed to access BMC"
                ilog "- ERROR: Failed to access $BMC_IP after $SECONDS sec."
                RC=$((RC+1))
            fi
        fi
    done
    sleep 60
}

create_vlan()
{
	if [ "$BMC_LINK_UP" == "yes" ]; then
		return
	fi

	if [ "$(get_field_mode)" == "01" ]; then
		set_field_mode '00'
		FIELD_MODE_SET=1
		bmc_reboot_from_dpu
	fi

	ilog "Creating VLAN 4040"
	if [ ! -d "/sys/bus/platform/drivers/mlxbf_gige" ]; then
		ilog "- ERROR: mlxbf_gige driver is not loaded"
		RC=$((RC+1))
		return
	fi
	OOB_IF=$(ls -1 "/sys/bus/platform/drivers/mlxbf_gige/MLNXBF17:00/net")
	ilog "Configuring VLAN id 4040 on ${OOB_IF}. This operation may take up to $BMC_IP_TIMEOUT seconds"
	SECONDS=0
	while ! ip link show vlan4040 2> /dev/null | grep -w '<BROADCAST,MULTICAST,UP,LOWER_UP>'; do
		if [ $SECONDS -gt $BMC_IP_TIMEOUT ]; then
			rlog "ERR Failed to create VLAN."
			ilog "- ERROR: Failed to create VLAN interface after $SECONDS sec. All the BMC related operations will be skipped."
			skip_bmc
			return
		fi
		ip link add link ${OOB_IF} name vlan4040 type vlan id 4040
		output=$(dhclient vlan4040 2>&1)
		rc=$?
		ilog "$output"
		if [ $rc -ne 0 ]; then
			ilog "dhclient failed"
			ilog "Configuring static IP: ${OOB_IP}/${OOB_NETPREFIX} for vlan4040"
			ip addr add ${OOB_IP}/${OOB_NETPREFIX} brd + dev vlan4040
		fi
		ip link set dev ${OOB_IF} up
		ip link set dev vlan4040 up
		sleep 1
	done
	while ! ping -c 3 $BMC_IP; do
		if [ $SECONDS -gt $BMC_IP_TIMEOUT ]; then
			rlog "ERR Failed to access BMC"
			ilog "- ERROR: Failed to access $BMC_IP after $SECONDS sec."
			skip_bmc
			return
		fi
		sleep 1
	done
	ilog "$(ip link show vlan4040)"
	BMC_LINK_UP="yes"
}

prepare_sshpass_environment()
{
        if [ ! -f /dev/pts/ptmx ]; then
                echo "none  /dev/pts  devpts  defaults 0 0" >> /etc/fstab
                mount /dev/pts
        fi
        if [ ! -f /etc/passwd ]; then
                echo "root:x:0:0:root:/root:/bin/bash" >> /etc/passwd
        fi
}

get_field_mode()
{
    mode=$(ipmitool raw 0x32 0x68 2> /dev/null | tr -d ' ')
    return $mode
}

set_field_mode()
{
    hvalue=$1

    ilog "Setting Field Mode to $hvalue"
    ilog "$(ipmitool raw 0x32 0x67 ${hvalue} 2>&1)"
}

get_bmc_token()
{
	cmd=$(echo curl -sSk -H \"Content-Type: application/json\" -X POST https://${BMC_IP}/login -d $BMC_CREDENTIALS)
	BMC_TOKEN=$(eval $cmd | jq -r ' .token')
	if [[ -z "$BMC_TOKEN" || "$BMC_TOKEN" == "null" ]]; then
		rlog "ERR Failed to get BMC token. Check BMC user/password"
		ilog "- ERROR: Failed to get BMC token using command: $cmd. Check BMC user/password."
		RC=$((RC+1))
		return 1
	fi
	return 0
}

change_uefi_password()
{
	UEFI_CREDENTIALS="'{\"Attributes\":{\"CurrentUefiPassword\":\"$UEFI_PASSWORD\",\"UefiPassword\":\"${NEW_UEFI_PASSWORD}\"}}'"
	cmd=$(echo curl -sSk -u $BMC_USER:"$BMC_PASSWORD" -H \"Content-Type: application/json\" -X PATCH https://${BMC_IP}/redfish/v1/Systems/Bluefield/Bios/Settings -d $UEFI_CREDENTIALS)
	ilog "Command: $cmd"
	output=$(eval $cmd)
	status=$(echo $output | jq '."@Message.ExtendedInfo"[0].Message')
	if [ "$status" != "\"The request completed successfully."\" ]; then
		rlog "ERR Failed to change UEFI password."
		ilog "Failed to change UEFI password. Output: $output"
		return 1
	fi

	ilog "UEFI password is set for the update. The new password will be activated on the second DPU reboot."

	return 0
}

change_bmc_password()
{
	current_password="$1"
	new_password="$2"

	NEW_BMC_CREDENTIALS="'{\"Password\":\"${new_password}\"}'"
	cmd=$(echo curl -sSk -u $BMC_USER:$current_password  -H \"Content-Type: application/json\" -X PATCH https://${BMC_IP}/redfish/v1/AccountService/Accounts/$BMC_USER -d $NEW_BMC_CREDENTIALS)
	output=$(eval $cmd)
	status=$(echo $output | jq '."@Message.ExtendedInfo"[0].Message')
	if [ "$status" != "\"The request completed successfully."\" ]; then
		rlog "ERR Failed to change BMC $BMC_USER password."
		ilog "Failed to change the password. Output: $output"
		return 1
	fi

	ilog "BMC password updated successfully."

	return 0
}

get_bmc_public_key()
{
		get_bmc_token
        SSH_PUBLIC_KEY=$(ssh-keyscan -t ed25519 ${OOB_IP} 2>&1 | tail -1 | cut -d ' ' -f 2-)

        pk_cmd=$(echo curl -sSk -H \"X-Auth-Token: $BMC_TOKEN\" -H \"Content-Type: application/json\" -X POST -d \'{\"RemoteServerIP\":\"${BMC_IP}\", \"RemoteServerKeyString\":\"$SSH_PUBLIC_KEY\"}\' https://$BMC_IP/redfish/v1/UpdateService/Actions/Oem/NvidiaUpdateService.PublicKeyExchange)
        bmc_pk=$(eval $pk_cmd | jq -r ' .Resolution')
		if [ "$bmc_pk" != "null" ]; then
			echo "$bmc_pk" >> /root/.ssh/authorized_keys
		fi
}

bmc_get_task_id()
{
	get_bmc_token
	task_id=$(curl -sSk -H "X-Auth-Token: $BMC_TOKEN" -X GET https://${BMC_IP}/redfish/v1/TaskService/Tasks | jq -r ' .Members' | grep odata.id | tail -1 | awk '{print $NF}' | tr -d '"')
	ilog "Task id: $task_id"
}

wait_bmc_task_complete()
{
	copy_status=$(curl -sSk -u $BMC_USER:$BMC_PASSWORD -X GET https://${BMC_IP}/redfish/v1/Chassis/Bluefield_ERoT | jq -r ' .Oem.Nvidia.BackgroundCopyStatus')
	if [ "X$copy_status" != "Xnull" ]; then
		if [ "$copy_status" != "Completed" ]; then
			ilog "BMC background copy is: $copy_status"
		fi

		SECONDS=0
		while [ "$copy_status" != "Completed" ]
		do
			if [ $SECONDS -gt $BMC_TASK_TIMEOUT ]; then
				ilog "- ERROR: BMC copy task timeout"
				RC=$((RC+1))
				break
			fi
			sleep 10
			copy_status=$(curl -sSk -u $BMC_USER:$BMC_PASSWORD -X GET https://${BMC_IP}/redfish/v1/Chassis/Bluefield_ERoT | jq -r ' .Oem.Nvidia.BackgroundCopyStatus')
		done
	fi

	bmc_get_task_id
	if [ -z "${task_id}" ]; then
		ilog "No active BMC task"
		return
	fi
	output=$(mktemp)
	#Check upgrade progress (%).
	get_bmc_token
	curl -sSk -H "X-Auth-Token: $BMC_TOKEN" https://${BMC_IP}${task_id} > $output
	percent_done=$(cat $output | jq -r ' .PercentComplete')
	SECONDS=0
	while [ "$percent_done" != "100" ]; do
		if [ "$percent_done" == "null" ]; then
			ilog "- ERROR: There is no task with task id: $task_id"
			RC=$((RC+1))
			break
		fi
		if [ $SECONDS -gt $BMC_TASK_TIMEOUT ]; then
			ilog "- ERROR: BMC task $task_id timeout"
			RC=$((RC+1))
			break
		fi
		get_bmc_token
		curl -sSk -H "X-Auth-Token: $BMC_TOKEN" https://${BMC_IP}${task_id} > $output
		percent_done=$(cat $output | jq -r ' .PercentComplete')
		task_state=$(cat $output | jq -r ' .TaskState')
		if [ "$task_state" == "Exception" ]; then
			ilog "- ERROR: BMC task $task_id exception"
			RC=$((RC+1))
			break
		fi
		sleep 10
	done
	task_state=$(jq '.TaskState' $output | tr -d '"')
	task_status=$(jq '.TaskStatus' $output | tr -d '"')

	if [ "$task_state$task_status" != "CompletedOK" ]; then
		echo "BMC task failed:"  >> $LOG
		cat $output >> $LOG
		RC=$((RC+1))
	fi
	/bin/rm -f $output
}

update_bmc_fw()
{
	wait_bmc_task_complete
	log "Updating BMC firmware"
	image=$(/bin/ls -1 {/mnt,/}${BMC_PATH}/${bmc_pref}*bmc*{fwpkg,tar} 2> /dev/null | grep -v preboot | tail -1)
	if [ -z "$image" ]; then
		ilog "- ERROR: Cannot find BMC firmware image"
		RC=$((RC+1))
		return
	fi
	ilog "Found BMC firmware image: $image"

	BMC_IMAGE_VERSION=$(cat {/mnt,/}${BMC_PATH}/${bmc_pref}-bmc-fw.version 2> /dev/null | head -1)
	if [ -z "$BMC_IMAGE_VERSION" ]; then
		if [[ "$image" =~ tar ]]; then
			# BlueField-2
			BMC_IMAGE_VERSION="$(strings -a -t d $image | grep -m 1 ExtendedVersion | cut -d '-' -f 2,3)"
		else
			BMC_IMAGE_VERSION="$(strings -a -t d $image | grep -m 1 BF- | cut -d '-' -f 2- | sed -e 's/ //g')"
		fi
	fi
	if [ -z "$BMC_IMAGE_VERSION" ]; then
		ilog "- ERROR: Cannot detect included BMC firmware version"
		RC=$((RC+1))
		return
	fi
	ilog "Provided BMC firmware version: $BMC_IMAGE_VERSION"

	get_bmc_token

	BMC_FIRMWARE_URL=$(curl -sSk -H "X-Auth-Token: $BMC_TOKEN" -X GET https://${BMC_IP}/redfish/v1/UpdateService/FirmwareInventory | grep BMC_Firmware | awk '{print $NF}' | tr -d \")
	ilog "- INFO: BMC_FIRMWARE_URL: $BMC_FIRMWARE_URL"
	BMC_INSTALLED_VERSION="$(curl -sSk -H "X-Auth-Token: $BMC_TOKEN" -X GET https://${BMC_IP}${BMC_FIRMWARE_URL} | jq -r ' .Version' | grep -o "\([0-9]\+\).\([0-9]\+\)-\([0-9]\+\)")"
	if [ -z "$BMC_INSTALLED_VERSION" ]; then
		ilog "- ERROR: Cannot detect running BMC firmware version"
		RC=$((RC+1))
		return
	fi
	ilog "Running BMC firmware version: $BMC_INSTALLED_VERSION"

	if [ "${BMC_IMAGE_VERSION}" == "${BMC_INSTALLED_VERSION}" ]; then
		if [ "X${FORCE_BMC_FW_INSTALL}" == "Xyes" ]; then
			ilog "Installed BMC version is the same as provided. FORCE_BMC_FW_INSTALL is set."
		else
			ilog "Installed BMC version is the same as provided. Skipping BMC firmware update."
			return
		fi
	fi

	ilog "Proceeding with the BMC firmware update."

	if [[ $(echo -e "${BMC_MIN_MULTIPART_VERSION}\n${BMC_INSTALLED_VERSION}" | sort -V | head -n1) == "${BMC_MIN_MULTIPART_VERSION}" ]]; then
		ilog "curl -sSk -u <BMC_USER:BMC_PASSWORD> https://${BMC_IP}/redfish/v1/UpdateService/update-multipart -F 'UpdateParameters={\"ForceUpdate\":true};type=application/octet-stream' -F UpdateFile=@${image}"
		output=$(curl -sSk -u $BMC_USER:$BMC_PASSWORD https://${BMC_IP}/redfish/v1/UpdateService/update-multipart -F 'UpdateParameters={"ForceUpdate":true};type=application/octet-stream' -F UpdateFile=@${image} 2>&1)
	else
		ilog "curl -sSk -u <BMC_USER:BMC_PASSWORD> -H "Content-Type: application/octet-stream" -X POST -T ${image} https://${BMC_IP}/redfish/v1/UpdateService"
		output=$(curl -sSk -u $BMC_USER:$BMC_PASSWORD -H "Content-Type: application/octet-stream" -X POST -T ${image} https://${BMC_IP}/redfish/v1/UpdateService 2>&1)
	fi
	ilog "BMC Firmware update: $output"

	BMC_FIRMWARE_UPDATED="yes"

	wait_bmc_task_complete
	if [ "$BMC_REBOOT" != "yes" ]; then
		log "INFO: BMC firmware was updated to: ${BMC_IMAGE_VERSION}. BMC restart is required."
	fi

	BMC_UPGRADE_RESET=1 bfcfg -f /dev/null
}

update_cec_fw()
{
	wait_bmc_task_complete
	log "Updating CEC firmware"
	image=$(/bin/ls -1 {/mnt,/}${CEC_PATH}/${bmc_pref}*cec*${cec_sfx} 2> /dev/null | tail -1)

	if [ -z "$image" ]; then
		ilog "- ERROR: Cannot find CEC firmware image"
		RC=$((RC+1))
		return
	fi
	ilog "Found CEC firmware image: $image"

	CEC_IMAGE_VERSION=$(cat {/mnt,/}${CEC_PATH}/${bmc_pref}-cec-fw.version 2> /dev/null | head -1)
	if [ -z "$CEC_IMAGE_VERSION" ]; then
		CEC_IMAGE_VERSION="$(strings -a -t d $image | grep -m 1 cec | cut -d '-' -f 2- | sed -e 's/ //g;s/.n02//')"
	fi
	if [ -z "$CEC_IMAGE_VERSION" ]; then
		# BlueField-2 CEC version format
		CEC_IMAGE_VERSION_HEXA="$(echo $image | grep -o '\-\(.*\)_' | grep -o '\([0-9a-fA-F]\+\).\([0-9a-fA-F]\+\)')"
		CEC_IMAGE_VERSION=$(printf "%d" 0x${CEC_IMAGE_VERSION_HEXA%*.*}).$(printf "%d" 0x${CEC_IMAGE_VERSION_HEXA##*.})
	fi
	if [ -z "$CEC_IMAGE_VERSION" ]; then
		ilog "- ERROR: Cannot detect included CEC firmware version"
		RC=$((RC+1))
		return
	fi
	ilog "Provided CEC firmware version: $CEC_IMAGE_VERSION"

	get_bmc_token

	CEC_INSTALLED_VERSION="$(curl -sSk -H "X-Auth-Token: $BMC_TOKEN" -X GET https://${BMC_IP}/redfish/v1/UpdateService/FirmwareInventory/Bluefield_FW_ERoT | jq -r ' .Version' | sed -e "s/[_|-]/./g;s/.n02//")"
	if [ -z "$CEC_INSTALLED_VERSION" ]; then
		ilog "- ERROR: Cannot detect running CEC firmware version"
		RC=$((RC+1))
		return
	fi
	ilog "Running CEC firmware version: $CEC_INSTALLED_VERSION"

	if [ "${CEC_IMAGE_VERSION}" == "${CEC_INSTALLED_VERSION}" ]; then
		if [ "X${FORCE_CEC_INSTALL}" == "Xyes" ]; then
			ilog "Installed CEC version is the same as provided. FORCE_CEC_INSTALL is set."
		else
			ilog "Installed CEC version is the same as provided. Skipping CEC firmware update."
			return
		fi
	fi

	ilog "Proceeding with the CEC firmware update..."

	if [ -z "$BMC_FIRMWARE_URL" ]; then
		BMC_FIRMWARE_URL=$(curl -sSk -H "X-Auth-Token: $BMC_TOKEN" -X GET https://${BMC_IP}/redfish/v1/UpdateService/FirmwareInventory | grep BMC_Firmware | awk '{print $NF}' | tr -d \")
		ilog "- INFO: BMC_FIRMWARE_URL: $BMC_FIRMWARE_URL"
	fi

	if [ -z "$BMC_INSTALLED_VERSION" ]; then
		BMC_INSTALLED_VERSION="$(curl -sSk -H "X-Auth-Token: $BMC_TOKEN" -X GET https://${BMC_IP}${BMC_FIRMWARE_URL} | jq -r ' .Version' | grep -o "\([0-9]\+\).\([0-9]\+\)-\([0-9]\+\)")"
		if [ -z "$BMC_INSTALLED_VERSION" ]; then
			ilog "- ERROR: Cannot detect running BMC firmware version"
			RC=$((RC+1))
			return
		fi
	fi

	if [[ $(echo -e "${BMC_MIN_MULTIPART_VERSION}\n${BMC_INSTALLED_VERSION}" | sort -V | head -n1) == "${BMC_MIN_MULTIPART_VERSION}" ]]; then
		ilog "curl -sSk -u <BMC_USER:BMC_PASSWORD> https://${BMC_IP}/redfish/v1/UpdateService/update-multipart -F 'UpdateParameters={\"ForceUpdate\":true};type=application/octet-stream' -F UpdateFile=@${image}"
		output=$(curl -sSk -u $BMC_USER:$BMC_PASSWORD https://${BMC_IP}/redfish/v1/UpdateService/update-multipart -F 'UpdateParameters={"ForceUpdate":true};type=application/octet-stream' -F UpdateFile=@${image} 2>&1)
	else
		ilog "curl -sSk -u <BMC_USER:BMC_PASSWORD> -H "Content-Type: application/octet-stream" -X POST -T ${image} https://${BMC_IP}/redfish/v1/UpdateService"
		output=$(curl -sSk -u $BMC_USER:$BMC_PASSWORD -H "Content-Type: application/octet-stream" -X POST -T ${image} https://${BMC_IP}/redfish/v1/UpdateService 2>&1)
	fi
	ilog "CEC Firmware update: $output"

	wait_bmc_task_complete
	if [ "$CEC_REBOOT" == "yes" ]; then
		if [[ $(echo -e "${CEC_MIN_RESET_VERSION}\n${CEC_INSTALLED_VERSION}" | sort -V | head -n1) == "${CEC_MIN_RESET_VERSION}" ]]; then
			log "Rebooting CEC..."
			output=$(curl -sSk -u $BMC_USER:"$BMC_PASSWORD" -H "Content-Type: application/json" -X POST -d '{"ResetType": "GracefulRestart"}' https://${BMC_IP}/redfish/v1/Chassis/Bluefield_ERoT/Actions/Chassis.Reset)
			status=$(echo $output | jq '."@Message.ExtendedInfo"[0].Message')
			if [ "$status" == "\"The request completed successfully."\" ]; then
				log "INFO: CEC firmware was updated to ${CEC_IMAGE_VERSION}."
			else
				rlog "ERR Failed to reset CEC"
				ilog "Failed to reset CEC. Output: $output"
				log "INFO: CEC firmware was updated to ${CEC_IMAGE_VERSION}. Host power cycle is required"
			fi
		else
			log "INFO: CEC firmware was updated to ${CEC_IMAGE_VERSION}. Host power cycle is required"
		fi
	fi

	BMC_UPGRADE_RESET=1 bfcfg -f /dev/null
}

bmc_reboot()
{
	log "Rebooting BMC..."
	get_bmc_token
	curl -sSk -H "X-Auth-Token: $BMC_TOKEN" -H "Content-Type: application/json" -X POST https://${BMC_IP}/redfish/v1/Managers/Bluefield_BMC/Actions/Manager.Reset -d '{"ResetType":"GracefulRestart"}'
	sleep 10
	wait_for_bmc_ip
}

bmc_reboot_from_dpu()
{
	ipmitool mc reset cold
	sleep 10
}

update_dpu_golden_image()
{
	log "Updating DPU Golden Image"
	image=$(/bin/ls -1 {/mnt,/}${DPU_GI_PATH}/${bmc_pref}*preboot-install.bfb 2> /dev/null | tail -1)

	if [ -z "$image" ]; then
		ilog "DPU golden image was not found"
		RC=$((RC+rc))
		return
	fi

	prepare_sshpass_environment

	ilog "Found DPU Golden Image: $image"
	DPU_GI_IMAGE_VERSION="$(sha256sum $image | awk '{print $1}')"
	ilog "Provided DPU Golden Image version: $DPU_GI_IMAGE_VERSION"

	DPU_GI_INSTALLED_VERSION="$(sshpass -p $BMC_SSH_PASSWORD $SSH ${BMC_SSH_USER}@${BMC_IP} dpu_golden_image golden_image_arm -V 2> /dev/null)"
	ilog "Installed DPU Golden Image version: $DPU_GI_INSTALLED_VERSION"

	if [ "$DPU_GI_IMAGE_VERSION" == "$DPU_GI_INSTALLED_VERSION" ]; then
		ilog "Installed DPU Golden Image version is the same as provided. Skipping DPU Golden Image update."
	else
		sshpass -p $BMC_SSH_PASSWORD $SCP $image ${BMC_SSH_USER}@${BMC_IP}:/tmp/
		output=$(sshpass -p $BMC_SSH_PASSWORD $SSH ${BMC_SSH_USER}@${BMC_IP} dpu_golden_image golden_image_arm -w /tmp/$(basename $image) 2>&1)
		if [ $? -eq 0 ]; then
			log "DPU Golden Image installed successfully"
		else
			log "DPU Golden Image installed failed"
		fi
		ilog "$output"
	fi
}

update_nic_firmware_golden_image()
{
	log "Updating NIC firmware Golden Image"
	image=$(/bin/ls -1 {/mnt,/}${NIC_FW_GI_PATH}/*${dpu_part_number}* 2> /dev/null | tail -1)

	if [ -z "$image" ]; then
		ilog "NIC firmware Golden Image for $dpu_part_number was not found"
		RC=$((RC+rc))
		return
	fi

	prepare_sshpass_environment

	ilog "Found NIC firmware Golden Image: $image"
	NIC_GI_IMAGE_VERSION="$(sha256sum $image | awk '{print $1}')"
	ilog "Provided NIC firmware Golden Image version: $NIC_GI_IMAGE_VERSION"

	NIC_GI_INSTALLED_VERSION="$(sshpass -p $BMC_SSH_PASSWORD $SSH ${BMC_SSH_USER}@${BMC_IP} dpu_golden_image golden_image_nic -V 2> /dev/null)"
	ilog "Installed NIC firmware Golden Image version: $NIC_GI_INSTALLED_VERSION"

	if [ "$NIC_GI_IMAGE_VERSION" == "$NIC_GI_INSTALLED_VERSION" ]; then
		ilog "Installed NIC firmware Golden Image version is the same as provided. Skipping NIC firmware Golden Image update."
		return
	fi

	sshpass -p $BMC_SSH_PASSWORD $SCP $image ${BMC_SSH_USER}@${BMC_IP}:/tmp/
	output=$(sshpass -p $BMC_SSH_PASSWORD $SSH ${BMC_SSH_USER}@${BMC_IP} dpu_golden_image golden_image_nic -w /tmp/$(basename $image) 2>&1)
	if [ $? -eq 0 ]; then
		log "NIC firmware Golden Image installed successfully"
	else
		log "NIC firmware Golden Image installed failed"
	fi
	ilog "$output"
}

bmc_components_update()
{
	if function_exists pre_bmc_components_update; then
		log "INFO: Running pre_bmc_components_update from bf.cfg"
		pre_bmc_components_update
	fi

	if [[ ! -z "$UEFI_PASSWORD" && ! -z "$NEW_UEFI_PASSWORD" ]]; then
		if [[ -z "$BMC_USER" || -z "$BMC_PASSWORD" ]]; then
			ilog "BMC_USER and/or BMC_PASSWORD are not defined. Skipping UEFI password change."
		else
			create_vlan
			change_uefi_password
		fi
	fi

	if [[ "$UPDATE_BMC_FW" == "yes" || "$UPDATE_CEC_FW" == "yes" || "$UPDATE_DPU_GOLDEN_IMAGE" == "yes" || "$UPDATE_NIC_FW_GOLDEN_IMAGE" == "yes" || ! -z "$NEW_BMC_PASSWORD" ]]; then
		if [[ -z "$BMC_USER" || -z "$BMC_PASSWORD" ]]; then
			ilog "BMC_USER and/or BMC_PASSWORD are not defined. Skipping BMC components upgrade."
			skip_bmc
			return
		else
			ilog "INFO: Running BMC components update flow"
			create_vlan
			# get_bmc_public_key
			if [ "$BMC_LINK_UP" == "yes" ]; then
				if [ ! -z "$NEW_BMC_PASSWORD" ]; then
					if change_bmc_password "$BMC_PASSWORD" "$NEW_BMC_PASSWORD"; then
						if [ "$BMC_PASSWORD" == "$BMC_SSH_PASSWORD" ]; then
							BMC_SSH_PASSWORD="$NEW_BMC_PASSWORD"
						fi
						BMC_PASSWORD="$NEW_BMC_PASSWORD"
					else
						skip_bmc
						return
					fi
				elif [ "$BMC_PASSWORD" == "$DEFAULT_BMC_PASSWORD" ]; then
					ilog "BMC password has the default value. Changing to the temporary password."
					if change_bmc_password "$BMC_PASSWORD" "$TMP_BMC_PASSWORD"; then
						BMC_PASSWORD="$TMP_BMC_PASSWORD"
					else
						skip_bmc
						return
					fi
					RESET_BMC_PASSWORD=1
				fi
				BMC_CREDENTIALS="'{\"username\":\"$BMC_USER\", \"password\":\"${BMC_PASSWORD}\"}'"
			else
				skip_bmc
				return
			fi
		fi

		if ! get_bmc_token; then
			skip_bmc
			return
		fi

	else
		return
	fi

	if function_exists bmc_custom_action1; then
		log "INFO: Running bmc_custom_action1 from bf.cfg"
		bmc_custom_action1
	fi

	if [[ "$UPDATE_BMC_FW" == "yes" && "$BMC_LINK_UP" == "yes" ]]; then
		update_bmc_fw
	fi

	if function_exists bmc_custom_action2; then
		log "INFO: Running bmc_custom_action2 from bf.cfg"
		bmc_custom_action2
	fi

	if [[ "$UPDATE_CEC_FW" == "yes" && "$BMC_LINK_UP" == "yes" ]]; then
		update_cec_fw
	fi

	if function_exists bmc_custom_action3; then
		log "INFO: Running bmc_custom_action3 from bf.cfg"
		bmc_custom_action3
	fi

	if [[ "$UPDATE_BMC_FW" == "yes" && "$BMC_LINK_UP" == "yes" && "$BMC_REBOOT" == "yes" && "$BMC_FIRMWARE_UPDATED" == "yes" ]]; then
		bmc_reboot
	fi

	if function_exists bmc_custom_action4; then
		log "INFO: Running bmc_custom_action4 from bf.cfg"
		bmc_custom_action4
	fi

	if [[ "$UPDATE_DPU_GOLDEN_IMAGE" == "yes" && "$BMC_LINK_UP" == "yes" ]]; then
		update_dpu_golden_image
	fi

	if function_exists bmc_post_dpu_gi; then
		log "INFO: Running bmc_post_dpu_gi from bf.cfg"
		bmc_post_dpu_gi
	fi

	if [[ "$UPDATE_NIC_FW_GOLDEN_IMAGE" == "yes" && "$BMC_LINK_UP" == "yes" ]]; then
		if [ -z "${dpu_part_number}" ]; then
			log "Cannot identify DPU Part Number. Skipping NIC firmware Golden Image update."
		else
			update_nic_firmware_golden_image
		fi
	fi

	if function_exists bmc_post_nic_fw_gi; then
		log "INFO: Running bmc_post_nic_fw_gi from bf.cfg"
		bmc_post_nic_fw_gi
	fi

	if [[ "X${BMC_REBOOT}" == "Xyes" && "X${BMC_REBOOT_CONFIG}" == "Xyes" && "${BMC_CONFIG_UPDATED}" == "yes" ]]; then
		bmc_reboot
	fi

	if [ $RESET_BMC_PASSWORD -eq 1 ]; then
		ilog "Reset BMC configuration to default"
		output=$(curl -sSk -u $BMC_USER:"$BMC_PASSWORD" -H "Content-Type: application/json" -X POST https://${BMC_IP}/redfish/v1/Managers/Bluefield_BMC/Actions/Manager.ResetToDefaults -d '{"ResetToDefaultsType": "ResetAll"}')
		status=$(echo $output | jq '."@Message.ExtendedInfo"[0].Message')
		if [ "$status" != "\"The request completed successfully."\" ]; then
			rlog "ERR Failed to reset BMC $BMC_USER password."
			ilog "Failed to reset BMC $BMC_USER password. Output: $output"
		fi
	fi

	if [ $FIELD_MODE_SET -eq 1 ]; then
		if [ "$(get_field_mode)" == "00" ]; then
			set_field_mode '01'
			FIELD_MODE_SET=0
			bmc_reboot_from_dpu
		fi
	fi

	if function_exists post_bmc_components_update; then
		log "INFO: Running post_bmc_components_update from bf.cfg"
		post_bmc_components_update
	fi
}

global_installation_flow()
{
	if function_exists bfb_pre_install; then
		log "INFO: Running bfb_pre_install from bf.cfg"
		bfb_pre_install
	fi

	configure_target_os
	configure_dhcp
	configure_sfs
	configure_services
	set_root_password
	# create_initramfs

	configure_grub

	update_uefi_boot_entries

	if [ "X$ENABLE_SFC_HBN" == "Xyes" ]; then
		enable_sfc_hbn
	fi

	if [ "X$ENABLE_BR_HBN" == "Xyes" ]; then
		enable_sfc_hbn
	fi

	update_efi_bootmgr

	if function_exists bfb_modify_os; then
		log "INFO: Running bfb_modify_os from bf.cfg"
		bfb_modify_os
	fi

	if function_exists bfb_custom_action1; then
		log "INFO: Running bfb_custom_action1 from bf.cfg"
		bfb_custom_action1
	fi

	if [ "$UPDATE_ATF_UEFI" == "yes" ]; then
		update_atf_uefi
	fi

	if function_exists bmc_components_update; then
		bmc_components_update
	fi

	if [ "$WITH_NIC_FW_UPDATE" == "yes" ]; then
		update_nic_firmware
	fi

	if function_exists bfb_post_install; then
		log "INFO: Running bfb_post_install from bf.cfg"
		bfb_post_install
	fi

	log "INFO: Installation finished"

	reset_nic_firmware
}

cat >> $LOG << EOF

############ DEBUG INFO (pre-install) ###############
KERNEL: $(uname -r)

LSMOD:
$(lsmod)

NETWORK:
$(ip addr show)

CMDLINE:
$(cat /proc/cmdline)

PARTED:
$(parted -l -s)

LSPCI:
$(lspci)

NIC FW INFO:
$(flint -d /dev/mst/mt*_pciconf0 q full)

DPU Part Number:
$dpu_part_number

MLXCONFIG:
$(mlxconfig -d /dev/mst/mt*_pciconf0 -e q)
########### DEBUG INFO END ############

EOF

rshlog_path="/sys/devices/platform/MLNXBF04:00/driver/rsh_log"
if [ ! -e "${rshlog_path}" ]; then
  rshlog_path="/sys/devices/platform/MLNXBF04:00/rsh_log"
fi

[ ! -e "${rshlog_path}" ] && log "RSHIM log path doe not exist: $rshlog_path"

global_installation_flow

if [ $RC -eq 0 ]; then
	rlog "`basename $0` finished successfully"
else
	echo "See $LOG"
	rlog "`basename $0` finished with errors"
fi
