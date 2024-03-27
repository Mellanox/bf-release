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
BFB_NIC_FW_UPDATE=0
NIC_FW_FOUND=0
FW_UPDATER=/opt/mellanox/mlnx-fw-updater/mlnx_fw_updater.pl
FW_DIR=/opt/mellanox/mlnx-fw-updater/firmware/

distro="Ubuntu"

rshimlog=$(which bfrshlog 2> /dev/null)
RC=0
err_msg=""
export LC_ALL=C

logfile=${distro}.installation.log
LOG=/root/$logfile

fspath=$(readlink -f "$(dirname $0)")

cx_pcidev=$(lspci -nD 2> /dev/null | grep 15b3:a2d[26c] | awk '{print $1}' | head -1)
cx_dev_id=$(lspci -nD -s ${cx_pcidev} 2> /dev/null | awk -F ':' '{print strtonum("0x" $NF)}')
pciids=$(lspci -nD 2> /dev/null | grep 15b3:a2d[26c] | awk '{print $1}')
dpu_part_number=$(flint -d $cx_pcidev q full | grep "Part Number:" | awk '{print $NF}')
PSID=$(mstflint -d $cx_pcidev q | grep PSID | awk '{print $NF}')

UPDATE_ATF_UEFI=${UPDATE_ATF_UEFI:-"yes"}
UPDATE_DPU_OS=${UPDATE_DPU_OS:-"yes"}
WITH_NIC_FW_UPDATE=${WITH_NIC_FW_UPDATE:-"yes"}
NIC_FW_UPDATE_PASSED=0
DHCP_CLASS_ID=${PXE_DHCP_CLASS_ID:-""}
DHCP_CLASS_ID_OOB=${DHCP_CLASS_ID_OOB:-"NVIDIA/BF/OOB"}
DHCP_CLASS_ID_DP=${DHCP_CLASS_ID_DP:-"NVIDIA/BF/DP"}
FACTORY_DEFAULT_DHCP_BEHAVIOR=${FACTORY_DEFAULT_DHCP_BEHAVIOR:-"true"}

if [ "${FACTORY_DEFAULT_DHCP_BEHAVIOR}" == "true" ]; then
	# Set factory defaults
	DHCP_CLASS_ID="NVIDIA/BF/PXE"
	DHCP_CLASS_ID_OOB="NVIDIA/BF/OOB"
	DHCP_CLASS_ID_DP="NVIDIA/BF/DP"
fi

rlog()
{
	if [ -n "$rshimlog" ]; then
		$rshimlog "$*"
	fi
}

log()
{
	msg="[$(date +%H:%M:%S)] $*"
	echo "$msg" > /dev/ttyAMA0
	echo "$msg" > /dev/hvc0
	if [ -n "$rshimlog" ]; then
		$rshimlog "$*"
	fi
	echo "$msg" >> $LOG
}

ilog()
{
	msg="[$(date +%H:%M:%S)] $*"
	echo "$msg" >> $LOG
	echo "$msg" > /dev/ttyAMA0
	echo "$msg" > /dev/hvc0
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
	if [ -n "$FLINT" ]; then
		PSID=$($FLINT -d $pciid q | grep PSID | awk '{print $NF}')

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
	fi

	sed -i -r -e "s/^(MACAddressPolicy.*)/# \1/" /usr/lib/systemd/network/99-default.link

	# openibd to support MLNX_OFED drivers coming with Canonical's deb
	sed -i -e "s/FORCE_MODE=.*/FORCE_MODE=yes/" /etc/infiniband/openib.conf

	/bin/rm -f /etc/ssh/sshd_config.d/60-cloudimg-settings.conf
	/bin/rm -f /etc/default/grub.d/50-cloudimg-settings.cfg

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
	if ! [ -z "${NUM_VFs_PHYS_PORT0}" ]; then
		ARG_PORT0="--ecpf0 "${NUM_VFs_PHYS_PORT0}
	fi
	if ! [ -z "${NUM_VFs_PHYS_PORT1}" ]; then
		ARG_PORT1="--ecpf1 "${NUM_VFs_PHYS_PORT1}
	fi
	HBN_UPLINKS=${HBN_UPLINKS:-"p0,p1"}
	HBN_REPS=${HBN_REPS:-"pf0hpf,pf1hpf,pf0vf0-pf0vf13"}
	HBN_DPU_SFS=${HBN_DPU_SFS:-"pf0dpu1,pf0dpu3"}
	HUGEPAGE_SIZE=${HUGEPAGE_SIZE:-2048}
	HUGEPAGE_COUNT=${HUGEPAGE_COUNT:-3072}
	CLOUD_OPTION=${CLOUD_OPTION:-""}
	log "INFO: Installing SFC HBN environment"
	ilog "$(HBN_UPLINKS=${HBN_UPLINKS} HBN_REPS=${HBN_REPS} HBN_DPU_SFS=${HBN_DPU_SFS} HUGEPAGE_SIZE=${HUGEPAGE_SIZE} HUGEPAGE_COUNT=${HUGEPAGE_COUNT} CLOUD_OPTION=${CLOUD_OPTION} /opt/mellanox/sfc-hbn/install.sh ${ARG_PORT0} ${ARG_PORT1} 2>&1)"
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

	if (hexdump -C /sys/firmware/acpi/tables/SSDT* | grep -q MLNXBF33); then
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
	mstflint -d $cx_pcidev q 2>&1 | grep -w 'FW Version:' | awk '{print $NF}'
}

provided_nic_fw()
{
	${FW_DIR}/mlxfwmanager_sriov_dis_aarch64_${cx_dev_id} --list 2> /dev/null | grep -w "${PSID}" | awk '{print $4}'
}

fw_update()
{
	if [[ -x ${FW_UPDATER} && -d ${FW_DIR} ]]; then
		BFB_NIC_FW_UPDATE=1
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
			log "INFO: NIC firmware update done"
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

global_installation_flow()
{
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

global_installation_flow
