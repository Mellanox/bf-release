#!/bin/bash

###############################################################################
#
# Copyright 2026 NVIDIA Corporation
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

# bfiso-btrfs-setup.sh - Convert an ISO (subiquity/curtin) installation on a
# Btrfs root into the layout used by btrfs-deferred-update.sh and
# btrfs-rollback.sh, the same layout as a BFB ROOTFS=btrfs installation:
#
#   - the root file system is the subvolume @, set as the default subvolume
#   - GRUB is installed from @: the ESP stub loads /@/boot/grub/grub.cfg and
#     the kernel command line has rootflags=subvol=@
#   - nothing but @ is left on the top-level volume
#
# Curtin installs into the top-level volume (subvolid=5) because it does not
# create subvolumes.  GRUB does not use the Btrfs default subvolume, so
# without this conversion it keeps loading the installed grub.cfg and kernel
# from the top-level volume and never boots an update staged in @.
#
# Run it as the LAST autoinstall late-command, from the installer
# environment and NOT with "curtin in-target": it removes the installed tree
# from the top-level volume, which is the root of the in-target chroot.
# Copy it out of the target first:
#
#   cp /target/usr/sbin/bfiso-btrfs-setup.sh /tmp/
#   bash /tmp/bfiso-btrfs-setup.sh /target /dev/nvme0n1
#
# Any failure exits non-zero, so that the installation stops instead of
# producing a system that cannot boot staged updates.

set -eE -o pipefail

PROG=$(basename "$0")
TOP=/tmp/bfiso-btrfs-top
ROOT=/tmp/bfiso-btrfs-root
SUBVOL=@
# Must match the bootloader ID used for the ESP stub (grub-install default)
BOOTLOADER_ID=ubuntu

usage()
{
	echo "Usage: $PROG <target> <boot disk>"
	echo ""
	echo "  <target>     Mount point of the installed system (/target)"
	echo "  <boot disk>  Disk that holds the ESP, for example /dev/nvme0n1"
	exit "${1:-1}"
}

log()
{
	echo "$PROG: $*"
}

err()
{
	echo "$PROG: ERROR: $*" >&2
	exit 1
}

case "$1" in
	-h|--help)
		usage 0
		;;
esac
[ $# -eq 2 ] || usage

TARGET=$1
DISK=$2

[ "$(id -u)" -eq 0 ] || err "must be run as root"
[ -b "$DISK" ] || err "$DISK is not a block device"
command -v btrfs > /dev/null || err "btrfs not found in the installer environment"
for tool in grub-install update-grub; do
	[ -x "$TARGET/usr/sbin/$tool" ] || err "$TARGET/usr/sbin/$tool not found"
done

ROOT_FSTYPE=$(findmnt -n -o FSTYPE --mountpoint "$TARGET") || err "$TARGET is not a mount point"
[ "$ROOT_FSTYPE" == "btrfs" ] || err "$TARGET is $ROOT_FSTYPE, not btrfs"
# findmnt reports the device as /dev/xxx[/subvol]
ROOT_DEV=$(findmnt -n -o SOURCE --mountpoint "$TARGET" | sed 's/\[.*//')
ESP_DEV=$(findmnt -n -o SOURCE --mountpoint "$TARGET/boot/efi") || err "$TARGET/boot/efi is not mounted"
log "root device $ROOT_DEV, ESP $ESP_DEV, boot disk $DISK"

cleanup()
{
	findmnt -rn --mountpoint "$ROOT" > /dev/null && umount -R -l "$ROOT"
	findmnt -rn --mountpoint "$TOP" > /dev/null && umount -l "$TOP"
	rmdir "$ROOT" "$TOP" 2> /dev/null || true
}
trap 'echo "$PROG: ERROR: failed at line $LINENO: $BASH_COMMAND" >&2' ERR
trap cleanup EXIT

#
# 1. Create @ as a snapshot of the installed top-level volume and make it the
#    default subvolume.
#
mkdir -p "$TOP"
mount -t btrfs -o subvolid=5 "$ROOT_DEV" "$TOP"
mount --make-private "$TOP"

[ ! -e "$TOP/$SUBVOL" ] || err "$SUBVOL already exists on $ROOT_DEV"
btrfs subvolume snapshot "$TOP" "$TOP/$SUBVOL"
SUBVOL_ID=$(btrfs subvolume show "$TOP/$SUBVOL" | awk '/Subvolume ID:/ {print $3}')
[ -n "$SUBVOL_ID" ] || err "cannot read the ID of $SUBVOL"
btrfs subvolume set-default "$SUBVOL_ID" "$TOP"
log "$SUBVOL (id=$SUBVOL_ID) is the default subvolume"

#
# 2. Reinstall GRUB and regenerate grub.cfg from inside @.
#    /@ must be the root of a real mount so that grub-probe finds its device
#    and GRUB writes /@/boot/grub paths and rootflags=subvol=@.
#    --no-nvram keeps the UEFI boot entry created by bfiso-post-install.sh.
#
mkdir -p "$ROOT"
mount -t btrfs -o subvol=$SUBVOL "$ROOT_DEV" "$ROOT"
mount --make-private "$ROOT"
mount "$ESP_DEV" "$ROOT/boot/efi"
for fs in /dev /proc /sys; do
	mount --rbind "$fs" "$ROOT$fs"
	mount --make-rslave "$ROOT$fs"
done

chroot "$ROOT" grub-install --no-nvram --bootloader-id="$BOOTLOADER_ID" "$DISK"
chroot "$ROOT" update-grub

STUB="$ROOT/boot/efi/EFI/$BOOTLOADER_ID/grub.cfg"
log "ESP GRUB stub ($STUB):"
cat "$STUB"
grep -q "/$SUBVOL/boot/grub" "$STUB" || err "the ESP GRUB stub does not load /$SUBVOL/boot/grub"
grep -Eq "rootflags=subvol=$SUBVOL( |\$)" "$ROOT/boot/grub/grub.cfg" ||
	err "/boot/grub/grub.cfg in $SUBVOL has no rootflags=subvol=$SUBVOL"
log "/etc/fstab in $SUBVOL:"
cat "$ROOT/etc/fstab"

umount -R "$ROOT"
rmdir "$ROOT"

#
# 3. Remove the installed tree from the top-level volume, so that only @
#    remains.  Do not cross into other file systems: directories that are
#    mount points under the target (/boot/efi, the installer's /proc, /sys,
#    /dev, /run binds) cannot be removed and are left empty.
#
log "removing the installed tree from the top-level volume"
find "$TOP" -mindepth 1 -maxdepth 1 ! -name "$SUBVOL" -print0 |
	xargs -0 -r rm -rf --one-file-system || true
log "top-level volume after cleanup:"
ls -la "$TOP"

umount "$TOP"
rmdir "$TOP"
trap - EXIT
log "done"
