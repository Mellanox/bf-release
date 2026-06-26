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

# btrfs-deferred-update.sh — Install packages into a BTRFS snapshot of the
# running root filesystem. The update is activated only after reboot.
#
# Usage: btrfs-deferred-update.sh [package1.deb package2.deb ...] | [--apt pkg1 pkg2 ...]
#
# The script:
#   1. Mounts the top-level BTRFS volume (subvolid=5)
#   2. Creates a writable snapshot @_new from the current @ subvolume
#   3. Installs packages inside the snapshot via chroot
#   4. Sets @_new as the default subvolume (activated on next boot)
#   5. Renames the old @ to @_old for rollback

set -e

PROG=$(basename "$0")

usage()
{
	echo "Usage:"
	echo "  $PROG pkg1.deb pkg2.deb ...     Install .deb files (dpkg -i)"
	echo "  $PROG --apt pkg1 pkg2 ...       Install packages via apt-get"
	echo "  $PROG --upgrade                 Upgrade all packages (apt-get upgrade)"
	echo ""
	echo "The update takes effect after reboot."
	echo "Use btrfs-rollback.sh to revert before or after reboot."
	exit 1
}

if [ $# -eq 0 ]; then
	usage
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "ERROR: Must be run as root" >&2
	exit 1
fi

# Detect root device from current mount
ROOT_DEV=$(findmnt -n -o SOURCE / | sed 's/\[.*\]//')
if [ -z "$ROOT_DEV" ]; then
	echo "ERROR: Cannot determine root device" >&2
	exit 1
fi

# Verify the root filesystem is BTRFS
ROOT_FSTYPE=$(findmnt -n -o FSTYPE /)
if [ "$ROOT_FSTYPE" != "btrfs" ]; then
	echo "ERROR: Root filesystem is $ROOT_FSTYPE, not btrfs" >&2
	exit 1
fi

WORKDIR=$(mktemp -d /tmp/btrfs-update.XXXXXX)
trap 'cleanup' EXIT

cleanup()
{
	# Unmount chroot binds if still mounted
	for mp in proc sys dev/pts dev; do
		umount "$WORKDIR/@_new/$mp" 2>/dev/null || true
	done
	umount "$WORKDIR" 2>/dev/null || true
	rmdir "$WORKDIR" 2>/dev/null || true
}

echo "==> Mounting top-level BTRFS volume from $ROOT_DEV"
mount -t btrfs -o subvolid=5 "$ROOT_DEV" "$WORKDIR"

# Verify @ exists
if [ ! -d "$WORKDIR/@" ]; then
	echo "ERROR: Subvolume @ not found on $ROOT_DEV" >&2
	exit 1
fi

# Block if a pending update already exists
if [ -d "$WORKDIR/@_old" ]; then
	echo "ERROR: A pending update already exists (@_old is present)." >&2
	echo "Reboot first or run btrfs-rollback.sh before staging another update." >&2
	exit 1
fi

# Remove stale @_new if it exists (interrupted previous run)
if [ -d "$WORKDIR/@_new" ]; then
	echo "==> Removing stale @_new snapshot from previous run"
	btrfs subvolume delete "$WORKDIR/@_new"
fi

echo "==> Creating snapshot @_new from @"
btrfs subvolume snapshot "$WORKDIR/@" "$WORKDIR/@_new"

echo "==> Preparing chroot environment"
mount --bind /proc "$WORKDIR/@_new/proc"
mount --bind /sys "$WORKDIR/@_new/sys"
mount --bind /dev "$WORKDIR/@_new/dev"
mount --bind /dev/pts "$WORKDIR/@_new/dev/pts"

# Install packages
if [ "$1" == "--upgrade" ]; then
	echo "==> Running apt-get update in snapshot"
	chroot "$WORKDIR/@_new" apt-get update
	echo "==> Upgrading all packages in snapshot"
	chroot "$WORKDIR/@_new" apt-get upgrade -y
elif [ "$1" == "--apt" ]; then
	shift
	echo "==> Running apt-get update in snapshot"
	chroot "$WORKDIR/@_new" apt-get update
	echo "==> Installing packages via apt-get: $*"
	chroot "$WORKDIR/@_new" apt-get install -y "$@"
else
	# Copy .deb files into snapshot and install
	DEB_DIR="$WORKDIR/@_new/tmp/deferred-debs"
	mkdir -p "$DEB_DIR"
	for deb in "$@"; do
		if [ ! -f "$deb" ]; then
			echo "ERROR: File not found: $deb" >&2
			exit 1
		fi
		cp "$deb" "$DEB_DIR/"
	done
	echo "==> Installing .deb packages in snapshot"
	chroot "$WORKDIR/@_new" dpkg -i /tmp/deferred-debs/*.deb
	chroot "$WORKDIR/@_new" apt-get install -f -y
	rm -rf "$DEB_DIR"
fi

echo "==> Unmounting chroot binds"
umount "$WORKDIR/@_new/dev/pts"
umount "$WORKDIR/@_new/dev"
umount "$WORKDIR/@_new/sys"
umount "$WORKDIR/@_new/proc"

# Rename current @ to @_old
echo "==> Renaming @ to @_old (rollback target)"
mv "$WORKDIR/@" "$WORKDIR/@_old"

# Rename @_new to @
echo "==> Renaming @_new to @"
mv "$WORKDIR/@_new" "$WORKDIR/@"

# Set new @ as default subvolume
NEW_SUBVOL_ID=$(btrfs subvolume show "$WORKDIR/@" | grep "Subvolume ID" | awk '{print $3}')
echo "==> Setting default subvolume to @ (id=$NEW_SUBVOL_ID)"
btrfs subvolume set-default "$NEW_SUBVOL_ID" "$WORKDIR"

umount "$WORKDIR"
rmdir "$WORKDIR"
trap - EXIT

echo ""
echo "SUCCESS: Update staged in @ subvolume."
echo "  - Reboot to activate the update."
echo "  - Run btrfs-rollback.sh to revert to the previous state."
