#!/bin/bash

###############################################################################
#
# Copyright 2023 NVIDIA Corporation
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

# btrfs-rollback.sh — Roll back a deferred BTRFS update by restoring @_old
# as the default subvolume.
#
# Usage: btrfs-rollback.sh [--delete-failed]
#
# Options:
#   --delete-failed   Delete the failed @ snapshot after rollback. If the
#                     failed snapshot is the running root, it is renamed to
#                     @_failed instead and must be deleted after reboot.
#
# The rollback takes effect after reboot (or immediately if run before reboot).

set -e

PROG=$(basename "$0")
DELETE_FAILED=0

usage()
{
	echo "Usage: $PROG [--delete-failed]"
	echo ""
	echo "  --delete-failed   Delete the failed @ snapshot after rollback"
	echo ""
	echo "Restores @_old as the default subvolume. Reboot to activate."
	exit "${1:-1}"
}

case "$1" in
	"")
		;;
	--delete-failed)
		DELETE_FAILED=1
		;;
	-h|--help)
		usage 0
		;;
	*)
		echo "ERROR: Unknown option: $1" >&2
		usage
		;;
esac

if [ $# -gt 1 ]; then
	echo "ERROR: Too many arguments" >&2
	usage
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "ERROR: Must be run as root" >&2
	exit 1
fi

# Detect root device
ROOT_DEV=$(findmnt -n -o SOURCE / | sed 's/\[.*\]//')
if [ -z "$ROOT_DEV" ]; then
	echo "ERROR: Cannot determine root device" >&2
	exit 1
fi

# Verify BTRFS
ROOT_FSTYPE=$(findmnt -n -o FSTYPE /)
if [ "$ROOT_FSTYPE" != "btrfs" ]; then
	echo "ERROR: Root filesystem is $ROOT_FSTYPE, not btrfs" >&2
	exit 1
fi

# Subvolume ID of the running root (used to avoid deleting it under ourselves)
RUNNING_SUBVOL_ID=$(findmnt -n -o OPTIONS / | tr ',' '\n' | sed -n 's/^subvolid=//p')

WORKDIR=$(mktemp -d /tmp/btrfs-rollback.XXXXXX)
trap 'umount "$WORKDIR" 2>/dev/null; rmdir "$WORKDIR" 2>/dev/null' EXIT

echo "==> Mounting top-level BTRFS volume from $ROOT_DEV"
mount -t btrfs -o subvolid=5 "$ROOT_DEV" "$WORKDIR"

if [ ! -d "$WORKDIR/@_old" ]; then
	echo "ERROR: No @_old subvolume found — nothing to roll back to" >&2
	exit 1
fi

# Set @_old as the default subvolume FIRST.  This must happen before any
# delete of @, because btrfs-progs refuses to delete the default subvolume.
# The default is tracked by ID, so the renames below do not affect it.
SUBVOL_ID=$(btrfs subvolume show "$WORKDIR/@_old" | grep "Subvolume ID" | awk '{print $3}')
echo "==> Setting default subvolume to @_old (id=$SUBVOL_ID)"
btrfs subvolume set-default "$SUBVOL_ID" "$WORKDIR"

# Handle the current (failed) @ subvolume
FAILED_KEPT=0
if [ -d "$WORKDIR/@" ]; then
	FAILED_ID=$(btrfs subvolume show "$WORKDIR/@" | grep "Subvolume ID" | awk '{print $3}')
	if [ $DELETE_FAILED -eq 1 ] && [ "$FAILED_ID" != "$RUNNING_SUBVOL_ID" ]; then
		echo "==> Deleting failed @ snapshot"
		btrfs subvolume delete "$WORKDIR/@"
	else
		if [ -d "$WORKDIR/@_failed" ]; then
			btrfs subvolume delete "$WORKDIR/@_failed"
		fi
		echo "==> Renaming current @ to @_failed"
		mv "$WORKDIR/@" "$WORKDIR/@_failed"
		if [ $DELETE_FAILED -eq 1 ]; then
			FAILED_KEPT=1
		fi
	fi
fi

# Restore @_old as @
echo "==> Renaming @_old to @"
mv "$WORKDIR/@_old" "$WORKDIR/@"

umount "$WORKDIR"
rmdir "$WORKDIR"
trap - EXIT

echo ""
echo "SUCCESS: Rolled back to previous @ subvolume."
echo "  - Reboot to activate."
if [ $FAILED_KEPT -eq 1 ]; then
	echo "  - The failed update is the running root, so it was renamed to"
	echo "    @_failed instead of deleted. After reboot, delete it with:"
	echo "      mount -o subvolid=5 $ROOT_DEV /mnt"
	echo "      btrfs subvolume delete /mnt/@_failed"
	echo "      umount /mnt"
fi
