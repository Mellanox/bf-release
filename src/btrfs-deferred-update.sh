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
# Usage: btrfs-deferred-update.sh [package1.deb ...] | [--apt pkg1 ...] | [--upgrade]
#
# The script:
#   1. Mounts the top-level BTRFS volume (subvolid=5)
#   2. Creates a writable snapshot @_new from the current @ subvolume
#   3. Installs packages inside the snapshot via chroot, without writing to
#      the EFI System Partition
#   4. Renames the old @ to @_old for rollback and @_new to @
#   5. Sets the new @ as the default subvolume (activated on next boot)

set -e

PROG=$(basename "$0")

usage()
{
	echo "Usage:"
	echo "  $PROG pkg1.deb pkg2.deb ...     Install .deb files (dpkg -i)"
	echo "  $PROG --apt pkg1 pkg2 ...       Install packages via apt-get"
	echo "  $PROG --upgrade                 Upgrade all packages (apt-get dist-upgrade)"
	echo ""
	echo "The update takes effect after reboot."
	echo "Use btrfs-rollback.sh to revert before or after reboot."
	exit "${1:-1}"
}

# Validate arguments before touching the filesystem, so that a bad or
# help-only invocation never creates an @_new snapshot.
if [ $# -eq 0 ]; then
	usage
fi

MODE=deb
case "$1" in
	-h|--help)
		usage 0
		;;
	--upgrade)
		MODE=upgrade
		if [ $# -ne 1 ]; then
			echo "ERROR: --upgrade does not take arguments" >&2
			usage
		fi
		;;
	--apt)
		MODE=apt
		if [ $# -lt 2 ]; then
			echo "ERROR: --apt requires at least one package name" >&2
			usage
		fi
		;;
	-*)
		echo "ERROR: Unknown option: $1" >&2
		usage
		;;
	*)
		# The files are copied into one directory in the snapshot, so
		# two files with the same name would overwrite each other.
		declare -A DEB_NAMES
		for deb in "$@"; do
			if [ ! -f "$deb" ]; then
				echo "ERROR: File not found: $deb" >&2
				exit 1
			fi
			name=$(basename "$deb")
			if [ -n "${DEB_NAMES[$name]}" ]; then
				echo "ERROR: Duplicate file name: $name" >&2
				exit 1
			fi
			DEB_NAMES[$name]=1
		done
		;;
esac

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
CREATED_NEW=0
trap 'cleanup' EXIT

# Unmount the whole chroot mount tree.  If something inside the chroot still
# holds a mount busy, detach it lazily so the snapshot can still be renamed;
# the mount goes away when it is no longer used.  Check with findmnt, not
# mountpoint: a Btrfs subvolume has its own device number, so mountpoint
# reports it as a mount point even when nothing is mounted on it.
umount_chroot()
{
	if ! findmnt -rn --mountpoint "$WORKDIR/@_new" > /dev/null; then
		return 0
	fi
	if ! umount -R "$WORKDIR/@_new"; then
		echo "WARNING: chroot mounts are busy, detaching them lazily" >&2
		umount -R -l "$WORKDIR/@_new"
	fi
}

cleanup()
{
	# Unmount the chroot mount tree if it is still mounted
	umount_chroot 2>/dev/null || true
	# Staging failed: drop the partial snapshot this run created
	if [ $CREATED_NEW -eq 1 ] && [ -d "$WORKDIR/@_new" ]; then
		echo "==> Staging failed, deleting partial @_new snapshot" >&2
		btrfs subvolume delete "$WORKDIR/@_new" >/dev/null 2>&1 || true
	fi
	umount "$WORKDIR" 2>/dev/null || true
	rmdir "$WORKDIR" 2>/dev/null || true
}

echo "==> Mounting top-level BTRFS volume from $ROOT_DEV"
mount -t btrfs -o subvolid=5 "$ROOT_DEV" "$WORKDIR"
# Keep the chroot mounts made below WORKDIR out of the running system's
# mount peer groups
mount --make-private "$WORKDIR"

# Verify @ exists
if [ ! -d "$WORKDIR/@" ]; then
	echo "ERROR: Subvolume @ not found on $ROOT_DEV" >&2
	exit 1
fi

# Block if a pending update already exists.  @_old is not removed by a
# reboot: the previous update must be accepted (delete @_old) or rolled back.
if [ -d "$WORKDIR/@_old" ]; then
	OLD_ID=$(btrfs subvolume show "$WORKDIR/@_old" | grep "Subvolume ID" | awk '{print $3}')
	RUNNING_SUBVOL_ID=$(findmnt -n -o OPTIONS / | tr ',' '\n' | sed -n 's/^subvolid=//p')
	echo "ERROR: A previous update is still pending (@_old, id=$OLD_ID, is present)." >&2
	if [ "$OLD_ID" == "$RUNNING_SUBVOL_ID" ]; then
		echo "The system has not been restarted into the staged update yet." >&2
		echo "Reboot to activate it, or run btrfs-rollback.sh to discard it." >&2
	else
		echo "To accept the current update, delete @_old:" >&2
		echo "  btrfs subvolume delete --subvolid $OLD_ID /" >&2
		echo "To revert the current update instead, run btrfs-rollback.sh." >&2
	fi
	exit 1
fi

# Remove stale @_new if it exists (interrupted previous run)
if [ -d "$WORKDIR/@_new" ]; then
	echo "==> Removing stale @_new snapshot from previous run"
	btrfs subvolume delete "$WORKDIR/@_new"
fi

echo "==> Creating snapshot @_new from @"
btrfs subvolume snapshot "$WORKDIR/@" "$WORKDIR/@_new"
CREATED_NEW=1

echo "==> Preparing chroot environment"
# Bind-mount the snapshot root on itself so that "/" inside the chroot is a
# real mount point.  Without it, grub-probe (run by the kernel postinst hook
# zz-update-grub) fails with "cannot find a device for /" and no kernel
# package can be configured.  This must come before the binds below: a plain
# bind mount does not carry submounts, so binding the root afterwards would
# hide /proc, /sys and /dev inside the chroot.
mount --bind "$WORKDIR/@_new" "$WORKDIR/@_new"

# Bind /proc, /sys and /dev recursively, so the chroot sees the mounts the
# running system has under them (efivarfs, securityfs, /dev/pts, /dev/shm
# and so on).  With plain binds those were missing, and package scripts
# mounted efivarfs again under /sys.
#
# The copies of shared mounts join the running system's peer groups, so
# mount and unmount events would cross in both directions: a filesystem
# mounted inside the chroot (for example efivarfs by a package script)
# appeared on the running system, and unmounting the chroot copies could
# unmount them on the running system.  Make each copy a slave immediately,
# before anything can be mounted or unmounted below it, so events only flow
# from the running system into the chroot.
bind_api_fs()
{
	mount --rbind "$1" "$WORKDIR/@_new$1"
	mount --make-rslave "$WORKDIR/@_new$1"
}
bind_api_fs /proc
bind_api_fs /sys
bind_api_fs /dev

# Name resolution: /etc/resolv.conf usually links into /run (for example
# /run/systemd/resolve/stub-resolv.conf), which is empty in the snapshot,
# so apt-get could not resolve network repositories.  Bind only the
# directory that holds the running system's resolv.conf, read-only.  The
# rest of /run is not bound: it holds the running system's sockets and
# state, and package scripts check it to decide whether to talk to systemd.
RESOLV_CONF=$(readlink -f /etc/resolv.conf || true)
RESOLV_DIR_CREATED=
case "$RESOLV_CONF" in
	/run/*)
		if [ -f "$RESOLV_CONF" ]; then
			RESOLV_DIR=$(dirname "$RESOLV_CONF")
			# Remember the top directory that has to be created, so it
			# can be removed from the snapshot again.
			dir=$RESOLV_DIR
			while [ "$dir" != "/run" ] && [ ! -d "$WORKDIR/@_new$dir" ]; do
				RESOLV_DIR_CREATED=$dir
				dir=$(dirname "$dir")
			done
			mkdir -p "$WORKDIR/@_new$RESOLV_DIR"
			mount --bind "$RESOLV_DIR" "$WORKDIR/@_new$RESOLV_DIR"
			mount --make-rslave "$WORKDIR/@_new$RESOLV_DIR"
			mount -o remount,bind,ro "$WORKDIR/@_new$RESOLV_DIR"
		fi
		;;
esac

# Keep boot loader installation off the EFI System Partition while staging.
# The ESP is shared with the running system, so anything written there takes
# effect immediately and cannot be undone by btrfs-rollback.sh.  The ESP is
# not mounted in the chroot, but the grub-efi and shim-signed postinst
# scripts call grub-multi-install / grub-install, which mount it through the
# bind-mounted /dev and install a GRUB whose prefix points at @_new.  That
# path no longer exists after the rename below, so the next boot would fail.
#
# Divert both tools to no-op stubs for the duration of the install.  The
# stubs record how they were called, so the same commands can be run after
# rebooting into the update.  dpkg honours the diversions, so new versions of
# the tools unpacked by this update land at the diverted path and are moved
# back when the diversions are removed.
ESP_TOOLS=(/usr/sbin/grub-install /usr/lib/grub/grub-multi-install)
ESP_LOG=/tmp/btrfs-deferred-update-esp.log	# path inside the snapshot

divert_esp_tools()
{
	local tool

	: > "$WORKDIR/@_new$ESP_LOG"
	for tool in "${ESP_TOOLS[@]}"; do
		chroot "$WORKDIR/@_new" dpkg-divert --quiet --local --rename \
			--divert "$tool.btrfs-deferred" --add "$tool"
		mkdir -p "$(dirname "$WORKDIR/@_new$tool")"
		cat > "$WORKDIR/@_new$tool" <<-EOF
		#!/bin/bash
		# Installed by btrfs-deferred-update.sh while an update is staged.
		{ printf '%q ' "$tool" "\$@"; echo; } >> "$ESP_LOG"
		echo "btrfs-deferred-update: not running $tool while staging" >&2
		exit 0
		EOF
		chmod 755 "$WORKDIR/@_new$tool"
	done
}

restore_esp_tools()
{
	local tool

	for tool in "${ESP_TOOLS[@]}"; do
		rm -f "$WORKDIR/@_new$tool"
		chroot "$WORKDIR/@_new" dpkg-divert --quiet --local --rename \
			--remove "$tool"
		# Remove the directory divert_esp_tools created for a tool that
		# is not installed.
		rmdir --ignore-fail-on-non-empty "$(dirname "$WORKDIR/@_new$tool")"
	done
}

divert_esp_tools

# Use noninteractive frontend and force-confold to prevent dpkg conffile
# prompts from blocking unattended runs.
export DEBIAN_FRONTEND=noninteractive
APT_OPTS=(-y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold")

# Install packages
if [ "$MODE" == "upgrade" ]; then
	echo "==> Running apt-get update in snapshot"
	chroot "$WORKDIR/@_new" apt-get update
	echo "==> Upgrading all packages in snapshot (dist-upgrade)"
	chroot "$WORKDIR/@_new" apt-get dist-upgrade "${APT_OPTS[@]}"
elif [ "$MODE" == "apt" ]; then
	shift
	echo "==> Running apt-get update in snapshot"
	chroot "$WORKDIR/@_new" apt-get update
	echo "==> Installing packages via apt-get: $*"
	chroot "$WORKDIR/@_new" apt-get install "${APT_OPTS[@]}" "$@"
else
	# Copy .deb files into the snapshot.  Pass their paths inside the
	# chroot explicitly: a glob here would be expanded by this shell on
	# the host, where /tmp/deferred-debs does not exist.
	DEB_DIR=/tmp/deferred-debs	# path inside the snapshot
	mkdir -p "$WORKDIR/@_new$DEB_DIR"
	CHROOT_DEBS=()
	for deb in "$@"; do
		cp "$deb" "$WORKDIR/@_new$DEB_DIR/"
		CHROOT_DEBS+=("$DEB_DIR/$(basename "$deb")")
	done
	echo "==> Installing .deb packages in snapshot"
	# dpkg -i fails when a dependency is missing.  Let apt-get install -f
	# resolve it, and then check that every package was installed.
	if ! chroot "$WORKDIR/@_new" dpkg --force-confdef --force-confold -i "${CHROOT_DEBS[@]}"; then
		echo "==> dpkg reported errors, resolving dependencies"
	fi
	chroot "$WORKDIR/@_new" apt-get install -f "${APT_OPTS[@]}"
	for deb in "${CHROOT_DEBS[@]}"; do
		pkg=$(dpkg-deb -f "$WORKDIR/@_new$deb" Package)
		ver=$(dpkg-deb -f "$WORKDIR/@_new$deb" Version)
		arch=$(dpkg-deb -f "$WORKDIR/@_new$deb" Architecture)
		if [ "$arch" != "all" ]; then
			pkg="$pkg:$arch"
		fi
		status=$(chroot "$WORKDIR/@_new" dpkg-query -W -f='${Status} ${Version}' "$pkg" 2>/dev/null || true)
		if [ "$status" != "install ok installed $ver" ]; then
			echo "ERROR: $(basename "$deb") was not installed (${status:-not found})" >&2
			exit 1
		fi
	done
	rm -rf "$WORKDIR/@_new$DEB_DIR"
fi

restore_esp_tools
ESP_SKIPPED=$(awk '!seen[$0]++' "$WORKDIR/@_new$ESP_LOG")
rm -f "$WORKDIR/@_new$ESP_LOG"

echo "==> Unmounting chroot binds"
umount_chroot

# Remove the directories created for the resolv.conf bind.  /run is a tmpfs
# on the running system, so they are not part of the update.
if [ -n "$RESOLV_DIR_CREATED" ]; then
	rm -rf --one-file-system "$WORKDIR/@_new$RESOLV_DIR_CREATED"
fi

# If update-grub ran inside the chroot, it saw the snapshot as subvolume
# @_new and may have written that path into grub.cfg (for example
# rootflags=subvol=@_new or /@_new/boot/...).  The snapshot is renamed to @
# below, so point those references at @.
GRUB_CFG="$WORKDIR/@_new/boot/grub/grub.cfg"
if [ -f "$GRUB_CFG" ] && grep -q '@_new\b' "$GRUB_CFG"; then
	echo "==> Updating subvolume references in /boot/grub/grub.cfg (@_new -> @)"
	sed -i 's/@_new\b/@/g' "$GRUB_CFG"
fi

# From here on, @_new holds the complete staged update.  Stop the failure
# cleanup from deleting it: if a rename below fails, @_new may be the only
# copy of the update, and the default subvolume still points at the
# running root, so the system is unaffected.
CREATED_NEW=0

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
if [ -n "$ESP_SKIPPED" ]; then
	echo "  - The update includes a boot loader update. It was not installed to"
	echo "    the EFI System Partition, which is shared with the running system."
	echo "    After rebooting into the update, install it with:"
	echo "$ESP_SKIPPED" | sed 's/^/      /'
	echo "    After that, a rollback restores the previous root file system but"
	echo "    not the previous boot loader."
fi
