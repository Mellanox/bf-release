#!/usr/bin/env python3
# ex:ts=4:sw=4:sts=4:et
# -*- tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*-
###############################################################################
#
# Copyright 2021 NVIDIA Corporation
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


import os
import sys
import argparse
import subprocess
import tempfile
import shutil
import json
import glob
import time
import re
import hashlib
import errno

__author__ = "Vladimir Sokolovsky <vlad@nvidia.com>"
__version__ = "1.0"

os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'

verbose = False

def get_status_output(cmd, verbose=False):
    rc, output = (0, '')

    if verbose:
        bf_log("Running command:", cmd)

    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT,
                                         shell=True, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        rc, output = (e.returncode, e.output.strip())

    if rc and verbose:
        bf_log("Running {} failed (error[{}])".format(cmd, rc))

    if verbose:
        bf_log("Output:\n", output)

    return rc, output


def get_other_root_dev():
    major, minor = divmod(os.stat('/').st_dev, 256)

    if minor == 2:
        return "4"
    else:
        return "2"


def get_checksum(filename):
    hash = "invalid"
    try:
        with open(filename, "rb") as f:
            bytes = f.read()
            hash = hashlib.sha256(bytes).hexdigest()
    except IOError as e:
        bf_log("I/O error({0}): {1}".format(e.errno, e.strerror))
    except FileNotFoundError:
        bf_log("ERROR: File {} does not exist".format(filename))
    except:
        bf_log("Unexpected error:", sys.exc_info()[0])
    return hash


def bf_log(msg, prog="bfb_admin.py", level=verbose):
    if level:
        print(msg)
    cmd = "logger -t {} -i '{}'".format(prog, msg)
    get_status_output(cmd, False)
    return 0


def fw_recover():
    ret = {
        "success": True,
    }
    cmd = "/opt/mellanox/mlnx-fw-updater/mlnx_fw_updater.pl \
                --force-fw-update \
                --fw-dir /opt/mellanox/mlnx-fw-updater/firmware/"
    rc, output = get_status_output(cmd, False)
    if rc:
        ret["success"] = False

    return json.dumps(ret)


def fw_get_bfb_info(filename):
    current_versions = {}
    ret = {
        "success": False,
        "valid": False,
        "version": "",
        "os": "",
        "krnl": "",
        "fw": "",
        "fw-current": "",
        "spdk": "",
        "lsnap": "",
        "next": False,
        "active": False
    }
    fw_current = ""

    cmd = "flint -d /dev/mst/mt*_pciconf0 -qq q | grep 'FW Version' | awk '{print $NF}' | tail -1"
    rc, output = get_status_output(cmd, False)
    if not rc:
        fw_current = output.strip()

    ret["fw-current"] = fw_current

    if os.path.exists(filename):
        ret["success"] = True
    else:
        bf_log("ERROR: File {} does not exist".format(filename))
        return json.dumps(ret)

    if os.path.exists("/etc/bfb_version.json"):
        with open("/etc/bfb_version.json", encoding='utf-8') as versions:
            current_versions = json.load(versions)

    file_checksum = get_checksum(filename)
    if os.path.exists(filename + ".sha256sum"):
        with open(filename + ".sha256sum", "r") as f:
            cached_checksum = f.read()
        if file_checksum != cached_checksum:
            os.remove(filename + ".sha256sum")
            if os.path.exists(filename + ".versions"):
                os.remove(filename + ".versions")
            with open(filename + ".sha256sum", "w") as f:
                f.write(file_checksum)
    else:
        if os.path.exists(filename + ".versions"):
            os.remove(filename + ".versions")

        with open(filename + ".sha256sum", "w") as f:
            f.write(file_checksum)

    if not os.path.exists(filename + ".versions"):
        dirpath = tempfile.mkdtemp()
        cmd = "cd {d}; \
                mlx-mkbfb -x {f}; \
                mkdir initramfs; \
                cd initramfs; \
                gzip -d < ../dump-initramfs-v0 | cpio -id; \
                cd ubuntu; \
                tar xJf image.tar.xz ./etc/bfb_version.json; \
                mv ./etc/bfb_version.json {f}.versions".format(d=dirpath, f=filename)
        rc, output = get_status_output(cmd, False)
        shutil.rmtree(dirpath)
        if rc:
            if verbose:
                print(output)
            return json.dumps(ret)

    if os.path.exists(filename + ".versions"):
        with open(filename + ".versions", encoding='utf-8') as bfb_versions:
            ret = json.load(bfb_versions)
            ret["fw-current"] = fw_current
            if "version" in ret:
                ret["valid"] = True

                if "version" in current_versions:
                    if ret["version"] == current_versions["version"]:
                        ret["active"] = True
                        if "next" in current_versions:
                            ret["next"] = current_versions["next"]
                        return json.dumps(ret)
                    else:
                        ret["active"] = False
                        # Check other rootfs
                        other_root_dev = get_other_root_dev()
                        if os.path.exists(f"/common/{other_root_dev}.version.json"):
                            with open(f"/common/{other_root_dev}.version.json", encoding='utf-8') as other:
                               other_versions = json.load(other)
                               if "version" in other_versions:
                                   if ret["version"] == other_versions["version"]:
                                       ret["next"] = True
                                   else:
                                       ret["next"] = False

    return json.dumps(ret)


def fw_activate_bfb(filename, now):            
    current_versions = {}
    ret = {
        "success": False,
        "reset_required": False
    }

    if not os.path.exists(filename):
        return json.dumps(ret)

    dirpath = tempfile.mkdtemp()
    cmd = "cd {d}; \
            mlx-mkbfb -x {f}; \
            mkdir initramfs; \
            cd initramfs; \
            gzip -d < ../dump-initramfs-v0 | cpio -id; \
            ln -snf `pwd`/ubuntu /ubuntu; \
            /ubuntu/install.sh; \
            /bin/rm -f /ubuntu".format(d=dirpath, f=filename)
    rc, output = get_status_output(cmd, False)
    shutil.rmtree(dirpath)
    if rc:
        if verbose:
            print(output)
        return json.dumps(ret)

    ret = {
        "success": True,
        "reset_required": True
    }

    # NIC FW update
    dirpath = tempfile.mkdtemp()
    other_root_dev = get_other_root_dev()
    cmd = "mount /dev/mmcblk0p{p} {m}; \
            {m}/opt/mellanox/mlnx-fw-updater/mlnx_fw_updater.pl \
                --force-fw-update \
                --fw-dir {m}/opt/mellanox/mlnx-fw-updater/firmware/; \
                umount {m}".format(p=other_root_dev, m=dirpath)
    rc, output = get_status_output(cmd, False)
    shutil.rmtree(dirpath)

    if os.path.exists("/etc/bfb_version.json"):
        with open("/etc/bfb_version.json", encoding='utf-8') as versions:
            current_versions = json.load(versions)
            current_versions["next"] = False

        with open("/etc/bfb_version.json", 'w') as versions:
            json.dump(current_versions, versions)

    return json.dumps(ret)


def fw_get_caps():            
    ret = {
        "success": True,
        "bfb_activate": True
    }
    return json.dumps(ret)
