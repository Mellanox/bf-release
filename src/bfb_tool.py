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
import errno
import bfb_admin

__author__ = "Vladimir Sokolovsky <vlad@nvidia.com>"
__version__ = "1.0"

prog = "bfb_tool"
os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'

SUPPORTED_OPERATIONS=["fw_get_bfb_info", "fw_activate_bfb", "fw_get_caps", "fw_recover"]
verbose = 0

def version():
    """Display program version information."""
    print(prog + '-' +  __version__)


def verify_args(args):
    ret = {
        "success": True,
        "output": ""
    }

    if (args.op not in SUPPORTED_OPERATIONS):
        ret["output"] = "ERROR: Operation {} is not supported".format(args.op)
        ret["success"] = False
    if args.op in ["fw_get_bfb_info", "fw_activate_bfb"] and not args.bfb:
        ret["output"] = "ERROR: Path to the BFB file should be proovided. Use '--bfb'"
        ret["success"] = False

    return json.dumps(ret)


def main():

    global verbose
    rc = 0
    ret = {"success": True, "output": ""}

    if os.geteuid() != 0:
        sys.exit('root privileges are required to run this script!')

    parser = argparse.ArgumentParser(description='BFB admin')
    parser.add_argument('--op', required=True, choices=SUPPORTED_OPERATIONS, help="Operation")
    parser.add_argument('--bfb', help="path to the BFB file")
    parser.add_argument('--now', action='store_true', help="Activate BFB now", default=False)
    parser.add_argument('--verbose', action='store_true', help="Print verbose information", default=False)
    parser.add_argument('--version', action='store_true', help='Display program version information and exit')


    args = parser.parse_args()
    if args.version:
        version()
        sys.exit(rc)

    verbose = args.verbose
    if verbose:
        print(args)

    if args.verbose:
        print ("Operation: ", args.op)

    ret = json.loads(verify_args(args))
    if ret["success"] == False:
        rc = 1

    if rc:
        bfb_admin.bf_log(ret["output"], prog, rc)
        sys.exit(rc)

    if args.op == 'fw_get_bfb_info':
        ret = json.loads(bfb_admin.fw_get_bfb_info(args.bfb))

    elif args.op == 'fw_activate_bfb':
        ret = json.loads(bfb_admin.fw_activate_bfb(args.bfb, args.now))

    elif args.op == 'fw_get_caps':
        ret = json.loads(bfb_admin.fw_get_caps())

    elif args.op == 'fw_recover':
        ret = json.loads(bfb_admin.fw_recover())

    if ret["success"] == False:
        rc = 1

    print(ret)

    sys.exit(rc)


if __name__ == '__main__':
        main()
