#!/usr/bin/env python3
# ex:ts=4:sw=4:sts=4:et
# -*- tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*-
###############################################################################
#
# Copyright 2020 NVIDIA Corporation
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
import shutil
import yaml
import json
import glob
import time
import re
import errno
from ipaddress import ip_address, IPv4Address

__author__ = "Vladimir Sokolovsky <vlad@nvidia.com>"
__version__ = "1.0"

prog = os.path.basename(sys.argv[0])
os.environ['PATH'] = '/opt/mellanox/iproute2/sbin:/usr/sbin:/usr/bin:/sbin:/bin'

MLXREG = '/usr/bin/mlxreg'
SUPPORTED_OPERATIONS=['ipconfig', 'mtuconfig', 'gwconfig', 'dnsconfig', 'domainconfig', 'roceconfig', 'vlanconfig']
SUPPORTED_ACTIONS=['set', 'show']
EXTENDED_ACTIONS=['set', 'show', 'list', 'remove']
cloud_init_config = "/var/lib/cloud/seed/nocloud-net/network-config"
netplan_config = "/etc/netplan/60-mlnx.yaml"

network_config = netplan_config

network_config_orig = network_config + ".orig"
network_config_backup = network_config + ".bak"

resolv_conf = "/etc/resolv.conf"
resolv_conf_orig = "/etc/resolv.conf.orig"
verbose = 0

class BFCONFIG:
    def __init__ (self, args):
        self.device = args.device
        self.port = args.port
        self.op = args.op
        self.action = args.action
        self.verbose = args.verbose
        self.vlan = args.vlan
        self.vlan_dev = ""
        self.vlan_remove = 0
        self.result = {}
        self.result['op'] = self.op
        self.result['action'] = self.action
        self.result['status'] = 0
        self.result['output'] = ""

        if self.op == 'vlanconfig' and self.action == 'remove':
            self.op = 'ipconfig'
            self.action = 'set'
            self.vlan_remove = 1

        self.offset = 2
        self.devices = []
        if self.port:
            self.pci_devices = self.__get_pci_device__()
            if self.pci_devices:
                self.pci_device = self.pci_devices[0]
            if not self.device:
                self.offset = self.__get_offset__()
                self.devices = self.__get_device__()
                self.device = self.devices[0]
                self.roce_devices = self.__get_roce_device__()
                self.roce_device = self.roce_devices[0]

            self.vlan_dev = "{}.{}".format(self.device, self.vlan)

        if self.op in ['ipconfig', 'mtuconfig', 'gwconfig']:
            self.load_network_data()
            data = self.data['network']
            self.ipv4_prefix = args.ipv4_prefix
            self.ipv6_prefix = args.ipv6_prefix
            self.dhcp4 = False
            self.dhcp6 = False
            self.ipv4_addr = None
            self.ipv6_addr = None
    #        self.bootproto = None
            network_type = 'ethernets'
            if self.vlan == '-1':
                network_type = 'ethernets'
            else:
                network_type = 'vlans'

            if network_type in data:
                if self.device in data[network_type]:
                    if 'addresses' in data[network_type][self.device]:
                        for addr in data[network_type][self.device]['addresses']:
                            ip, prefix = addr.split('/')
                            if validIPAddress(ip) == 'IPv4':
                                self.ipv4_addr, self.ipv4_prefix = ip, prefix
                            if validIPAddress(ip) == 'IPv6':
                                self.ipv6_addr, self.ipv6_prefix = ip, prefix
                    if 'dhcp4' in data[network_type][self.device]:
                        self.ipv4_addr = "dhcp4"
                    if 'dhcp6' in data[network_type][self.device]:
                        self.ipv6_addr = "dhcp6"

            if args.ipv4_addr:
                if args.ipv4_addr == "dhcp":
                    self.dhcp4 = True
    #                self.bootproto = "dhcp"
                elif args.ipv4_addr == "0":
                    self.ipv4_addr = None
                    self.ipv4_prefix = None
                else:
                    self.ipv4_addr = args.ipv4_addr
    #                self.bootproto = "static"

            if args.ipv6_addr:
                if args.ipv6_addr == "dhcp":
                    self.dhcp6 = True
    #                self.bootproto = "dhcp"
                elif args.ipv6_addr == "0":
                    self.ipv6_addr = None
                    self.ipv6_prefix = None
                else:
                    self.ipv6_addr = args.ipv6_addr
    #                self.bootproto = "static"

    #        if args.bootproto:
    #            self.bootproto = args.bootproto

            self.ipv4_gateway = args.ipv4_gateway
            self.ipv6_gateway = args.ipv6_gateway
            self.network = args.network or '0.0.0.0'
            self.network_prefix = args.network_prefix or '0'
            self.metric = args.metric
            self.mtu = args.mtu
    #        self.nmcontrolled = args.nmcontrolled
    #        self.onboot = args.onboot

        if self.op in ['dnsconfig', 'domainconfig']:
            self.clean_domain = False
            self.ipv4_nameservers = []
            self.ipv6_nameservers = []
            self.searchdomains = []
            self.nameservers = []
            self.domains = []

            if self.op == "dnsconfig" and self.action == "set":
                if args.ipv4_nameservers:
                    for ipv4_nameserver in args.ipv4_nameservers:
                        if ',' in ipv4_nameserver[0]:
                            self.ipv4_nameservers.extend(ipv4_nameserver[0].split(','))
                        else:
                            self.ipv4_nameservers.append(ipv4_nameserver[0])

                if args.ipv6_nameservers:
                    for ipv6_nameserver in args.ipv6_nameservers:
                        if ',' in ipv6_nameserver[0]:
                            self.ipv6_nameservers.extend(ipv6_nameserver[0].split(','))
                        else:
                            self.ipv6_nameservers.append(ipv6_nameserver[0])

            if self.op == "domainconfig" and self.action == "set":
                self.clean_domain = True
                if args.domains != [['']]:
                    self.clean_domain = False
                    for domain in args.domains:
                        if ',' in domain[0]:
                            self.domains.extend(domain[0].split(','))
                        else:
                            if domain[0]:
                                self.domains.append(domain[0])

            try:
                # Read current configuration
                with open(resolv_conf, 'r') as stream:
                    for line in stream:
                        line = line.strip()
                        if line.startswith("search"):
                            self.searchdomains = line.split(' ')[1:]
                        elif line.startswith("nameserver"):
                            self.nameservers.append(line.split(' ')[1])
            except Exception as e:
                bf_log ("ERR: Failed to read configuration file {}. Exception: {}".format(resolv_conf, e))
                return None

        if self.op in ['vlanconfig'] and self.action in ['list']:
            self.load_network_data()

        if self.op in ['roceconfig']:
            self.type = args.type
            self.trust = args.trust
            self.ecn = []
            self.cable_len = args.cable_len
            self.dscp2prio = args.dscp2prio
            self.prio_tc = []
            self.pfc = []
            self.prio2buffer = []
            self.ratelimit = []
            self.buffer_size = []

            if args.ecn:
                for ecn in args.ecn:
                    if ',' in ecn[0]:
                        self.ecn.extend(ecn[0].split(','))
                    else:
                        self.ecn.append(ecn[0])

            if args.prio_tc:
                for prio_tc in args.prio_tc:
                    if ',' in prio_tc[0]:
                        self.prio_tc.extend(prio_tc[0].split(','))
                    else:
                        self.prio_tc.append(prio_tc[0])

            if args.pfc:
                for pfc in args.pfc:
                    if ',' in pfc[0]:
                        self.pfc.extend(pfc[0].split(','))
                    else:
                        self.pfc.append(pfc[0])

            if args.prio2buffer:
                for prio2buffer in args.prio2buffer:
                    if ',' in prio2buffer[0]:
                        self.prio2buffer.extend(prio2buffer[0].split(','))
                    else:
                        self.prio2buffer.append(prio2buffer[0])

            if args.ratelimit:
                for ratelimit in args.ratelimit:
                    if ',' in ratelimit[0]:
                        self.ratelimit.extend(ratelimit[0].split(','))
                    else:
                        self.ratelimit.append(ratelimit[0])

            if args.buffer_size:
                for buffer_size in args.buffer_size:
                    if ',' in buffer_size[0]:
                        self.buffer_size.extend(buffer_size[0].split(','))
                    else:
                        self.buffer_size.append(buffer_size[0])

        if self.op in ['vlanconfig']:
            self.skprio_up_egress = []
            self.up_skprio_ingress = []

            if args.skprio_up_egress:
                for skprio_up_egress in args.skprio_up_egress:
                    if ',' in skprio_up_egress[0]:
                        self.skprio_up_egress.extend(skprio_up_egress[0].split(','))
                    else:
                        self.skprio_up_egress.append(skprio_up_egress[0])

            if not len(self.skprio_up_egress):
                self.skprio_up_egress = ['0', '0', '0', '0', '0', '0', '0', '0']
            elif len(self.skprio_up_egress) != 8:
                self.result['status'] = 1
                self.result['output'] = "ERROR: Illegal skprio: {}. 8 skprio_up_egress priorities are expected"


            if args.up_skprio_ingress:
                for up_skprio_ingress in args.up_skprio_ingress:
                    if ',' in up_skprio_ingress[0]:
                        self.up_skprio_ingress.extend(up_skprio_ingress[0].split(','))
                    else:
                        self.up_skprio_ingress.append(up_skprio_ingress[0])

            if not len(self.up_skprio_ingress):
                self.up_skprio_ingress = ['0', '0', '0', '0', '0', '0', '0', '0']
            elif len(self.up_skprio_ingress) != 8:
                self.result['status'] = 1
                self.result['output'] = "ERROR: Illegal skprio: {}. 8 up_skprio_ingress priorities are expected"

            for prio in self.skprio_up_egress + self.up_skprio_ingress:
                if int(prio) > 7 or int(prio) < 0:
                    self.result['status'] = 1
                    self.result['output'] = "ERROR: Illegal skprio: {}. Legal range 0-7".format(prio)

        return

    def load_network_data(self):
        """
        Load data from netplan configuration file
        """
        self.data = {}
        try:
            with open(network_config, 'r') as stream:
                self.data = yaml.safe_load(stream)
        except Exception as e:
            bf_log ("ERR: Failed to load configuration file {}. Exception: {}".format(network_config, e))
        return

    def __get_pci_device__(self):
        """
        Get network device assosiated with the port
        """
        devices = []
        try:
            if self.port:
                cmd = "readlink -f /sys/class/infiniband/mlx5_{}/device".format(self.port)
            else:
                cmd = "readlink -f /sys/class/infiniband/mlx5_*"
            rc, output = get_status_output(cmd)
            for line in output.split('\n'):
                if line:
                    devices.append(line.split('/')[-1])
        except Exception as e:
            bf_log ("ERR: Port {} does not exist. Exception: {}".format(self.port, e))
            return None

        return devices

    def __get_offset__(self):
        mlnx_devs = self.pci_device[:-2]
        cmd = "lspci -s {} | wc -l".format(mlnx_devs)
        rc, output = get_status_output(cmd)
        if rc:
            return 2

        return output.strip()

    def __get_device__(self):
        """
        Get network device assosiated with the port
        """
        devices = []
        try:
            if self.port:
                # Map port to SF
                cmd = "/bin/ls -d /sys/class/net/*/device/infiniband/mlx5_{}".format(str(int(self.port) + int(self.offset)))
            else:
                cmd = "/bin/ls -d /sys/class/net/*/device/infiniband/mlx5_*"
            rc, output = get_status_output(cmd)
            for line in output.split('\n'):
                if line:
                    devices.append(line.split('/')[4])
        except Exception as e:
            bf_log ("ERR: Port {} does not exist. Exception: {}".format(self.port, e))
            return None

        return devices

    def __get_roce_device__(self):
        """
        Get network device assosiated with the port
        """
        devices = []
        try:
            cmd = "/bin/ls -d /sys/class/net/*/smart_nic/pf"
            rc, output = get_status_output(cmd)
            line = output.split('\n')[int(self.port)]
            if line:
                devices.append(line.split('/')[4])
        except Exception as e:
            bf_log ("ERR: Port {} does not exist. Exception: {}".format(self.port, e))
            return None

        return devices

    def show(self):
        """
        Show configurations
        """

        if self.op == 'vlanconfig':
            self.show_vlan_config()
            return

        if self.vlan == '-1':
            dev = self.device
            network_type = 'ethernets'
        else:
            dev = self.vlan_dev
            network_type = 'vlans'

        if self.op in ['ipconfig', 'mtuconfig', 'gwconfig']:
            data = {}
            data = self.data['network']

            if network_type not in data or dev not in data[network_type]:
                self.result['status'] = 1
                self.result['output'] = "ERR: Device {} does not exist.".format(dev)
                return

        if self.op == 'ipconfig':
            ipv4_addr=""
            ipv4_prefix=""
            ipv6_addr=""
            ipv6_prefix=""
            vlan="-1"
            link=""

            if dev in data[network_type]:
                if 'addresses' in data[network_type][dev]:
                    for addr in data[network_type][dev]['addresses']:
                        ip, prefix = addr.split('/')
                        if validIPAddress(ip) == 'IPv4':
                            ipv4_addr, ipv4_prefix = ip, prefix
                        if validIPAddress(ip) == 'IPv6':
                            ipv6_addr, ipv6_prefix = ip, prefix
                if 'dhcp4' in data[network_type][dev]:
                    ipv4_addr = "dhcp4"
                if 'dhcp6' in data[network_type][dev]:
                    ipv6_addr = "dhcp6"

            self.result['output'] = "ipv4_addr={}/ipv4_prefix={}/ipv6_addr={}/ipv6_prefix={}".format(ipv4_addr, ipv4_prefix, ipv6_addr, ipv6_prefix)

        elif self.op == 'mtuconfig':
            if dev in data[network_type]:
                if 'mtu' in data[network_type][dev]:
                    self.result['output'] = "mtu={}".format(data[network_type][dev]['mtu'])

            if 'mtu' not in self.result:
                mtu = get_mtu(dev)
                if mtu == 0:
                    bf_log ("ERR: Failed to get MTU for {} interface. RC={}".format(dev, rc))
                    self.result['status'] = rc
                    self.result['output'] = "ERR: Failed to get MTU for {} interface. RC={}".format(dev, rc)
                    return
                self.result['output'] = "mtu={}".format(str(mtu))

        elif self.op == 'gwconfig':
            ipv4_gateway = ""
            ipv6_gateway = ""
            if dev in data[network_type]:
                if 'routes' in data[network_type][dev]:
                    self.result['routes'] = data[network_type][dev]['routes']
                if 'gateway4' in data[network_type][dev]:
                    ipv4_gateway = data[network_type][dev]['gateway4']
                if 'gateway6' in data[network_type][dev]:
                    ipv6_gateway = data[network_type][dev]['gateway6']
            self.result['output'] = "ipv4_gateway={}/ipv6_gateway={}".format(ipv4_gateway, ipv6_gateway)

        elif self.op == 'dnsconfig':
            ipv4_nameservers = []
            ipv6_nameservers = []
            for nameserver in self.nameservers:
                if validIPAddress(nameserver) == 'IPv4':
                    ipv4_nameservers.append(nameserver)
                if validIPAddress(nameserver) == 'IPv6':
                    ipv6_nameservers.append(nameserver)
            self.result['output'] = "ipv4_nameservers={}/ipv6_nameservers={}".format(','.join(ipv4_nameservers), ','.join(ipv6_nameservers))

        elif self.op == 'domainconfig':
            self.result['output'] = "domains={}".format(','.join(self.searchdomains))

        elif self.op == 'roceconfig':
            trust = ""
            cable_len = ""
            prio_tc = ""
            prio_tc_arr = ['0','0','0','0','0','0','0','0']
            ecn = []
            pfc = ""
            prio2buffer = ""
            buffer_size = ""
            dscp2prio = ""
            ratelimit = ""
            ratelimit_arr = []
            roce_accl = []

            cmd = "bash -c 'mlnx_qos -i {} -a'".format(self.roce_device)
            rc, mlnx_qos_output = get_status_output(cmd, verbose)
            if rc:
                bf_log ("ERR: Failed to run mlnx_qos. RC={}\nOutput:\n{}".format(rc, mlnx_qos_output))
                self.result['status'] = rc
                self.result['output'] = "ERR: Failed to run mlnx_qos. RC={}\nOutput:\n{}".format(rc, mlnx_qos_output)
                return

            in_dscp2prio = 0
            dscp2prio_map = {}
            in_pfc_configuration = 0

            for i in range(8):
                dscp2prio_map[i] = ''

            for line in mlnx_qos_output.split('\n'):
                if 'Priority trust state:' in line:
                    trust = line.split(' ')[-1]
                elif 'Cable len:' in line:
                    cable_len = line.split(' ')[-1]
                elif 'Receive buffer size' in line:
                    buffer_size = line.split(':')[-1][1:-1]
                elif 'PFC configuration:' in line:
                    in_pfc_configuration = 1
                elif 'tc:' in line:
                    in_pfc_configuration = 0
                    info = re.search(r'tc:(.*?)ratelimit:(.*?)tsa:(.*?)$', line)
                    prio_tc = info.group(1).strip()
                    ratelimit_arr.append(info.group(2).strip().rstrip(','))
                elif in_pfc_configuration:
                    if 'enabled' in line:
                        pfc = ','.join(line.split())
                        pfc = ','.join(pfc.split(',')[1:])
                    elif 'buffer' in line:
                        prio2buffer = ','.join(line.split())
                        prio2buffer = ','.join(prio2buffer.split(',')[1:])
                elif 'dscp2prio mapping:' in line:
                    in_dscp2prio = 1
                elif 'default priority:' in line:
                    in_dscp2prio = 0
                elif in_dscp2prio:
                    prio = int(line.split(':')[1][0])
                    dscp2prio_map[prio] += str(''.join(line.split(':')[2:]))
                elif 'priority:' in line:
                    prio = int(line.split(':')[1].strip())
                    prio_tc_arr[prio] = prio_tc

            for i in range(8):
                if len(dscp2prio_map[i]):
                    dscp2prio += '{}'.format('{' + dscp2prio_map[i][:-1] + '},')
                else:
                    dscp2prio += '{}'.format('{},')

            dscp2prio = dscp2prio[:-1]
            ratelimit = ','.join(ratelimit_arr)
            prio_tc = ','.join(prio_tc_arr)

            cmd = "bash -c 'mlxreg -d {} --get --reg_name ROCE_ACCL'".format(self.pci_device)
            rc, mlxreg_output = get_status_output(cmd, verbose)
            if rc:
                bf_log ("ERR: Failed to run mlxreg. RC={}\nOutput:\n{}".format(rc, mlxreg_output))
                self.result['status'] = rc
                self.result['output'] = "ERR: Failed to run mlxreg. RC={}\nOutput:\n{}".format(rc, mlxreg_output)
                return

            for line in mlxreg_output.split('\n'):
                if 'roce' in line:
                    reg_name = line.split('|')[0].strip()
                    reg_data = line.split('|')[1].strip()
                    roce_accl.append("{}={}".format(reg_name, reg_data))

            for i in range(8):
                cmd = 'bash -c "cat /sys/class/net/{device}/ecn/roce_np/enable/{prio} 2> /dev/null"'.format(ecn=ecn, device=self.roce_device, prio=i)
                rc, ecn_output = get_status_output(cmd, verbose)
                if rc:
                    self.result['status'] = rc
                    self.result['output'] = "ERR: Failed to read ECN. RC={}\nOutput:\n{}".format(rc, ecn_output)
                    bf_log ("ERR: Failed to get ECN. RC={}\nOutput:\n{}".format(rc, ecn_output))
                    return

                ecn.append(ecn_output.strip())

            self.result['output'] = "trust={trust}/prio_tc={prio_tc}/ecn={ecn}/pfc={pfc}/cable_len={cable_len}/prio2buffer={prio2buffer}/buffer_size={buffer_size}/dscp2prio={dscp2prio}/ratelimit={ratelimit}/roce_accl={roce_accl}".format(trust=trust,prio_tc=prio_tc,ecn=','.join(ecn),pfc=pfc,cable_len=cable_len,prio2buffer=prio2buffer,buffer_size=buffer_size,dscp2prio=dscp2prio,ratelimit=ratelimit,roce_accl=','.join(roce_accl))

        return

    def set_netplan_dev_data(self):
        """
        Set device configuration to be used by netplan
        """

        cmd = None
        addr = None
        prefix = None
        dev = self.device
        dev_info = {}
        data = self.data['network']

        network_type = ""

        dev_info['renderer'] = "networkd"

        if self.vlan == '-1':
            network_type = "ethernets"
        else:
            dev = self.vlan_dev
            network_type = "vlans"
            dev_info['id'] = self.vlan
            dev_info['link'] = self.device
            if 'vlans' not in data:
                data['vlans'] = {}

        if self.op == "ipconfig":
            dev_info['addresses'] = []
            dev_info['dhcp4'] = None
            dev_info['dhcp6'] = None
        elif self.op == "gwconfig":
            dev_info['routes'] = []
            dev_info['gateway4'] = None
            dev_info['gateway6'] = None
        elif self.op == "mtuconfig":
            dev_info['mtu'] = None

        if dev in data[network_type]:
            if self.op in ['ipconfig', 'gwconfig']:
                if 'mtu' in data[network_type][dev]:
                    dev_info['mtu'] = data[network_type][dev]['mtu']
            if self.op in ['ipconfig', 'mtuconfig']:
                if 'routes' in data[network_type][dev]:
                    dev_info['routes'] = data[network_type][dev]['routes']
                if 'gateway4' in data[network_type][dev]:
                    dev_info['gateway4'] = data[network_type][dev]['gateway4']
                if 'gateway6' in data[network_type][dev]:
                    dev_info['gateway6'] = data[network_type][dev]['gateway6']
            if self.op in ['mtuconfig', 'gwconfig']:
                if 'addresses' in data[network_type][dev]:
                    dev_info['addresses'] = data[network_type][dev]['addresses']
                if 'dhcp4' in data[network_type][dev]:
                    dev_info['dhcp4'] = data[network_type][dev]['dhcp4']
                if 'dhcp6' in data[network_type][dev]:
                    dev_info['dhcp6'] = data[network_type][dev]['dhcp6']

        # Set configuration parameters
        if self.op == "ipconfig":
            if self.dhcp4:
                dev_info['dhcp4'] = "true"
            elif self.ipv4_addr:
                dev_info['addresses'].append("{}/{}".format(self.ipv4_addr, self.ipv4_prefix))

            if self.dhcp6:
                dev_info['dhcp6'] = "true"
            elif self.ipv6_addr:
                dev_info['addresses'].append("{}/{}".format(self.ipv6_addr, self.ipv6_prefix))

        if self.op == "mtuconfig":
            if self.mtu:
                dev_info['mtu'] = self.mtu

        if self.op == "gwconfig":
            if self.ipv4_gateway:
                if self.metric:
                    dev_info['routes'].append([{'metric': self.metric, 'to': "{}/{}".format(self.network, self.network_prefix), 'via': self.ipv4_gateway}])
                # elif self.network != '0.0.0.0' and self.network_prefix != '0':
                #     dev_info['routes'].append([{'to': "{}/{}".format(self.network, self.network_prefix), 'via': self.ipv4_gateway}])
                else:
                    dev_info['gateway4'] = self.ipv4_gateway

            if self.ipv6_gateway:
                if self.metric:
                    dev_info['routes'].append([{'metric': self.metric, 'to': "{}/{}".format(self.network, self.network_prefix), 'via': self.ipv6_gateway}])
                # elif self.network and self.network_prefix:
                #     dev_info['routes'].append([{'to': "{}/{}".format(self.network, self.network_prefix), 'via': self.ipv6_gateway}])
                else:
                    dev_info['gateway6'] = self.ipv6_gateway

        # Cleanup empty spaces
        if self.op == "ipconfig":
            if not len(dev_info['addresses']):
                del dev_info['addresses']
            if not dev_info['dhcp4']:
                del dev_info['dhcp4']
            if not dev_info['dhcp6']:
                del dev_info['dhcp6']
        elif self.op == "gwconfig":
            if not len(dev_info['routes']):
                del dev_info['routes']
            if not dev_info['gateway4']:
                del dev_info['gateway4']
            if not dev_info['gateway6']:
                del dev_info['gateway6']
        elif self.op == "mtuconfig":
            if not dev_info['mtu']:
                del dev_info['mtu']

        return dev_info

    def set_network_config(self):
        """
        Set configuration to be used by netplan
        """
        rc = 0
        cmd = None
        addr = None
        prefix = None
        dev = self.device
        vlan_dev = "{}.{}".format(self.device, self.vlan)
        conf_vlans = {}

        conf = self.data['network']['ethernets']
        if "vlans" in self.data['network']:
            conf_vlans = self.data['network']['vlans']

        if self.vlan == '-1':
            conf[dev] = self.set_netplan_dev_data()
            if len(conf[dev]):
                self.data['network']['ethernets'][dev] = conf[dev]
            else:
                if dev in self.data['network']['ethernets']:
                    del self.data['network']['ethernets'][dev]
        else:
            if 'vlans' not in self.data['network'] or vlan_dev not in self.data['network']['vlans']:
                if self.op in ['mtuconfig', 'gwconfig']:
                    self.result['status'] = 1
                    self.result['output'] = "ERR: VLAN interface {} does not exist".format(vlan_dev)
                    return 1

            if self.op == 'mtuconfig':
                parent_mtu = get_mtu(self.device)
                if parent_mtu < int(self.mtu):
                    self.result['status'] = 1
                    self.result['output'] = "ERR: Parent interface MTU should not be less than VLAN's MTU"
                    return 1

            if not self.vlan_remove:
                conf_vlans[vlan_dev] = self.set_netplan_dev_data()

            # VLAN configuration always includes 'id' and 'link' fields
            if not self.vlan_remove and len(conf_vlans[vlan_dev]) > 2:
                self.data['network']['vlans'][vlan_dev] = conf_vlans[vlan_dev]
            else:
                if "vlans" not in self.data['network']:
                    self.result['status'] = 1
                    self.result['output'] = "ERR: VLAN {} does not exist".format(vlan_dev)
                    return 1
                if vlan_dev in self.data['network']['vlans']:
                    del self.data['network']['vlans'][vlan_dev]
                    if len(self.data['network']['vlans']) == 0:
                        del self.data['network']['vlans']
                    cmd = "ip link delete link {} name {}".format(dev, vlan_dev)
                    rc, output = get_status_output(cmd, verbose)
                else:
                    self.result['status'] = 1
                    self.result['output'] = "ERR: VLAN {} does not exist".format(vlan_dev)
                    return 1

        try:
            with open(network_config, 'w') as stream:
                output = yaml.dump(self.data, stream, sort_keys=False)
        except:
            self.result['status'] = rc
            self.result['output'] = "ERR: Failed to write into configuration file {}".format(network_config)
            bf_log ("ERR: Failed to write into configuration file {}".format(network_config))

            return 1

        return rc

    def set_resolv_conf(self):
        # DNS configuration
        """
        Update /etc/resolv.conf directly
        """

        try:
            with open(resolv_conf, 'w') as stream:
                if not self.clean_domain:
                    if self.domains:
                        stream.write("search {}\n".format(' '.join(str(domain) for domain in self.domains)))
                    else:
                        if self.searchdomains:
                            stream.write("search {}\n".format(' '.join(str(domain) for domain in self.searchdomains)))

                if self.ipv4_nameservers or self.ipv6_nameservers:
                    if self.ipv4_nameservers:
                        for nameserver in self.ipv4_nameservers:
                            if nameserver:
                                stream.write("nameserver {}\n".format(str(nameserver)))
                    if self.ipv6_nameservers:
                        for nameserver in self.ipv6_nameservers:
                            if nameserver:
                                stream.write("nameserver {}\n".format(str(nameserver)))
                else:
                    if self.nameservers:
                        for nameserver in self.nameservers:
                            if nameserver.strip():
                                stream.write("nameserver {}\n".format(str(nameserver)))

        except Exception as e:
            self.result['status'] = rc
            self.result['output'] = "ERR: Failed to write to the configuration file {}. Exception: {}".format(resolv_conf, e)
            bf_log (self.result['output'])

        return


    def apply_config(self):
        cmd = "bash -c 'netplan apply'"
        rc, output = get_status_output(cmd, verbose)
        if rc or 'Error:' in output:
            if not rc:
                rc = 1
            self.result['status'] = 1
            self.result['output'] = "Failed to run netplan apply: {}".format(output)
            bf_log ("ERR: Failed to apply configuration. RC={}\nOutput:\n{}".format(rc, output))

        return rc

    def ip_config(self):
        """
        Construct and apply ip command like:
        ip address add dev tmfifo_net0 192.168.100.1/24"
        """
        rc = 0
        cmd = None

        if self.ipv4_addr:
            cmd = "ip address add dev {}".format(self.device)
            if self.ipv4_prefix:
                cmd += " {}/{}".format(self.ipv4_addr, self.ipv4_prefix)
            else:
                cmd += " {}".format(self.ipv4_addr)
            rc, output = get_status_output(cmd, verbose)
            if rc:
                bf_log ("ERR: Failed to configure IP address for {} interface. RC={}".format(self.device, rc))
                return rc

        if self.ipv6_addr:
            cmd = "ip address add dev {}".format(self.device)
            if self.ipv6_prefix:
                cmd += " {}/{}".format(self.ipv6_addr, self.ipv6_prefix)
            else:
                cmd += " {}".format(self.ipv6_addr)
            rc, output = get_status_output(cmd, verbose)
            if rc:
                bf_log ("ERR: Failed to configure IP address for {} interface. RC={}".format(self.device, rc))
                return rc

        # Set routing
        if self.network or self.ipv4_gateway or self.ipv6_gateway:
            if self.network:
                if self.ipv4_gateway:
                    cmd = "ip route add {}/{} via {}".format(self.network, self.network_prefix, self.ipv4_gateway)
                elif self.ipv6_gateway:
                    cmd = "ip route add {}/{} via {}".format(self.network, self.network_prefix, self.ipv6_gateway)
                else:
                    cmd = "ip route add {}/{} via {}".format(self.network, self.network_prefix, self.device)
            else:
                if self.ipv4_gateway:
                    cmd = "ip route add default gw {}".format(self.ipv4_gateway)
                elif self.ipv6_gateway:
                    cmd = "ip route add default gw {}".format(self.ipv6_gateway)

        if self.metric:
            cmd += " metric {}".format(self.metric)

        rc, output = get_status_output(cmd, verbose)
        if rc:
            bf_log ("ERR: Failed to configure gateway for {} interface. RC={}".format(self.device, rc))
            return rc

        if self.mtu:
            cmd = "ip link set {} mtu {}".format(self.device, self.mtu)
            rc, output = get_status_output(cmd, verbose)
            if rc:
                bf_log ("ERR: Failed to configure MTU for {} interface. RC={}".format(self.device, rc))
                return rc

        return rc

    def set_roce_config(self):
        """
        ROCE configuration
        """

        if not os.path.exists(MLXREG):
            self.result['status'] = 1
            self.result['output'] = "ERR: mlxreg tool does not exist. Cannot show/set RoCE configuration"
            bf_log(self.result['output'])
            return

        mlnx_qos_params = ""

        if self.ecn:
            i = 0
            for ecn in self.ecn:
                cmd = 'bash -c "echo {ecn} > /sys/class/net/{device}/ecn/roce_np/enable/{prio} || true; \
                                echo {ecn} > /sys/class/net/{device}/ecn/roce_rp/enable/{prio} || true"'.format(ecn=ecn, device=self.roce_device, prio=i)
                rc, ecn_output = get_status_output(cmd, verbose)
                if rc:
                    self.result['status'] = rc
                    self.result['output'] = "ERR: Failed to set ECN. RC={}\nOutput:\n{}".format(rc, ecn_output)
                    bf_log (self.result['output'])
                    return
                i += 1

        if self.type:
            if self.type == "lossy":
                cmd = 'bash -c "mlxreg -d {} --yes --reg_name ROCE_ACCL --set \"roce_adp_retrans_en=0x1,roce_tx_window_en=0x1,roce_slow_restart_en=0x1\""'.format(self.pci_device)
            else:
                cmd = 'bash -c "mlxreg -d {} --yes --reg_name ROCE_ACCL --set \"roce_adp_retrans_en=0x0,roce_tx_window_en=0x0,roce_slow_restart_en=0x0\""'.format(self.pci_device)
            rc, type_output = get_status_output(cmd, verbose)
            if rc:
                self.result['status'] = rc
                self.result['output'] = "ERR: Failed to run mlxreg. RC={}\nOutput:\n{}".format(rc, type_output)
                bf_log (self.result['output'])
                return

        if self.trust:
            mlnx_qos_params += " --trust {}".format(self.trust)

        if self.cable_len:
            mlnx_qos_params += " --cable_len {}".format(self.cable_len)

        if self.dscp2prio:
            mlnx_qos_params += " --dscp2prio {}".format(self.dscp2prio)

        if self.prio_tc:
            mlnx_qos_params += " --prio_tc {}".format(','.join(self.prio_tc))

        if self.pfc:
            mlnx_qos_params += " --pfc {}".format(','.join(self.pfc))

        if self.prio2buffer:
            mlnx_qos_params += " --prio2buffer {}".format(','.join(self.prio2buffer))

        if self.ratelimit:
            mlnx_qos_params += " --ratelimit {}".format(','.join(self.ratelimit))

        if self.buffer_size:
            mlnx_qos_params += " --buffer_size {}".format(','.join(self.buffer_size))

        if mlnx_qos_params:
            cmd = "bash -c 'mlnx_qos -i {} {}'".format(self.roce_device, mlnx_qos_params)
            rc, mlnx_qos_output = get_status_output(cmd, verbose)
            if rc:
                self.result['status'] = rc
                self.result['output'] = "ERR: Failed to run mlnx_qos. RC={}\nOutput:\n{}".format(rc, mlnx_qos_output)
                bf_log (self.result['output'])
                return

        return

    def set_vlan_config(self):
        """
        Set VLAN configuration
        """

        ip_cmd = "ip link set link {} name {} type vlan id {} ".format(self.device, self.vlan_dev, self.vlan)

        if self.skprio_up_egress:
            egress_cmd = ip_cmd + "egress-qos-map " + " ".join(["{}:{}".format(i,self.skprio_up_egress[i]) for i in range(len(self.skprio_up_egress))])
            rc, output = get_status_output(egress_cmd, verbose)
            if rc:
                self.result['status'] = rc
                self.result['output'] = output
                bf_log ("ERR: Failed to set skprio_up_egress. RC={}\nOutput:\n{}".format(rc, output))
                return

        if self.up_skprio_ingress:
            ingress_cmd = ip_cmd + "ingress-qos-map " + " ".join(["{}:{}".format(i,self.up_skprio_ingress[i]) for i in range(len(self.up_skprio_ingress))])
            rc, output = get_status_output(ingress_cmd, verbose)
            if rc:
                self.result['status'] = rc
                self.result['output'] = output
                bf_log ("ERR: Failed to set up_skprio_ingress. RC={}\nOutput:\n{}".format(rc, output))
                return

        return

    def show_vlan_config(self):
        """
        Show VLAN configuration
        """
        ip_cmd = "ip -json -details link show {} ".format(self.vlan_dev)
        rc, output = get_status_output(ip_cmd, verbose)
        if rc:
            self.result['status'] = rc
            self.result['output'] = output
            return

        egress_qos = ['0', '0', '0', '0', '0', '0', '0', '0']
        data = yaml.safe_load(output)[0]
        if 'egress_qos' in data['linkinfo']['info_data']:
            for key in data['linkinfo']['info_data']['egress_qos']:
                egress_qos[key['from']] = str(key['to'])

        self.result['output'] = 'skprio_up_egress='
        self.result['output'] += ','.join(egress_qos)

        cmd = "grep ^INGRESS /proc/net/vlan/{} | cut -d ':' -f 2- | sed -e 's/[0-9]://g' | sed -e 's/^ *//' | sed -r 's/[[:space:]]+/,/g' | tr -d '\n'".format(self.vlan_dev)
        rc, output = get_status_output(cmd, verbose)
        if rc:
            self.result['status'] = rc
            self.result['output'] = output.strip()
            return

        self.result['output'] += '/up_skprio_ingress={}'.format(output)
        return

    def list_vlans(self):
        """
        List VLANs
        """
        list = []
        if 'vlans' in self.data['network']:
            for vlan_dev in self.data['network']['vlans']:
                if self.data['network']['vlans'][vlan_dev]['link'] == self.device:
                    list.append(self.data['network']['vlans'][vlan_dev]['id'])

            self.result['output'] = ','.join(list)


def version():
    """Display program version information."""
    print(prog + ' ' + __version__)


def get_status_output(cmd, verbose=False):
    rc, output = (0, '')

    if verbose:
        print("Running command:", cmd)

    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT,
                                         shell=True, universal_newlines=True)
    except subprocess.CalledProcessError as e:
        rc, output = (e.returncode, e.output.strip())

    if rc and verbose:
        print("Running {} failed (error[{}])".format(cmd, rc))

    if verbose:
        print("Output:\n", output)

    return rc, output


def bf_log(msg, level=verbose):
    if level:
        print(msg)
    cmd = "logger -t {} -i '{}'".format(prog, msg)
    get_status_output(cmd, False)
    return 0


def check_domain(domain):
    if len(domain) > 63 or len(domain) < 2:
        return 1
    pattern = r'[^\.a-z0-9\-]'
    if re.search(pattern, domain):
        return 1
    return 0


def verify_args(args):
    rc = 0
    msg = ""
    supported_actions = SUPPORTED_ACTIONS
    if (args.op not in SUPPORTED_OPERATIONS):
        msg = "ERROR: Operation {} is not supported".format(args.op)
        rc = 1
    if args.op == 'vlanconfig':
        supported_actions = EXTENDED_ACTIONS
        if args.vlan == '-1' and args.action in ['set', 'show', 'remove']:
            msg = "ERROR: VLAN have to be provided. Use '--vlan'"
            rc = 1

    if (args.action not in supported_actions):
        msg = "ERROR: Action {} is not supported by operation {}".format(args.action, args.op)
        rc = 1
    if args.op not in ['dnsconfig', 'domainconfig'] and not args.port:
        msg = "ERROR: Port number have to be provided. Use '--port'"
        rc = 1

    if args.op == 'mtuconfig' and args.action == 'set' and not args.mtu:
        msg = "ERROR: MTU have to be provided. Use '--mtu'"
        rc = 1

    if args.domains:
        for domain in args.domains:
            if ',' in domain[0]:
                for domain in domain[0].split(','):
                    if check_domain(domain):
                        msg = "ERROR: Domain name is invalid"
                        rc = 1
            else:
                if len(domain[0]) != 0 and check_domain(domain[0]):
                    msg = "ERROR: Domain name is invalid"
                    rc = 1

    if args.ipv4_addr and args.ipv4_addr not in ['dhcp', '0']:
        if validIPAddress(args.ipv4_addr) == 'Invalid':
            msg = "ERROR: ipv4_addr is invalid"
            rc = 1
        if not args.ipv4_prefix:
            msg = "ERROR: ipv4_prefix is required"
            rc = 1

    if args.ipv6_addr and args.ipv6_addr not in ['dhcp', '0']:
        if validIPAddress(args.ipv6_addr) == 'Invalid':
            msg = "ERROR: ipv6_addr is invalid"
            rc = 1
        if not args.ipv6_prefix:
            msg = "ERROR: ipv6_prefix is required"
            rc = 1

    if args.network:
        if validIPAddress(args.network) == 'Invalid':
            msg = "ERROR: network is invalid"
            rc = 1

    if args.ipv4_gateway:
        if validIPAddress(args.ipv4_gateway) == 'Invalid':
            msg = "ERROR: ipv4_gateway is invalid"
            rc = 1

    if args.ipv6_gateway:
        if validIPAddress(args.ipv6_gateway) == 'Invalid':
            msg = "ERROR: ipv6_gateway is invalid"
            rc = 1

    return rc, msg

def get_mtu(dev):
    cmd = "cat /sys/class/net/{}/mtu".format(dev)
    rc, mtu = get_status_output(cmd, verbose)
    if rc:
        bf_log ("ERR: Failed to get MTU for {} interface. RC={}".format(dev, rc))
        return 0
    return int(mtu.strip())

def validIPAddress(IP: str) -> str:
    try:
        return "IPv4" if type(ip_address(IP)) is IPv4Address else "IPv6"
    except ValueError:
        return "Invalid"


def netmask_to_prefix(netmask):
    """
    Convert NETMASK to PREFIX
    """
    return(sum([ bin(int(bits)).count("1") for bits in netmask.split(".") ]))


def main():

    global verbose
    rc = 0
    result = {"status": 0, "output": ""}

    if os.geteuid() != 0:
        sys.exit('root privileges are required to run this script!')

    parser = argparse.ArgumentParser(description='Configure network interfaces')
#    parser.add_argument('--permanent', action='store_true', help="Keep network configuration permanent", default=True)
    parser.add_argument('--op', required='--version' not in sys.argv, choices=SUPPORTED_OPERATIONS, help="Operation")
    parser.add_argument('--device', help="Network device name")
    parser.add_argument('--action', required='--version' not in sys.argv, choices=EXTENDED_ACTIONS, help="Action")
    parser.add_argument('--get_devices', action='store_true', help="Print network interface bound to the provided port", default=False)
    parser.add_argument('--port', required='--get-devices' in sys.argv, choices=['0', '1'], help="HCA port 0|1")
    parser.add_argument('--ipv4_addr', help="IPv4 address")
    parser.add_argument('--ipv4_prefix', help="Network prefix for IPv4 address.")
    parser.add_argument('--ipv6_addr', help="IPv6 address")
    parser.add_argument('--ipv6_prefix', help="Network prefix for IPv6 address.")
    parser.add_argument('--network', help="Subnet network")
    parser.add_argument('--network_prefix', help="PREFIX to use with route add", default=0)
    parser.add_argument('--ipv4_gateway', help="IPv4 gateway address")
    parser.add_argument('--ipv6_gateway', help="IPv6 gateway address")
    parser.add_argument('--metric', help="Metric for the default route using ipv4_gateway")
#    parser.add_argument('--bootproto', help="BOOTPROTO=none|static|bootp|dhcp")
    parser.add_argument('--mtu', help="Default MTU for this device")
#    parser.add_argument('--nmcontrolled', help="NMCONTROLLED=yes|no")
    parser.add_argument('--ipv4_nameservers', action='append', nargs='+', help="DNS server IP. Use multiple times for the list of DNS servers")
    parser.add_argument('--ipv6_nameservers', action='append', nargs='+', help="DNS server IP. Use multiple times for the list of DNS servers")
    parser.add_argument('--domains', action='append', nargs='+', help="Search domain name. Use multiple times for the list of domains")
    parser.add_argument('--type', choices=['lossy', 'lossless'], help="RoCE type")
    parser.add_argument('--trust', choices=['pcp', 'dscp'], help="RoCE trust")
    parser.add_argument('--ecn', action='append', nargs='+', help="enable/disable ECN for priority. Use multiple times")
    parser.add_argument('--dscp2prio', help="RoCE set/del a (dscp,prio) mapping. e.g: 'del,30,2'.")
    parser.add_argument('--prio_tc', action='append', nargs='+', help="RoCE priority to traffic class mapping. Use multiple times")
    parser.add_argument('--pfc', action='append', nargs='+', help="RoCE priority to traffic class. Use multiple times")
    parser.add_argument('--cable_len',  help="Len for buffer's xoff and xon thresholds calculation")
    parser.add_argument('--prio2buffer', action='append', nargs='+', help="Priority to receive buffer. Use multiple times")
    parser.add_argument('--ratelimit', action='append', nargs='+', help="Rate limit per traffic class (in Gbps). Use multiple times")
    parser.add_argument('--buffer_size', action='append', nargs='+', help="Receive buffer size. Use multiple times")
    parser.add_argument('--roce_accl', action='append', nargs='+', help="field=value advanced accelerations. Use multiple times")
    parser.add_argument('--skprio_up_egress', action='append', nargs='+', help="Outbound sk_prio to UP priority mapping. Use multiple times")
    parser.add_argument('--up_skprio_ingress', action='append', nargs='+', help="Inbound UP priority to sk_prio mapping. Use multiple times")
    parser.add_argument('--show',  help="Show parameter value")
    parser.add_argument('--vlan', help="vlan id", default='-1')
#    parser.add_argument('--onboot', help="ONBOOT 'yes' or 'no'", default='yes')
    parser.add_argument('--verbose', action='store_true', help="Print verbose information", default=False)
    parser.add_argument('--version', action='store_true', help='Display program version information and exit')


    args = parser.parse_args()
    if args.version:
        version()
        sys.exit(rc)

    verbose = args.verbose
    if verbose:
        print(args)

    rc, msg = verify_args(args)
    if rc:
        result['op'] = args.op
        result['action'] = args.action
        result['output'] = msg
        result['status'] = rc
        print(json.dumps(result, indent=None))
        bf_log(result['output'])
        sys.exit(rc)

    bfconfig = BFCONFIG(args)
    if bfconfig.result['status']:
        print(json.dumps(bfconfig.result, indent=None))
        sys.exit(bfconfig.result['status'])

    if args.get_devices:
        print (bfconfig.devices)
        sys.exit(0)

    if bfconfig.action == 'show':
        bfconfig.show()
        result = bfconfig.result
        print(json.dumps(result, indent=None))
        sys.exit(result['status'])

    # TBD:
    # Add restore factory default parameter
    # nmcontrolled
    # ipv4_nameservers
    # search
    # vlan
    # RoCE
    # Exit if restricted host

    if not os.path.exists(network_config):
        result['op'] = args.op
        result['action'] = args.action
        result['output'] = "ERROR: network configuration file {} does not exist".format(network_config)
        result['status'] = 1
        bf_log(result['output'], 1)
        sys.exit(1)

    if not os.path.exists(network_config_orig):
        shutil.copy2(network_config, network_config_orig)

    shutil.copy2(network_config, network_config_backup)

    if not os.path.exists(resolv_conf_orig):
        shutil.copy2(resolv_conf, resolv_conf_orig)

    if args.verbose:
        print ("Operation: ", args.op)

    if bfconfig.op in ['ipconfig', 'mtuconfig', 'gwconfig']:
        rc = bfconfig.set_network_config()
        if rc:
            result = bfconfig.result
            print(json.dumps(result, indent=None))
            sys.exit(result['status'])

        rc = bfconfig.apply_config()
        if rc:
            bf_log("Reverting configuration")
            shutil.copy2(network_config, network_config + ".bad")
            shutil.copy2(network_config_backup, network_config)
            rc1 = bfconfig.apply_config()
            if rc1:
                bf_log("Restoring factory default configuration")
                shutil.copy2(network_config_orig, network_config)
                rc2 = bfconfig.apply_config()
                if rc2:
                    bf_log("ERR: Failed to restore factory default configuration")

    elif bfconfig.op in ['dnsconfig', 'domainconfig']:
        bfconfig.set_resolv_conf()

    elif bfconfig.op in ['roceconfig']:
        bfconfig.set_roce_config()

    elif bfconfig.op in ['vlanconfig']:
        if bfconfig.action == 'set':
            bfconfig.set_vlan_config()

        elif bfconfig.action == 'list':
            bfconfig.list_vlans()

    result = bfconfig.result
    print(json.dumps(result, indent=None))
    if result['status']:
        sys.exit(result['status'])

    sys.exit(rc)


if __name__ == '__main__':
        main()
