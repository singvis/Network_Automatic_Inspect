#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import re

from collections import OrderedDict
from netmiko.snmp_autodetect import SNMPDetect

# 华为有VRP和YunShan两个操作系统
SNMP_MAPPER_BASE = OrderedDict({
    "hp_comware": {
        "oid": ".1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r".*H3C Comware.*", re.IGNORECASE),
    },
    "huawei_vrpv8": {
        "oid": ".1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r".*VRP\s+\(R\)\s+software,\s*Version\s+8.*", re.IGNORECASE),
    },
    "huawei": {
        "oid": ".1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r"(.*VRP\s+\(R\)\s+software,\s*Version.*)|(.*Huawei\s+YunShan\s+OS.*)", re.IGNORECASE),
    },
    "cisco_ios": {
        "oid": ".1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r".*Cisco IOS Software,.*", re.IGNORECASE),
    },
    "cisco_xe": {
        "oid": ".1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r".*IOS-XE Software,.*", re.IGNORECASE),
    },
    "cisco_xr": {
        "oid": ".1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r".*Cisco IOS XR Software.*", re.IGNORECASE),
    },
    "cisco_asa": {
        "oid": ".1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r".*Cisco Adaptive Security Appliance.*", re.IGNORECASE),
    },
    "cisco_nxos": {
        "oid": ".1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r".*Cisco NX-OS.*", re.IGNORECASE),
    },
    "cisco_wlc": {
        "oid": ".1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r".*Cisco Controller.*", re.IGNORECASE),
    },
    "fortinet": {
        "oid": ".1.3.6.1.4.1.12356.100.1.1.1.0",  # 修改源码飞塔OID，原获取null
        "expr": re.compile(r"FG.*", re.IGNORECASE),
    },
    "juniper_junos": {
        "oid": ".1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r".*Juniper.*"),
    },
    "paloalto_panos": {
        "oid": ".1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r".*Palo Alto Networks.*", re.IGNORECASE),
    },
    "f5_tmsh": {
        "oid": ".1.3.6.1.4.1.3375.2.1.4.1.0",
        "expr": re.compile(r".*BIG-IP.*", re.IGNORECASE),
    },
    "arista_eos": {
        "oid": ".1.3.6.1.2.1.1.1.0",
        "expr": re.compile(r".*Arista Networks EOS.*", re.IGNORECASE),
    },

})


class MySNMPDetect(SNMPDetect):
    def autodetect(self):
        """
        此方法重写
        """
        for device_type, v in SNMP_MAPPER_BASE.items():
            oid = v["oid"]
            regex = v["expr"]

            snmp_response = self._get_snmp(oid)

            # See if we had a match
            if re.search(regex, snmp_response):
                return device_type

        return None


if __name__ == '__main__':
    snmp = MySNMPDetect(hostname='192.168.0.11', community='cisco', snmp_version='v2c').autodetect()
    print(snmp)
