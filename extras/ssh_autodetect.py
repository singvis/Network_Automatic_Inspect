#!/usr/bin/env python3
# -*- coding:utf-8 -*-
"""
Author：Singvis
微信公众号: 点滴技术
B站：点滴技术
"""

from netmiko.ssh_autodetect import SSHDetect

# 按需增加
SSH_MAPPER_BASE = {
    "hp_comware": {
        "cmd": "display version",
        "search_patterns": ["H3C Comware"],
        "priority": 99,
        "dispatch": "_autodetect_std",
    },
    "huawei": {
        "cmd": "display version",
        "search_patterns": [
            r"Huawei Technologies",
            r"Huawei Versatile Routing Platform Software",
        ],
        "priority": 99,
        "dispatch": "_autodetect_std",
    },
    "cisco_ios": {
        "cmd": "show version",
        "search_patterns": [
            "Cisco IOS Software",
            "Cisco Internetwork Operating System Software",
        ],
        "priority": 99,
        "dispatch": "_autodetect_std",
    },
    "cisco_nxos": {
        "cmd": "show version",
        "search_patterns": [r"Cisco Nexus Operating System", r"NX-OS"],
        "priority": 99,
        "dispatch": "_autodetect_std",
    },
    "cisco_xr": {
        "cmd": "show version",
        "search_patterns": [r"Cisco IOS XR"],
        "priority": 99,
        "dispatch": "_autodetect_std",
    },
    "cisco_wlc": {
        "cmd": "",
        "dispatch": "_autodetect_remote_version",
        "search_patterns": [r"CISCO_WLC"],
        "priority": 99,
    },
    "cisco_asa": {
        "cmd": "show version",
        "search_patterns": [r"Cisco Adaptive Security Appliance", r"Cisco ASA"],
        "priority": 99,
        "dispatch": "_autodetect_std",
    },
    "arista_eos": {
        "cmd": "show version",
        "search_patterns": [r"Arista"],
        "priority": 99,
        "dispatch": "_autodetect_std",
    },
    "f5_tmsh": {
        "cmd": "show sys version",
        "search_patterns": [r"BIG-IP"],
        "priority": 99,
        "dispatch": "_autodetect_std",
    },
    "f5_linux": {
        "cmd": "cat /etc/issue",
        "search_patterns": [r"BIG-IP"],
        "priority": 99,
        "dispatch": "_autodetect_std",
    },
    "juniper_junos": {
        "cmd": "show version",
        "search_patterns": [
            r"JUNOS Software Release",
            r"JUNOS .+ Software",
            r"JUNOS OS Kernel",
            r"JUNOS Base Version",
        ],
        "priority": 99,
        "dispatch": "_autodetect_std",
    },
    "fortinet": {
        "cmd": "get system status",
        "search_patterns": [r"FortiOS"],
        "priority": 99,
        "dispatch": "_autodetect_std",
    },
    "paloalto_panos": {
        "cmd": "show system info",
        "search_patterns": [r"model:\s+PA"],
        "priority": 99,
        "dispatch": "_autodetect_std",
    },
}

# Sort SSH_MAPPER_BASE such that the most common commands are first
cmd_count = {}
for k, v in SSH_MAPPER_BASE.items():
    count = cmd_count.setdefault(v["cmd"], 0)
    cmd_count[v["cmd"]] = count + 1
cmd_count = {k: v for k, v in sorted(cmd_count.items(), key=lambda item: item[1])}

# SSH_MAPPER_BASE will be a list after this
SSH_MAPPER_BASE = sorted(
    SSH_MAPPER_BASE.items(), key=lambda item: int(cmd_count[item[1]["cmd"]])
)
SSH_MAPPER_BASE.reverse()


class MySSHDetect(SSHDetect):
    """
    主要是重写SSH_MAPPER_BASE变量
    """
    SSH_MAPPER_BASE = SSH_MAPPER_BASE

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
