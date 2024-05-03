#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import re
from netmiko.ssh_dispatcher import HuaweiSSH, HPComwareSSH


class CustomHuaweiSSH(HuaweiSSH):
    def enable(self, cmd="system-view", ):
        """enable mode on huawei is system-view."""
        return self.config_mode(config_command=cmd)
