#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import re
from netmiko.fortinet import FortinetSSH


class MyFortinetSSH(FortinetSSH):
    """重写了FortinetSSH类"""

    # 因为通过ftp备份配置，不需要关闭分屏
    # 多vdom场景下，需要进入global模式，需要有一些权限权限，可以备份多个vdom的配置
    def disable_paging(self, delay_factor=1, **kwargs):
        check_command = "get system status | grep Virtual"
        output = self.send_command_timing(check_command)
        self.allow_disable_global = True
        self.vdoms = False
        self._output_mode = "more"

        if re.search(r"Virtual domain configuration: (multiple|enable)", output):
            self.vdoms = True
            vdom_additional_command = "config global"
            output = self.send_command_timing(vdom_additional_command, delay_factor=2)
            if "Command fail" in output:
                self.allow_disable_global = False
                self.remote_conn.close()
                self.establish_connection(width=100, height=1000)
        return output
