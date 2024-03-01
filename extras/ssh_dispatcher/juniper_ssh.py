#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from netmiko.juniper import JuniperSSH


class JuniperSSH(JuniperSSH):
    """重写了JuniperSSH类"""

    # netscreen 不支持""set cli screen-width 511""命令，调整下命令
    def session_preparation(self):
        """Prepare the session after the connection has been established."""
        self.enter_cli_mode()

        self.disable_paging(
            command="set console page 0", pattern=r"->"
        )
        self.set_base_prompt()
