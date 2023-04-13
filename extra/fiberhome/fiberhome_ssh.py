import re

from netmiko.cisco_base_connection import CiscoSSHConnection
from netmiko.ssh_exception import NetmikoTimeoutException


class FiberHomeSSH(CiscoSSHConnection):

    def session_preparation(self) -> None:
        """Prepare the session after the connection has been established."""
        self.ansi_escape_codes = True
        self._test_channel_read(pattern=r"#|>")
        self.set_terminal_width(
            command="terminal width 511", pattern=r"terminal width 511"
        )
        self.disable_paging()
        self.set_base_prompt()

    def set_base_prompt(self, pri_prompt_terminator=r'#',
                        alt_prompt_terminator=r'>',
                        delay_factor=0.1) -> str:
        return super(FiberHomeSSH, self).set_base_prompt(pri_prompt_terminator=pri_prompt_terminator,
                                                         alt_prompt_terminator=alt_prompt_terminator,
                                                         delay_factor=delay_factor)

    def normalize_linefeeds(self, a_string: str) -> str:
        """Convert '\r\n' or '\r\r\n' to '\n, and remove extra '\r's in the text."""
        newline = re.compile(r"(\r\r\n\r|\r\r\n|\r\n)")
        return newline.sub(self.RESPONSE_RETURN, a_string).replace("\r", "\n")

    def send_command(
            self,
            command_string,
            expect_string=None,
            delay_factor=1,
            max_loops=500,
            auto_find_prompt=True,
            strip_prompt=True,
            strip_command=True,
            normalize=True,
            use_textfsm=False,
            textfsm_template=None,
            use_ttp=False,
            ttp_template=None,
            use_genie=False,
            cmd_verify=False,
    ):
        """
        烽火设备部分命令show的时候，回显在前，执行的命令在回显之后显示，顾将cmd_verify置为False
        """
        return super(FiberHomeSSH, self).send_command(command_string,
                                                      expect_string=expect_string,
                                                      delay_factor=delay_factor,
                                                      max_loops=max_loops,
                                                      auto_find_prompt=auto_find_prompt,
                                                      strip_prompt=strip_prompt,
                                                      strip_command=strip_command,
                                                      normalize=normalize,
                                                      use_textfsm=use_textfsm,
                                                      textfsm_template=textfsm_template,
                                                      use_ttp=use_ttp,
                                                      ttp_template=ttp_template,
                                                      use_genie=use_genie,
                                                      cmd_verify=cmd_verify)

    def send_command_timing(
            self,
            command_string,
            delay_factor=1,
            max_loops=150,
            strip_prompt=True,
            strip_command=True,
            normalize=True,
            use_textfsm=False,
            textfsm_template=None,
            use_ttp=False,
            ttp_template=None,
            use_genie=False,
            cmd_verify=False,
            cmd_echo=None,
    ):
        """
        烽火设备部分命令show的时候，回显在前，执行的命令在回显之后显示，顾将cmd_verify置为False
        """
        return super(FiberHomeSSH, self).send_command_timing(command_string,
                                                             delay_factor=delay_factor,
                                                             max_loops=max_loops,
                                                             strip_prompt=strip_prompt,
                                                             strip_command=strip_command,
                                                             normalize=normalize,
                                                             use_textfsm=use_textfsm,
                                                             textfsm_template=textfsm_template,
                                                             use_ttp=use_ttp,
                                                             ttp_template=ttp_template,
                                                             use_genie=use_genie,
                                                             cmd_verify=cmd_verify)

    def check_enable_mode(self, check_string: str = "#") -> bool:
        """Check if in enable mode. Return boolean."""
        return super(FiberHomeSSH, self).check_enable_mode(check_string=check_string)

    def enable(
            self,
            cmd: str = r"enable",
            pattern: str = "ssword",
            enable_pattern=r'#',
            re_flags: int = re.IGNORECASE,
    ) -> str:
        output = ""
        msg = (
            "Failed to enter enable mode. Please ensure you pass "
            "the 'secret' argument to ConnectHandler."
        )

        # Check if in enable mode
        # Send "enable" mode command
        self.write_channel(self.normalize_cmd(cmd))
        try:
            # Read the command echo
            end_data = ""
            if self.global_cmd_verify is not False:
                output += self.read_until_pattern(pattern=re.escape(cmd.strip()))
                end_data = output.split(cmd.strip())[-1]

            # Search for trailing prompt or password pattern
            if pattern not in output and self.base_prompt not in end_data:
                output += self.read_until_prompt_or_pattern(
                    pattern=pattern, re_flags=re_flags
                )
            # Send the "secret" in response to password pattern
            if re.search(pattern, output):
                self.write_channel(self.normalize_cmd(self.secret))
                output += self.read_until_prompt()

            # Search for terminating pattern if defined
            if enable_pattern and not re.search(enable_pattern, output):
                output += self.read_until_pattern(pattern=enable_pattern)
            else:
                if not self.check_enable_mode():
                    raise ValueError(msg)
        except NetmikoTimeoutException:
            raise ValueError(msg)
        return output

    def exit_enable_mode(self, exit_command: str = "end") -> str:
        return super(FiberHomeSSH, self).exit_enable_mode(exit_command=exit_command)

    # 目前来看进入config模式 形如config.*)的回显
    def check_config_mode(self, check_string: str = "config.*)#", pattern: str = "#") -> bool:
        """
        Checks if the device is in configuration mode or not.
        """
        return super(FiberHomeSSH, self).check_config_mode(check_string=check_string, pattern=pattern)

    def config_mode(
            self,
            config_command: str = "configure",
            pattern: str = "#",
            re_flags: int = 0,
    ) -> str:
        return super(FiberHomeSSH, self).config_mode(
            config_command=config_command, pattern=pattern, re_flags=re_flags
        )

    def exit_config_mode(self, exit_config: str = "end", pattern: str = r"#.*|>.*") -> str:
        """Exit from configuration mode."""
        return super().exit_config_mode(exit_config=exit_config, pattern=pattern)

    def save_config(self,
                    cmd="write file",
                    confirm=True,
                    confirm_response="y", ) -> str:
        return super(FiberHomeSSH, self).save_config(cmd=cmd,
                                                     confirm=confirm,
                                                     confirm_response=confirm_response)
