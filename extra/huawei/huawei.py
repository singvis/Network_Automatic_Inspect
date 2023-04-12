import time
import re
from netmiko.huawei.huawei import HuaweiSSH
from netmiko.ssh_exception import NetmikoAuthenticationException
from netmiko import log

COMMIT_CMD = 'commit'
UNCOMMIT_FALG = ['Warning: Uncommitted configurations found']

EXIT_CMD = 'return'


class HuaweiZetSSH(HuaweiSSH):

    def commit(self):
        self.clear_buffer()
        cmd = f'{COMMIT_CMD}{self.RETURN}'
        self.write_channel(cmd)
        output = self.read_until_prompt_or_pattern(pattern=r"\[.*?\]")
        # Error: Unrecognized command found at '^' position
        if 'Unrecognized command' in output:
            raise Exception('This platform does not support commit,or the device is not in the config mode')

        return output

    def send_config_set(self, *args, **kwargs):
        '''
        如果自动commit则调用父类方法的时候，不能退出config模式，先调用重写的commit，
        然后根据用户最早传入的是否离开config模式决定是否离开config模式。
        如果非自动commit，暂时不离开config模式，根据回显判断是否有输入yes no的提示（询问是否不提交配置），自动输入一个yes
        :param auto_commit:  布尔 默认false ，是否自动commit
        :param kwargs:
        :return: 交互的整段回显
        '''
        intend_exit_config_mode = kwargs.get('exit_config_mode', True)
        # 执行结束后均不离开config模式 通过intend_exit_config_mode来执行
        kwargs['exit_config_mode'] = False
        if 'auto_commit' in kwargs:
            auto_commit = kwargs.get('auto_commit')
            del kwargs['auto_commit']
        else:
            auto_commit = False

        if auto_commit:

            output = super(HuaweiZetSSH, self).send_config_set(*args, **kwargs)
            output += self.commit()
            if intend_exit_config_mode:
                self.exit_config_mode()
        else:
            # Warning: Uncommitted configurations found. Are you sure to commit them before exiting? [Y(yes)/N(no)/C(cancel)]
            output = super(HuaweiZetSSH, self).send_config_set(*args, **kwargs)
            pattern = r'>|]|\[Y\S+/N\S+\]'
            if intend_exit_config_mode:
                self.clear_buffer()
                self.write_channel(f'{EXIT_CMD}{self.RETURN}')
                exit_output = self.read_until_prompt_or_pattern(pattern)
                output += exit_output
                # 如果提示有未提交的配置，则输入Y不提交配置。其他情况无此提示信息，则代表return执行成功
                if self._warning_uncommitted(exit_output):
                    pattern = '>'
                    self.write_channel('Y\n')
                    confirm_output = self.read_until_prompt_or_pattern(pattern)
                    output += confirm_output

        return output

    def _warning_uncommitted(self, output, uncommitted_flags=UNCOMMIT_FALG):
        for i in uncommitted_flags:
            if i in output:
                return True
        return False
