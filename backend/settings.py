#!/usr/bin/env python3
# -*- coding:UTF-8 -*-

import configparser

from pathlib import Path

# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ configparser start config ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# 当前文件的绝对路径
BASE_DIR = Path(__file__).resolve().parent

try:
    cf = configparser.ConfigParser()
    cf.read(BASE_DIR / 'config.ini')

    config = dict(cf.items())
    # print(config)
except ModuleNotFoundError:
    print("configparser模块没有安装.")

# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ configparser start end ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^


# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ account start config ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

# read account info
read_user = config['ACCOUNT'].get('read_user')
# write account info
write_user = config['ACCOUNT'].get('write_user')

# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ account start end ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^


# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ftp start config ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

# FTP Server info
ftp_server = config['FTP_SERVER'].get('ftp_server')
ftp_user = config['FTP_SERVER'].get('ftp_user')
ftp_password = config['FTP_SERVER'].get('ftp_password')

# ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ftp start end ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

if __name__ == '__main__':
    pass
