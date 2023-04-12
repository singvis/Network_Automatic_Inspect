#!/usr/bin/env python3
# -*- coding:UTF-8 -*-

import sys

from core.Network_Automatic_Inspect import NetworkHandler

if __name__ == '__main__':
    # 开启debug，用于分析后台执行记录结果，方便定位问题
    # 需要debug，请把注释删除即可，自动会生成一份debug.log文件
    # logging.basicConfig(filename='debug.log', level=logging.DEBUG)
    # logging.getLogger("netmiko")

    text = """
    功能列表：
    1. 连接测试.
    2. 采集设备配置信息.
    3. 保存设备配置.
    4. 下发设备配置(生产环境请谨慎操作).
    """
    print(text)

    choice_function = input("请选择: ")
    if choice_function == '1':
        # 测试连接性
        print('^' * 100)
        NetworkHandler().main_connect_t()
        print('^' * 100)
    elif choice_function == '2':
        # 采集设备配置信息
        print('^' * 100)
        NetworkHandler().main_get_config()
        print('^' * 100)
    elif choice_function == '3':
        # 保存设备配置
        print('^' * 100)
        NetworkHandler().main_save_config()
        print('^' * 100)
    elif choice_function == '4':
        # 下发设备配置
        print('^' * 100)
        NetworkHandler().main_send_config()
        print('^' * 100)
    else:
        print("没有这个功能!")
        sys.exit(1)
