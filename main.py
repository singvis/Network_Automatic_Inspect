import sys

from utils.RichTool import RichTool
from NetAutoTool import NetAutoTool

if __name__ == '__main__':
    net, rich = NetAutoTool(), RichTool

    table = {
        "colums": ('序号', '功能'),
        "rows": [
            ('1', '连接测试'),
            ('2', '采集设备信息'),
            ('3', '批量配置设备'),
            ('4', '批量保存设备'),
            ('5', '批量ping'),
            ('6', '清除设备缓存数据'),
        ]
    }

    rich.printTable(title="按功能选择对应的序号", colums=table["colums"], rows=table["rows"])

    choice_function = input("请选择: ")
    if choice_function == '1':
        """测试连接"""
        rich.startLine(message="连接网络设备")
        net.execute_connect()
        rich.endLine(message="连接网络设备")
    elif choice_function == '2':
        """采集设备配置"""
        rich.startLine(message="采集设备配置信息")
        net.execute_getConfig()
        rich.endLine(message="采集设备配置信息")
    elif choice_function == '3':
        """下发设备配置"""
        net.execute_sendConfig()
    elif choice_function == '4':
        """保存设备配置"""
        net.execute_saveConfig()
    elif choice_function == '5':
        """批量ping设备"""
        net.execute_ping()
    elif choice_function == '6':
        """清除设备缓存数据"""
        net.clear_cache_data()
    else:
        print("没有这个功能!")
        sys.exit(1)
