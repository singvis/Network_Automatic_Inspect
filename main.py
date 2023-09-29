import sys

from utils.RichTool import RichTool
from NetAutoTool import NetAutoTool

if __name__ == '__main__':
    net, rich = (NetAutoTool(), RichTool())
    rich.func_table()

    rich.con.rule(style='blue', characters='^')
    choice_function = input("请选择: ")
    if choice_function == '1':
        """测试连接"""
        net.connect_t()
    elif choice_function == '2':
        """采集设备信息"""
        net.connect()
    elif choice_function == '3':
        """配置设备"""
        net.connect_config()
    elif choice_function == '4':
        """批量ping设备"""
        print("没有这个功能!")
        sys.exit(1)
    else:
        print("没有这个功能!")
        sys.exit(1)
