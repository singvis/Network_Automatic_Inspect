#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import os
import configparser


class Config(object):
    def __init__(self, config_file='config.ini'):
        self._path = os.path.join(os.path.dirname(os.path.abspath(__file__)), config_file)
        if not os.path.exists(self._path):
            raise FileNotFoundError("找不到文件: config.ini")
        self.cf = configparser.ConfigParser()
        self.cf.read(self._path, encoding="utf-8-sig")
        self.cfRaw = configparser.RawConfigParser()
        self.cfRaw.read(self._path, encoding="utf-8-sig")

    def get(self, section, name):
        return self.cf.get(section, name)

    def getRaw(self, section, name):
        return self.cfRaw.get(section, name)


global_config = Config()

if __name__ == '__main__':
    global_config = Config()
    cf = global_config.getRaw('account', 'secret')
    print(type(cf), bool(cf), cf)
