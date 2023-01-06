#!/usr/bin/env python3
#-*- coding:UTF-8 -*-

import configparser

cf = configparser.ConfigParser()
cf.read(filenames='config.ini')

config = cf.items()

# read account info

reader_user = config['ACCOUNT'].get('read_user')

# write account info
write_user = config['ACCOUNT'].get('write_user')