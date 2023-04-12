#!/usr/bin/env python3
#-*- coding:UTF-8 -*-

from netmiko.ssh_dispatcher import CLASS_MAPPER_BASE, CLASS_MAPPER
for k, v in CLASS_MAPPER_BASE.items():
    vendor = k.split('_', maxsplit=1)[0]
    print("{} {}".format(vendor, k))
print("~" * 100)
for k, v in CLASS_MAPPER.items():
    vendor = k.rsplit('_', maxsplit=2)[0]
    print("{} {}".format(vendor, k))