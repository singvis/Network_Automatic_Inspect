#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import re

from collections import OrderedDict
from netmiko.ssh_autodetect import SSHDetect


class MySSHDetect(SSHDetect):
    pass