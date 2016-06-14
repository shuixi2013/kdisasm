#!/usr/bin/env python
# encoding: utf-8
"""
@author:     idhyt
@date:
@description:

"""
import os

KALLSYMS_FILE_NAME = "kallsyms-m2-Flyme 5.1.5.0Y"
KERNEL_FILE_NAME = "kernel-m2-Flyme 5.1.5.0Y"

CURRENT_PATH = os.path.split(os.path.realpath(__file__))[0]

KERNEL_FILE_PATH = "/file/".join([CURRENT_PATH, KERNEL_FILE_NAME])
KALLSYMS_FILE_PATH = "/file/".join([CURRENT_PATH, KALLSYMS_FILE_NAME])
