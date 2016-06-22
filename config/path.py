#!/usr/bin/env python
# encoding: utf-8
"""
@author:     idhyt
@date:
@description:

"""
import os

KALLSYMS_FILE_NAME = ""
KERNEL_FILE_NAME = ""

CURRENT_PATH = os.path.split(os.path.realpath(__file__))[0]

KERNEL_FILE_PATH = "/file/".join([CURRENT_PATH, KERNEL_FILE_NAME])
KALLSYMS_FILE_PATH = "/file/".join([CURRENT_PATH, KALLSYMS_FILE_NAME])


if not KALLSYMS_FILE_NAME or not KERNEL_FILE_NAME:
    file_list = os.listdir("".join([CURRENT_PATH, "/file/"]))
    for file_ in file_list:
        if "kernel" in file_:
            KERNEL_FILE_NAME = file_
            continue
        if "kallsyms" in file_:
            KALLSYMS_FILE_NAME = file_
            continue

    KERNEL_FILE_PATH = "/file/".join([CURRENT_PATH, KERNEL_FILE_NAME])
    KALLSYMS_FILE_PATH = "/file/".join([CURRENT_PATH, KALLSYMS_FILE_NAME])