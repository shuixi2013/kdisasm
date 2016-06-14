#!/usr/bin/env python
# encoding: utf-8
"""
@author:     idhyt
@date:
@description:

"""

import kdisasm

from config.path import *

disasm = kdisasm.DisAsm(KERNEL_FILE_PATH, KALLSYMS_FILE_PATH)
kallsyms = kdisasm.KallSyms(KALLSYMS_FILE_PATH)

# patch tags
patch_tags = {
    "selinux_enforcing_tags": [],
    "cred_security_offset_tags": [],
    "ptmx_fops_tags": [],
    "ioctl_back_address_tags": [],
    "init_task_tags": [],
    "tasks_offset_tags": [],
}


def arm32(func):
    global patch_tags

    return func


def arm64(func):
    global patch_tags

    patch_tags["selinux_enforcing_tags"] = [
        "adrp x0,",  # adrp x0, #0xffffffc000f4c000
        "str w1,"  # str w1, [x0, #0xc0c]
    ]

    patch_tags["cred_security_offset_tags"] = [
        "ldr x0, [x0,",  # ldr x0, [x0, 0x48]
    ]

    patch_tags["ptmx_fops_tags"] = [
        "bl",  # bl #0xffffffc00031d040
        "mov x0",  # mov x0, x19
        "add regs",  # add x19, x20, #0x10;
        "add regs",  # add x20, x21, #0xd80;
        "adrp regs"  # adrp x21, #0xffffffc001039000
    ]

    patch_tags["ioctl_back_address_tags"] = [
        "cmn w0, #0x203",  # #define ENOIOCTLCMD   515 /* No ioctl command */
    ]

    patch_tags["init_task_tags"] = [
        "#0xdead",
        "adrp",
    ]

    patch_tags["tasks_offset_tags"] = [
        "adrp",
        "str regs,",
    ]

    return func


# patch selinux_enforcing = 0
def get_selinux_enforcing_address():
    selinux_enforcing_tags = patch_tags["selinux_enforcing_tags"]

    enforcing_setup_address = 0
    asm_list = disasm.get_asm_by_name("enforcing_setup")
    for asm in asm_list:
        if selinux_enforcing_tags[0] in asm:
            enforcing_setup_address += long(asm.split("#")[-1].strip(), 16)
        if selinux_enforcing_tags[1] in asm:
            enforcing_setup_address += long(asm.split("#")[-1].rstrip("]"), 16)

    print "selinux_enforcing_address: 0x%lx" % enforcing_setup_address
    return enforcing_setup_address


# thread_info -> task -> cred -> security
# cred_has_capability()
def get_security_offset():
    cred_security_offset_tags = patch_tags["cred_security_offset_tags"]

    cred_security_offset = 0
    asm_list = disasm.get_asm_by_name("cred_has_capability")
    for asm in asm_list:
        if cred_security_offset_tags[0] in asm:
            cred_security_offset = long(asm.split("#")[-1].strip("]"), 16)

    print "cred_security_offset: 0x%lx" % cred_security_offset
    return cred_security_offset


# patch ioctl
def get_ptmx_fops_address():
    ptmx_fops_tags = patch_tags["ptmx_fops_tags"]

    ptmx_fops_address = 0

    tty_default_fops_address = kallsyms.find_apis_addr(["tty_default_fops"])["tty_default_fops"]
    # print hex(tty_default_fops_address)
    asm_list = disasm.get_asm_by_name("pty_init")
    i, regs = 0, ""
    for asm in reversed(asm_list):
        if i == 0:
            if ptmx_fops_tags[0] in asm and long(asm.split("#")[-1].strip(), 16) == tty_default_fops_address:
                i += 1
                continue
        if i == 1:
            if ptmx_fops_tags[1] in asm:
                regs = asm.split(" ")[-1].strip()
                ptmx_fops_tags[2] = ptmx_fops_tags[2].replace("regs", regs)
                i += 1
                continue
        if i == 2:
            if ptmx_fops_tags[2] in asm:
                regs = asm.split(" ")[3].strip(",")
                ptmx_fops_tags[3] = ptmx_fops_tags[3].replace("regs", regs)
                i += 1
                ptmx_fops_address += long(asm.split("#")[-1].strip(), 16)
                continue

        if i == 3:
            if ptmx_fops_tags[3] in asm:
                regs = asm.split(" ")[3].strip(",")
                ptmx_fops_tags[4] = ptmx_fops_tags[4].replace("regs", regs)
                i += 1
                ptmx_fops_address += long(asm.split("#")[-1].strip(), 16)
                continue
        if i == 4:
            if ptmx_fops_tags[4] in asm:
                ptmx_fops_address += long(asm.split("#")[-1].strip(), 16)
                break

    if ptmx_fops_address > 0xffffffc000000000:
        print "ptmx_fops_address: 0x%lx" % ptmx_fops_address
        return ptmx_fops_address

    raise


# patch do_vfs_ioctl->vfs_ioctl(unlocked_ioctl) back address
def get_ioctl_back_address():
    ioctl_back_address_tags = patch_tags["ioctl_back_address_tags"]

    ioctl_back_address = 0
    asm_list = disasm.get_asm_by_name("do_vfs_ioctl")
    for asm in asm_list:
        if ioctl_back_address_tags[0] in asm:
            ioctl_back_address = long(asm.split(":")[0].strip(), 16)
            break

    if ioctl_back_address > 0xffffffc000000000:
        print "ioctl_back_address: 0x%lx" % ioctl_back_address
        return ioctl_back_address

    raise


# global var init_task
def get_init_task_address():
    init_task_tags = patch_tags["init_task_tags"]

    init_task_address = 0
    asm_list = disasm.get_asm_by_name("cgroup_init_subsys")
    i = 0
    for asm in reversed(asm_list):
        if init_task_tags[0] in asm:
            i += 1
        if i == 3 and init_task_tags[1] in asm:
            init_task_address = long(asm.split("#")[-1].strip(), 16)
            break
    if init_task_address & 0xffff == 0:
        print "init_task_address: 0x%lx" % init_task_address
        return init_task_address

    raise


# thread_info -> task -> tasks
def get_task_struct_tasks_offset():
    tasks_offset_tags = patch_tags["tasks_offset_tags"]

    task_struct_tasks_offset = 0
    init_task_address = get_init_task_address()

    asm_list = disasm.get_asm_by_name("copy_process")
    i = 0
    offset_tag = "tag"
    for asm in asm_list:
        if i < 3:
            if tasks_offset_tags[0] in asm and long(asm.split("#")[-1].strip(), 16) == init_task_address:
                i += 1

        if i == 2:
            regs = asm.split(" ")[2].strip(",")
            offset_tag = tasks_offset_tags[1].replace("regs", regs)
            i += 1
            continue

        if i == 3 and offset_tag in asm:
            task_struct_tasks_offset = long(asm.split("#")[-1].strip("]"), 16)
            break

    if task_struct_tasks_offset > 0:
        print "task_struct_tasks_offset: 0x%lx" % task_struct_tasks_offset
        return task_struct_tasks_offset

    raise


# u:r:init:s0
def get_selinux_init_context_sid():
    pass


@arm64
def main():
    get_selinux_enforcing_address()
    get_security_offset()
    get_ptmx_fops_address()
    get_ioctl_back_address()
    get_task_struct_tasks_offset()

if __name__ == '__main__':
    main()
