#!/usr/bin/env python
# encoding: utf-8
"""
@author:     idhyt@hotmail.com
@date:
@description:

"""


from kdisasm import *


# patch tags
patch_tags = {
    "selinux_enforcing_tags": [],
    "cred_security_offset_tags": [],
    "ptmx_fops_tags": [],
    "ioctl_back_address_tags": [],
    "init_task_tags": [],
    "tasks_offset_tags": [],
}


# platform
platform = 0


def arm32(func):
    global patch_tags, platform

    platform = 32

    patch_tags["selinux_enforcing_tags"] = [
        "ldr r3, [pc,",   # ldr r3, [pc, #0x14]
        "str r2, [r3,",  # str r2, [r3, #4]
        "mov r0, #1",     #
    ]

    return func


def arm64(func):
    global patch_tags, platform

    platform = 64

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
    asm_list = ckdisasm.get_asm_by_name("enforcing_setup")

    if platform == 32:
        i = 0
        for index, asm in enumerate(asm_list):
            if i == 0 and selinux_enforcing_tags[0] in asm:
                i += 1
                pc = long(asm.split(":")[0], 16) + BYTE_SIZE
                read_address_offset = long(asm.split("#")[-1].rstrip("]"), 16)
                read_address = pc + read_address_offset + BYTE_SIZE
                enforcing_setup_address += ckdisasm.get_kernel_instance().read_value_by_kernel_address(read_address)
                continue

            if i == 1 and selinux_enforcing_tags[1] in asm and selinux_enforcing_tags[2] in asm_list[index+1]:
                offset = long(asm.split("#")[-1].rstrip("]"), 16)
                enforcing_setup_address += offset
                break

    elif platform == 64:
        for asm in asm_list:
            if selinux_enforcing_tags[0] in asm:
                enforcing_setup_address += long(asm.split("#")[-1].strip(), 16)
            if selinux_enforcing_tags[1] in asm:
                enforcing_setup_address += long(asm.split("#")[-1].rstrip("]"), 16)
    else:
        raise

    print "selinux_enforcing_address = 0x%lx" % enforcing_setup_address
    return enforcing_setup_address


# thread_info -> task -> cred -> security
# cred_has_capability()
def get_security_offset():
    cred_security_offset_tags = patch_tags["cred_security_offset_tags"]

    cred_security_offset = 0
    asm_list = ckdisasm.get_asm_by_name("cred_has_capability")

    if platform == 32:
        pass

    elif platform == 64:
        for asm in asm_list:
            if cred_security_offset_tags[0] in asm:
                cred_security_offset = long(asm.split("#")[-1].strip("]"), 16)

    else:
        raise

    print "cred_security_offset = 0x%lx" % cred_security_offset
    return cred_security_offset


# patch ioctl
def get_ptmx_fops_address():
    ptmx_fops_tags = patch_tags["ptmx_fops_tags"]

    ptmx_fops_address = 0

    tty_default_fops_address = ckdisasm.get_kallsyms_instance().find_apis_address(["tty_default_fops"])["tty_default_fops"]
    # print hex(tty_default_fops_address)
    asm_list = ckdisasm.get_asm_by_name("pty_init")

    if platform == 32:
        pass

    elif platform == 64:
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

    else:
        raise

    if ptmx_fops_address > KERNEL_BASE_ADDR:
        print "ptmx_fops_address = 0x%lx" % ptmx_fops_address
        return ptmx_fops_address

    raise


# patch do_vfs_ioctl->vfs_ioctl(unlocked_ioctl) back address
def get_ioctl_back_address():
    ioctl_back_address_tags = patch_tags["ioctl_back_address_tags"]

    ioctl_back_address = 0
    asm_list = ckdisasm.get_asm_by_name("do_vfs_ioctl")

    if platform == 32:
        pass

    elif platform == 64:
        for asm in asm_list:
            if ioctl_back_address_tags[0] in asm:
                ioctl_back_address = long(asm.split(":")[0].strip(), 16)
                break

    else:
        raise

    if ioctl_back_address > KERNEL_BASE_ADDR:
        print "ioctl_back_address = 0x%lx" % ioctl_back_address
        return ioctl_back_address

    raise


# global var init_task
def get_init_task_address():
    init_task_tags = patch_tags["init_task_tags"]

    init_task_address = 0
    asm_list = ckdisasm.get_asm_by_name("cgroup_init_subsys")

    if platform == 32:
        pass

    elif platform == 64:
        i = 0
        for asm in reversed(asm_list):
            if init_task_tags[0] in asm:
                i += 1
                continue

            if i == 3 and init_task_tags[1] in asm:
                init_task_address = long(asm.split("#")[-1].strip(), 16)
                break

    if init_task_address & 0xfff == 0:
        print "init_task_address = 0x%lx" % init_task_address
        return init_task_address

    raise


# thread_info -> task -> tasks
def get_task_struct_tasks_offset():
    tasks_offset_tags = patch_tags["tasks_offset_tags"]

    task_struct_tasks_offset = 0
    init_task_address = get_init_task_address()

    asm_list = ckdisasm.get_asm_by_name("copy_process")

    if platform == 32:
        pass

    elif platform == 64:
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

    else:
        raise

    if task_struct_tasks_offset > 0:
        print "task_struct_tasks_offset = 0x%lx" % task_struct_tasks_offset
        return task_struct_tasks_offset

    raise


def get_commit_creds_address():
    api_name_list = [
        "commit_creds",
    ]
    commit_creds_address = ckdisasm.get_kallsyms_instance().find_apis_address(api_name_list)["commit_creds"]
    print "commit_creds_address = 0x%x" % commit_creds_address

    return commit_creds_address


def get_prepare_kernel_cred_address():
    api_name_list = [
        "prepare_kernel_cred",
    ]
    prepare_kernel_cred_address = ckdisasm.get_kallsyms_instance().find_apis_address(api_name_list)["prepare_kernel_cred"]
    print "prepare_kernel_cred = 0x%x" % prepare_kernel_cred_address

    return prepare_kernel_cred_address


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
