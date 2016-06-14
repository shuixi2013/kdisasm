#!/usr/bin/env python
# encoding: utf-8
"""
@author:     idhyt
@date:
@description:

"""

import time
from config.path import *
from capstone import *

# http://www.capstone-engine.org/lang_python.html
Architecture = "@"
BasicMode = "@"

KERNEL_BASE_ADDR = "@"


def arm32(func):
    global Architecture, BasicMode, KERNEL_BASE_ADDR

    Architecture = CS_ARCH_ARM
    BasicMode = CS_MODE_ARM     # CS_MODE_THUMB
    KERNEL_BASE_ADDR = 0xc0008000

    return func


def arm64(func):
    global Architecture, BasicMode, KERNEL_BASE_ADDR

    Architecture = CS_ARCH_ARM64
    BasicMode = CS_MODE_ARM
    KERNEL_BASE_ADDR = 0xffffffc000080000

    return func


def output_log(print_info, is_print=True, is_print_time=False):

    if is_print:
        date = ""
        if is_print_time:
            date = "[%s] " % time.ctime(time.time())
        print '%s%s' % (str(date), print_info)


# Disassemble and dump
@arm64
class DisAsm(object):
    def __init__(self, kernel_file_path=None, kallsyms_file_path=None):
        if not isinstance(kernel_file_path, str) or not isinstance(kallsyms_file_path, str):
            raise

        self.__kernel_base_addr = KERNEL_BASE_ADDR
        self.__kernel_file_path = kernel_file_path
        self.__kallsyms_file_path = kallsyms_file_path
        self.__all_hex_content = None
        self.__all_kallsyms_api_info = None

        self.__kallsyms = KallSyms(self.__kallsyms_file_path)

    def __clean__(self):
        self.__kernel_file_path = None
        self.__kallsyms_file_path = None
        self.__all_hex_content = None
        self.__all_kallsyms_api_info = None

    def get_part_hex_code(self, start, len_=0x100):
        f = open(self.__kernel_file_path, "rb")
        f.seek(start, 0)
        hex_content = f.read(len_)
        f.close()
        return hex_content

    def get_all_hex_code(self):
        if self.__all_hex_content is None:
            f = open(self.__kernel_file_path, "rb")
            self.__all_hex_content = f.read()
            f.close()
        return self.__all_hex_content

    def get_kallsyms_api_info(self):
        if self.__all_kallsyms_api_info is None:
            self.__all_kallsyms_api_info = self.__kallsyms.get_all_api_info()

        return self.__all_kallsyms_api_info

    def disasm_hex_code(self, hex_code, disasm_base_addr=0x1000, is_dump=False):
        if len(hex_code) == 0:
            return []
        asm_list = []
        try:
            md = Cs(Architecture, BasicMode)
            for i in md.disasm(hex_code, disasm_base_addr):
                # print "0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str)
                # print "0x%x: %s %s" % (i.address, i.mnemonic, i.op_str)
                if is_dump:
                    asm_list.append("0x%x: %s %s\n" % (i.address, i.mnemonic, i.op_str))
                else:
                    asm_list.append("0x%x: %s %s" % (i.address, i.mnemonic, i.op_str))
            return asm_list
        except CsError as e:
            output_log(str(e))

    def get_asm(self, disasm_start_addr, disasm_len):
        disasm_file_offset = disasm_start_addr - self.__kernel_base_addr
        buf = self.get_part_hex_code(disasm_file_offset, disasm_len)
        return self.disasm_hex_code(buf, disasm_start_addr)

    def dump_disasm(self, dump_file_name):
        all_api_info = self.get_kallsyms_api_info()

        if not isinstance(all_api_info, list):
            raise

        with open(dump_file_name, "w+") as f:
            for aip_info in all_api_info:

                start_ = aip_info["address"] - self.__kernel_base_addr
                cur_hex_code = self.get_part_hex_code(start_, aip_info["length"])
                cur_ins_list = self.disasm_hex_code(cur_hex_code, aip_info["address"], True)
                cur_ins_info = "0x%lx %s 0x%lx" % (aip_info["address"], aip_info["api_name"], aip_info["length"])
                cur_ins_list.insert(0, "\n\n%s\n" % cur_ins_info)

                f.writelines(cur_ins_list)

                del cur_ins_list[:]

                output_log("[ok]" + cur_ins_info)

        f.close()

    # param: "api_name"
    # return: ["asm1", "asm2", ...]
    def get_asm_by_name(self, api_name):

        if not isinstance(api_name, str):
            raise

        all_api_info = self.get_kallsyms_api_info()

        if not isinstance(all_api_info, list):
            raise

        for api_info in all_api_info:
            if api_info["api_name"] == api_name:
                return self.get_asm(api_info["address"], api_info["length"])


# find api address of kallsyms
# used to search rop
class KallSyms():
    def __init__(self, kallsyms_file_path):
        self.__kallsyms_file_path = kallsyms_file_path
        self.__all_kallsyms_content = None

    def __clean__(self):
        self.__kernel_file_path = None
        self.__all_kallsyms_content = None

    # return []
    def get_all_kallsyms_content(self):
        if self.__all_kallsyms_content is None:
            with open(self.__kallsyms_file_path, "r+") as f:
                self.__all_kallsyms_content = f.readlines()
                f.close()
        return self.__all_kallsyms_content

    # return = [
    #     {"api_name": "xxx", "address": 0, "length": 0},
    #     {"api_name": "xxx", "address": 0, "length": 0},
    # ]
    def get_all_api_info(self):
        all_kallsyms_list = []

        all_kallsyms_content = self.get_all_kallsyms_content()
        if not isinstance(all_kallsyms_content, list):
            raise

        for index_ in xrange(0, len(all_kallsyms_content)):
            cur_aip_name = all_kallsyms_content[index_].split(" ")[-1].strip()
            cur_api_addr = long("0x" + all_kallsyms_content[index_].split(" ")[0].strip(), 16)

            # last one default disassemble 0x100
            next_api_addr = long("0x" + all_kallsyms_content[index_+1].split(" ")[0].strip(), 16) \
                if index_ < len(all_kallsyms_content)-1 else cur_api_addr + 0x100

            cur_api_len = next_api_addr - cur_api_addr

            temp = {}
            temp["api_name"] = str(cur_aip_name)
            temp["address"] = cur_api_addr
            temp["length"] = cur_api_len
            all_kallsyms_list.append(temp)

        return all_kallsyms_list

    # param ["api_name", "api_name2", ...]
    # return [{"api_name": address}, {}, ...]
    def find_apis_addr(self, api_name_list):
        if not isinstance(api_name_list, list):
            raise

        apis_addr_dict = {}

        all_kallsyms_content = self.get_all_kallsyms_content()

        for cur_line in all_kallsyms_content:
            cur_line = cur_line.strip("\n")
            cur_api_name = cur_line.split(" ")[-1].strip()
            if cur_api_name in api_name_list:
                cur_api_addr = "0x" + cur_line.split(" ")[0].strip()
                apis_addr_dict.setdefault(cur_api_name, long(cur_api_addr, 16))
                api_name_list.remove(cur_api_name)
                # print "0x" + c_line

            if len(api_name_list) == 0:
                break

        if len(api_name_list) > 0:
            output_log("get api addr lost")
            output_log(", ".join(api_name_list))

        return apis_addr_dict


# example disassemble
def dump_asm():
    da = DisAsm(KERNEL_FILE_PATH, KALLSYMS_FILE_PATH)
    da.dump_disasm("mx2-kernel-asmx64.c")


# example find api address
def get_apis_addr():
    api_name_list = [
        "pty_init",
        "tty_ioctl",
        "enforcing_setup",
        "mtk_wcn_cmb_stub_query_ctrl",
        "stat_seq_show",
        "clk_composite_set_parent",
        "el1_irq",
        "do_vfs_ioctl",
        "usb_hcd_irq"
    ]
    kallsyms = KallSyms(KALLSYMS_FILE_PATH)
    apis_addr_dict = kallsyms.find_apis_addr(api_name_list)
    print apis_addr_dict


def get_api_asm():
    da = DisAsm(KERNEL_FILE_PATH, KALLSYMS_FILE_PATH)
    asm_list = da.get_asm_by_name("cred_has_capability")
    for asm_ in asm_list:
        print asm_


if __name__ == '__main__':
    # dump_asm()
    # get_apis_addr()
    get_api_asm()
    pass


