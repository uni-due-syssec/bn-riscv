from binaryninja import (Architecture, Endianness, RegisterInfo, SegmentFlag, InstructionInfo, BinaryView)

from .const import ADDR_SIZE, INT_SIZE

from capstone import *

from interval3 import Interval, IntervalSet


class RISCV(Architecture):
    name = "RISCV"

    address_size = ADDR_SIZE
    default_int_size = INT_SIZE

    instr_alignment = 1
    max_instr_length = 33

    endianness = Endianness.LittleEndian

    regs = {
        "sp": RegisterInfo("sp", ADDR_SIZE),
    }

    stack_pointer = "sp"

    def get_instruction_info(self, data, addr):
        #print("My_instruction_info")
        #print("data "+str(data))
        #print("addr "+str(addr))

        result = InstructionInfo()
        result.length = 2
        if addr >= int("0x3a0", 16):
            md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
            for i in md.disasm(data, addr):
                print("0x%x:\t%s\t%s\t%s" % (i.address, i.mnemonic, i.op_str, i.size))
                result.length = i.size
                break

        #result.add_branch()
        return result

    def get_instruction_text(self, data, addr):
        print("My_instruction_text")

        size = 2
        name = ""

        if addr >= int("0x3a0", 16):
            md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
            for i in md.disasm(data, addr):
                print("0x%x:\t%s\t%s\t%s" % (i.address, i.mnemonic, i.op_str, i.size))
                size = i.size
                name = i.mnemonic
                break

        tokens = []

        return tokens, size

    #str data: max_instruction_length bytes from the binary at virtual address ``addr``
    #int addr: virtual address of bytes in ``data``
    #LowLevelILFunction il: The function the current instruction belongs to
    #int return: the length of the current instruction
    def get_instruction_low_level_il(self, data, addr, il):

        size = 2

        if addr >= int("0x3a0", 16):
            md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
            for i in md.disasm(data, addr):
                print("0x%x:\t%s\t%s\t%s" % (i.address, i.mnemonic, i.op_str, i.size))
                size = i.size
                break

        return size


class RISCVView(BinaryView):
    name = "RISCV"
    long_name = "Risc-V Bytecode"

    def __init__(self, data):
        print("_init_R_View")
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.raw = data

    def init(self):
        print("init_R_View")
        self.arch = Architecture['RISCV']
        self.platform = Architecture['RISCV'].standalone_platform
        self.max_function_size_for_analysis = 0

        file_size = len(self.raw)
        code = IntervalSet([Interval(0, file_size)])

        for interval in code:
            if isinstance(interval, int):
                continue
            self.add_auto_segment(
                0, file_size,
                0, file_size,
                (
                    SegmentFlag.SegmentReadable |
                    SegmentFlag.SegmentExecutable
                )
            )

        self.add_entry_point(0)

        return True

    @staticmethod
    def is_valid_for_data(data):
        return data.file.original_filename.endswith('.risc')

