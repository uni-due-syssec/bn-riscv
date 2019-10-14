from capstone import *
from capstone.riscv import *
from collections import namedtuple


def decode(data, addr):

    instr = namedtuple('Instruction', 'size name op imm')
    size = 2
    name = ""
    op = ""
    imm = 0

    md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
    md.detail = True

    for insn in md.disasm(data, addr):
        size = insn.size
        name = insn.mnemonic

        if len(insn.operands) > 0:
            for i in insn.operands:
                if i.type == RISCV_OP_REG:
                    op += " " + (insn.reg_name(i.value.reg))
                elif i.type == RISCV_OP_IMM:
                    imm = i.value.imm
                elif i.type == RISCV_OP_MEM:
                    if i.mem.base != 0:
                        op += " " + insn.reg_name(i.mem.base)
                    if i.mem.disp != 0:
                        imm = i.mem.disp

        return instr(size, name, op, imm)




