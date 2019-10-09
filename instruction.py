from capstone import *
from collections import namedtuple


def decode(data, addr):

    instr = namedtuple('Instruction', 'size name operand')
    size = 2
    name = ""
    operand = ""

    md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
    for i in md.disasm(data, addr):
        size = i.size
        name = i.mnemonic
        operand = i.op_str
        break

    if not name:
        if data[:2] == b'\x82\x80':
            name = "ret"

    return instr(size, name, operand)



