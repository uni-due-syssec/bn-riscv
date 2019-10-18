from capstone import *
from capstone.riscv import *
from collections import namedtuple
from binaryninja import InstructionTextToken, InstructionTextTokenType


def decode(data, addr):

    instr = namedtuple('Instruction', 'size name op imm imm_val')
    op = ""
    imm = 0

    md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
    md.detail = True

    for insn in md.disasm(data, addr):
        size = insn.size
        name = insn.mnemonic
        imm_val = False

        if len(insn.operands) > 0:
            for i in insn.operands:
                if i.type == RISCV_OP_REG:
                    op += " " + (insn.reg_name(i.value.reg))
                elif i.type == RISCV_OP_IMM:
                    imm = i.value.imm
                    imm_val = True
                elif i.type == RISCV_OP_MEM:
                    if i.mem.base != 0:
                        op += " " + insn.reg_name(i.mem.base)
                    if i.mem.disp != 0:
                        imm = i.mem.disp
                        imm_val = True

        return instr(size, name, op, imm, imm_val)


def gen_token(instr):

    tokens = [InstructionTextToken(
        InstructionTextTokenType.TextToken,
        "{:6} ".format(
            instr.name
        )
    )]
    operands = instr.op.split()
    for i in operands:
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, " "+i))

    if instr.imm_val:
        tokens.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, " " + str(instr.imm)))

    return tokens





